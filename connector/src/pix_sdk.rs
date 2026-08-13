//! Production Curvy rs-sdk bridge for the connector-owned PIX pool.

use std::{fmt::Write, sync::Arc};

use babyjubjub_ec::elliptic_curve::group::GroupEncoding;
use curvy_core::{
    babyjubjub::BabyJubPoint,
    field::{Bn254Fr, Fr, fr_from_be_bytes_mod, fr_to_be_32, fr_to_biguint, fr_to_dec},
    witness::KnownOwner,
};
use curvy_sdk::{Account, CurvyClient, Identity, OwnedNote, PreparedDeposit, Route, TxLedger};
use hopr_api::types::{
    crypto::prelude::BjjPublicKey,
    network::PixAddressId,
    primitive::prelude::{Address, HoprBalance},
};
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::pix::{CommittedCurvyNote, CurvySdkAdapter, CurvyWithdrawal, CurvyWithdrawalOutcome, RedbCurvyDepositState};

const SDK_STATE_TABLE: TableDefinition<u8, Vec<u8>> = TableDefinition::new("curvy_pix_sdk_state");
const SDK_STATE_KEY: u8 = 0;
const MAX_ALLOCATIONS_PER_PROOF: usize = 7;
const MAX_COMMITMENTS_PER_PROOF: usize = 5;
const MAX_WITHDRAWAL_INPUTS: usize = 10;
const MAX_ALLOCATION_INPUTS: usize = 2;

/// Runtime configuration for the rs-sdk allocation and withdrawal bridge.
pub struct RsSdkCurvyAdapterConfig {
    /// Curvy account whose private-pool notes fund PIX allocations and receive change.
    pub spender: Account,
    /// EVM key that submits allocation, commitment, and withdrawal calls.
    pub submitter_private_key: String,
    /// EVM key used to commit pending notes.
    pub operator_private_key: String,
    /// Token identifier used by all pool notes.
    pub token: u64,
    /// Transaction route. Production should use [`Route::Blokli`].
    pub route: Route,
    /// Fee collector identity required when the configured protocol fee is non-zero.
    pub fee_recipient: Option<Identity>,
}

impl RsSdkCurvyAdapterConfig {
    pub fn new(spender: Account, submitter_private_key: String, operator_private_key: String, token: u64) -> Self {
        Self {
            spender,
            submitter_private_key,
            operator_private_key,
            token,
            route: Route::Blokli,
            fee_recipient: None,
        }
    }
}

/// Errors raised by the production rs-sdk bridge.
#[derive(Debug, thiserror::Error)]
pub enum RsSdkCurvyAdapterError {
    #[error(transparent)]
    Sdk(#[from] anyhow::Error),
    #[error("invalid Curvy adapter value: {0}")]
    InvalidValue(String),
    #[error("the private pool has no committed note large enough to fund {required} wei")]
    NoFunding { required: u128 },
    #[error("the requested withdrawal is {requested}, but only {available} is stored")]
    InsufficientNotes { requested: u128, available: u128 },
    #[error(
        "the requested withdrawal is {requested}, but the selected whole notes total {selected}; Curvy cannot produce change"
    )]
    InexactWithdrawal { requested: u128, selected: u128 },
    #[error("PIX allocation ID was reused with a different address or amount")]
    ConflictingAllocation,
    #[error("an earlier Curvy allocation has an ambiguous outcome and must be reconciled")]
    AmbiguousAllocation,
    #[error("a different Curvy shield deposit is already in progress")]
    ShieldInProgress,
    #[error("the Curvy shield portal contains {actual} wei instead of the expected {required} wei")]
    UnexpectedShieldFunding { actual: u128, required: u128 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredNote {
    owner_pub: [String; 2],
    shared_secret: String,
    ephemeral_key: [String; 2],
    view_tag: u16,
    amount: String,
    token: String,
}

impl From<&OwnedNote> for StoredNote {
    fn from(note: &OwnedNote) -> Self {
        Self {
            owner_pub: [fr_to_dec(&note.owner_pub.0), fr_to_dec(&note.owner_pub.1)],
            shared_secret: fr_to_dec(&note.shared_secret),
            ephemeral_key: [fr_to_dec(&note.ephemeral_key.0), fr_to_dec(&note.ephemeral_key.1)],
            view_tag: note.view_tag,
            amount: fr_to_dec(&note.amount),
            token: fr_to_dec(&note.token),
        }
    }
}

impl TryFrom<&StoredNote> for OwnedNote {
    type Error = RsSdkCurvyAdapterError;

    fn try_from(note: &StoredNote) -> Result<Self, Self::Error> {
        let field = |value: &str, name: &str| {
            Bn254Fr::try_from_dec(value)
                .map(Bn254Fr::into_inner)
                .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("{name}: {error}")))
        };
        Ok(Self {
            owner_pub: (
                field(&note.owner_pub[0], "owner x")?,
                field(&note.owner_pub[1], "owner y")?,
            ),
            shared_secret: field(&note.shared_secret, "shared secret")?,
            ephemeral_key: (
                field(&note.ephemeral_key[0], "ephemeral x")?,
                field(&note.ephemeral_key[1], "ephemeral y")?,
            ),
            view_tag: note.view_tag,
            amount: field(&note.amount, "amount")?,
            token: field(&note.token, "token")?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum StoredShieldStage {
    Prepared,
    Funded,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredShield {
    note: StoredNote,
    gross: String,
    recovery: String,
    portal_address: String,
    stage: StoredShieldStage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum StoredAllocationStage {
    Prepared,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredAllocation {
    id: [u8; PixAddressId::SIZE],
    address: [u8; 32],
    amount: String,
    stage: StoredAllocationStage,
}

impl StoredAllocation {
    fn new(id: PixAddressId, address: &BjjPublicKey, amount: HoprBalance) -> Result<Self, RsSdkCurvyAdapterError> {
        Ok(Self {
            id: id.to_bytes(),
            address: address
                .as_ref()
                .try_into()
                .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("BJJ address must be 32 bytes".to_owned()))?,
            amount: amount.amount().to_string(),
            stage: StoredAllocationStage::Prepared,
        })
    }

    fn matches(&self, address: &BjjPublicKey, amount: HoprBalance) -> bool {
        self.address.as_slice() == address.as_ref() && self.amount == amount.amount().to_string()
    }
}

impl StoredShield {
    fn prepared(&self) -> Result<PreparedDeposit, RsSdkCurvyAdapterError> {
        let gross = self
            .gross
            .parse()
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(format!("shield gross: {error}")))?;
        Ok(PreparedDeposit::from_recovery_parts(
            OwnedNote::try_from(&self.note)?,
            gross,
            self.recovery.clone(),
            self.portal_address.clone(),
        ))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SdkState {
    funding: Vec<StoredNote>,
    /// Emitted notes that must be committed before their change can fund another allocation.
    pending: Vec<StoredNote>,
    /// Set after an ambiguous aggregation to prevent accidental double spending.
    ambiguous_allocation: bool,
    #[serde(default)]
    ambiguous_input: Option<StoredNote>,
    #[serde(default)]
    ambiguous_inputs: Vec<StoredNote>,
    #[serde(default)]
    ambiguous_change: Option<StoredNote>,
    #[serde(default)]
    ambiguous_emitted: Vec<StoredNote>,
    #[serde(default)]
    shield_in_flight: Option<StoredShield>,
    #[serde(default)]
    allocations: Vec<StoredAllocation>,
    #[serde(default)]
    ambiguous_allocation_ids: Vec<[u8; PixAddressId::SIZE]>,
}

struct RedbCurvySdkStore {
    db: Arc<redb::Database>,
}

impl RedbCurvySdkStore {
    fn new(state: &RedbCurvyDepositState) -> Result<Self, RsSdkCurvyAdapterError> {
        let db = state.shared_database();
        let write = db.begin_write().map_err(db_error)?;
        write.open_table(SDK_STATE_TABLE).map_err(db_error)?;
        write.commit().map_err(db_error)?;
        Ok(Self { db })
    }

    fn load(&self) -> Result<SdkState, RsSdkCurvyAdapterError> {
        let read = self.db.begin_read().map_err(db_error)?;
        let table = read.open_table(SDK_STATE_TABLE).map_err(db_error)?;
        table
            .get(SDK_STATE_KEY)
            .map_err(db_error)?
            .map(|value| serde_json::from_slice(&value.value()).map_err(anyhow::Error::new))
            .transpose()?
            .map_or_else(|| Ok(SdkState::default()), Ok)
    }

    fn save(&self, state: &SdkState) -> Result<(), RsSdkCurvyAdapterError> {
        let encoded = serde_json::to_vec(state).map_err(anyhow::Error::new)?;
        let write = self.db.begin_write().map_err(db_error)?;
        {
            let mut table = write.open_table(SDK_STATE_TABLE).map_err(db_error)?;
            table.insert(SDK_STATE_KEY, encoded).map_err(db_error)?;
        }
        write.commit().map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: impl std::fmt::Display) -> RsSdkCurvyAdapterError {
    RsSdkCurvyAdapterError::Sdk(anyhow::anyhow!(error.to_string()))
}

/// Concrete [`CurvySdkAdapter`] backed directly by `curvy-sdk`.
pub struct RsSdkCurvyAdapter {
    client: Arc<CurvyClient>,
    config: RsSdkCurvyAdapterConfig,
    store: RedbCurvySdkStore,
    state: parking_lot::Mutex<SdkState>,
    chain: tokio::sync::Mutex<()>,
}

impl RsSdkCurvyAdapter {
    pub fn new(
        client: Arc<CurvyClient>,
        config: RsSdkCurvyAdapterConfig,
        state: &RedbCurvyDepositState,
    ) -> Result<Self, RsSdkCurvyAdapterError> {
        let store = RedbCurvySdkStore::new(state)?;
        let persisted = store.load()?;
        Ok(Self {
            client,
            config,
            store,
            state: parking_lot::Mutex::new(persisted),
            chain: tokio::sync::Mutex::new(()),
        })
    }

    /// Shields initial private-pool funding if no durable funding already exists.
    pub async fn ensure_funded(
        &self,
        gross: u128,
        recovery_address: &str,
    ) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        self.recover_pending().await?;
        let already_funded = {
            let state = self.state.lock();
            !state.funding.is_empty() && state.shield_in_flight.is_none()
        };
        if already_funded {
            return Ok(Vec::new());
        }
        let mut shield = if let Some(shield) = self.state.lock().shield_in_flight.clone() {
            if shield.gross != gross.to_string() || shield.recovery != recovery_address {
                return Err(RsSdkCurvyAdapterError::ShieldInProgress);
            }
            shield
        } else {
            let prepared = self
                .client
                .prepare_deposit(&self.config.spender, gross, self.config.token, recovery_address)
                .await?;
            let shield = StoredShield {
                note: StoredNote::from(&prepared.note),
                gross: prepared.gross.to_string(),
                recovery: prepared.recovery,
                portal_address: prepared.portal_address,
                stage: StoredShieldStage::Prepared,
            };
            let mut state = self.state.lock();
            state.shield_in_flight = Some(shield.clone());
            self.store.save(&state)?;
            shield
        };
        let prepared = shield.prepared()?;
        {
            let observed_status = self.client.note_status(&prepared.note.note_id()).await?;
            let mut ledger = Vec::new();
            if !matches!(observed_status, 1 | 2) {
                if shield.stage == StoredShieldStage::Prepared {
                    let portal_balance = self.client.eth_balance(&prepared.portal_address).await?;
                    if portal_balance == 0 {
                        ledger.push(
                            self.client
                                .fund_prepared_deposit(&prepared, &self.config.operator_private_key, self.config.route)
                                .await?,
                        );
                    } else if portal_balance != gross {
                        return Err(RsSdkCurvyAdapterError::UnexpectedShieldFunding {
                            actual: portal_balance,
                            required: gross,
                        });
                    }
                    shield.stage = StoredShieldStage::Funded;
                    let mut state = self.state.lock();
                    state.shield_in_flight = Some(shield.clone());
                    self.store.save(&state)?;
                }
                ledger.push(
                    self.client
                        .shield_prepared_deposit(&prepared, &self.config.operator_private_key, self.config.route)
                        .await?,
                );
            }
            {
                let mut state = self.state.lock();
                let stored = StoredNote::from(&prepared.note);
                let prepared_id = note_id(&prepared.note);
                let already_funding = state
                    .funding
                    .iter()
                    .map(OwnedNote::try_from)
                    .collect::<Result<Vec<_>, _>>()?
                    .iter()
                    .any(|note| note_id(note) == prepared_id);
                if !already_funding {
                    state.funding.push(stored.clone());
                }
                if observed_status != 2 && !state.pending.iter().any(|note| note == &stored) {
                    state.pending.push(stored);
                }
                state.shield_in_flight = None;
                self.store.save(&state)?;
            }
            ledger.extend(self.recover_pending().await?);
            Ok(ledger)
        }
    }

    pub fn available_funding(&self) -> Result<u128, RsSdkCurvyAdapterError> {
        let mut amounts = self
            .state
            .lock()
            .funding
            .iter()
            .map(OwnedNote::try_from)
            .map(|note| {
                note.and_then(|note| {
                    fr_to_biguint(&note.amount).try_into().map_err(|_| {
                        RsSdkCurvyAdapterError::InvalidValue("funding amount does not fit u128".to_owned())
                    })
                })
            })
            .collect::<Result<Vec<u128>, _>>()?;
        amounts.sort_unstable_by(|left, right| right.cmp(left));
        amounts
            .into_iter()
            .take(MAX_ALLOCATION_INPUTS)
            .try_fold(0_u128, |total, amount| {
                total
                    .checked_add(amount)
                    .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("funding total overflows u128".to_owned()))
            })
    }

    /// Reconciles an ambiguous aggregation after Blokli has indexed at least one output.
    ///
    /// Returning `Ok(false)` keeps allocation blocked because an all-unknown result
    /// cannot distinguish a rejected transaction from one that has not been indexed yet.
    pub async fn reconcile_ambiguous_allocation(&self) -> Result<bool, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        let (inputs, change, emitted, allocation_ids) = {
            let state = self.state.lock();
            if !state.ambiguous_allocation {
                return Ok(true);
            }
            let mut inputs = state.ambiguous_inputs.clone();
            if inputs.is_empty()
                && let Some(input) = state.ambiguous_input.clone()
            {
                inputs.push(input);
            }
            if inputs.is_empty() {
                return Ok(false);
            }
            let Some(change) = state.ambiguous_change.clone() else {
                return Ok(false);
            };
            (
                inputs,
                change,
                state.ambiguous_emitted.clone(),
                state.ambiguous_allocation_ids.clone(),
            )
        };
        let emitted_notes = emitted.iter().map(OwnedNote::try_from).collect::<Result<Vec<_>, _>>()?;
        let mut observed = false;
        for note in &emitted_notes {
            if matches!(self.client.note_status(&note.note_id()).await?, 1 | 2) {
                observed = true;
                break;
            }
        }
        if !observed {
            return Ok(false);
        }
        {
            let mut state = self.state.lock();
            state.funding.retain(|note| !inputs.contains(note));
            state.funding.push(change);
            state.pending.extend(emitted);
            state.ambiguous_allocation = false;
            state.ambiguous_input = None;
            state.ambiguous_inputs.clear();
            state.ambiguous_change = None;
            state.ambiguous_emitted.clear();
            for allocation in &mut state.allocations {
                if allocation_ids.contains(&allocation.id) {
                    allocation.stage = StoredAllocationStage::Completed;
                }
            }
            state.ambiguous_allocation_ids.clear();
            self.store.save(&state)?;
        }
        self.recover_pending().await?;
        Ok(true)
    }

    async fn recover_pending(&self) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let pending = self.state.lock().pending.clone();
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let notes = pending.iter().map(OwnedNote::try_from).collect::<Result<Vec<_>, _>>()?;
        let mut ledger = Vec::new();
        for chunk in notes.chunks(MAX_COMMITMENTS_PER_PROOF) {
            let mut ids = Vec::new();
            for note in chunk {
                if self.client.note_status(&note.note_id()).await? != 2 {
                    ids.push(note.note_id());
                }
            }
            if !ids.is_empty() {
                ledger.extend(
                    self.client
                        .commit(&ids, &self.config.operator_private_key, self.config.route)
                        .await?,
                );
            }
        }
        let mut state = self.state.lock();
        state.pending.clear();
        self.store.save(&state)?;
        Ok(ledger)
    }

    fn recipient(address: &BjjPublicKey) -> Result<KnownOwner, RsSdkCurvyAdapterError> {
        let bytes: [u8; 32] = address
            .as_ref()
            .try_into()
            .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("BJJ address must be 32 bytes".to_owned()))?;
        let point = Option::<babyjubjub_ec::ProjectivePoint>::from(babyjubjub_ec::ProjectivePoint::from_bytes(
            &babyjubjub_ec::GroupRepr(bytes),
        ))
        .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("invalid compressed BJJ point".to_owned()))?;
        let affine = babyjubjub_ec::AffinePoint::from(point);
        let coordinate = |value: String| {
            Bn254Fr::try_from_dec(&value)
                .map(Bn254Fr::into_inner)
                .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(error.to_string()))
        };
        let owner = BabyJubPoint::try_from_xy(coordinate(affine.x().to_string())?, coordinate(affine.y().to_string())?)
            .map_err(|error| RsSdkCurvyAdapterError::InvalidValue(error.to_string()))?;
        let mut shared_secret = [0_u8; 32];
        getrandom::fill(&mut shared_secret).map_err(|error| RsSdkCurvyAdapterError::InvalidValue(error.to_string()))?;
        Ok(KnownOwner::new(
            owner,
            Bn254Fr::from_fr(fr_from_be_bytes_mod(&shared_secret)),
        ))
    }

    async fn allocate(
        &self,
        deposits: &[(PixAddressId, BjjPublicKey, HoprBalance)],
    ) -> Result<Vec<TxLedger>, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        if self.state.lock().ambiguous_allocation {
            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
        }
        let deposits = {
            let state = self.state.lock();
            let mut pending = Vec::new();
            for (id, address, amount) in deposits {
                if let Some(existing) = state
                    .allocations
                    .iter()
                    .find(|allocation| allocation.id == id.to_bytes())
                {
                    if !existing.matches(address, *amount) {
                        return Err(RsSdkCurvyAdapterError::ConflictingAllocation);
                    }
                    match existing.stage {
                        StoredAllocationStage::Completed => continue,
                        StoredAllocationStage::Prepared => {
                            return Err(RsSdkCurvyAdapterError::AmbiguousAllocation);
                        }
                    }
                }
                pending.push((*id, *address, *amount));
            }
            pending
        };
        let mut receipts = Vec::new();
        self.recover_pending().await?;
        for chunk in deposits.chunks(MAX_ALLOCATIONS_PER_PROOF) {
            let allocations = chunk
                .iter()
                .map(|(_, address, amount)| {
                    let amount = amount.amount().try_into().map_err(|_| {
                        RsSdkCurvyAdapterError::InvalidValue("allocation amount does not fit u128".to_owned())
                    })?;
                    Ok((Self::recipient(address)?, amount))
                })
                .collect::<Result<Vec<_>, RsSdkCurvyAdapterError>>()?;
            let total = allocations.iter().try_fold(0_u128, |total, (_, amount)| {
                total
                    .checked_add(*amount)
                    .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("allocation total overflows u128".to_owned()))
            })?;
            let minimum = self
                .client
                .pix_minimum_input(&Fr::from(self.config.token), total, 0)
                .await?;
            let funding = {
                let state = self.state.lock();
                let mut candidates = state
                    .funding
                    .iter()
                    .map(|stored| {
                        let note = OwnedNote::try_from(stored)?;
                        let amount = fr_to_biguint(&note.amount).try_into().map_err(|_| {
                            RsSdkCurvyAdapterError::InvalidValue("funding amount does not fit u128".to_owned())
                        })?;
                        Ok((stored.clone(), note, amount))
                    })
                    .collect::<Result<Vec<(_, _, u128)>, RsSdkCurvyAdapterError>>()?;
                candidates.sort_unstable_by_key(|candidate| std::cmp::Reverse(candidate.2));
                if let Some(single) = candidates.iter().find(|candidate| candidate.2 >= minimum) {
                    vec![single.clone()]
                } else {
                    let selected = candidates.into_iter().take(MAX_ALLOCATION_INPUTS).collect::<Vec<_>>();
                    let available = selected.iter().try_fold(0_u128, |total, candidate| {
                        total.checked_add(candidate.2).ok_or_else(|| {
                            RsSdkCurvyAdapterError::InvalidValue("funding total overflows u128".to_owned())
                        })
                    })?;
                    if available < minimum {
                        return Err(RsSdkCurvyAdapterError::NoFunding { required: minimum });
                    }
                    selected
                }
            };
            let allocation_records = chunk
                .iter()
                .map(|(id, address, amount)| StoredAllocation::new(*id, address, *amount))
                .collect::<Result<Vec<_>, _>>()?;
            {
                let mut state = self.state.lock();
                state.allocations.extend(allocation_records.clone());
                self.store.save(&state)?;
            }
            let funding_notes = funding.iter().map(|(_, note, _)| note.clone()).collect::<Vec<_>>();
            let aggregated = self
                .client
                .aggregate_pix_allocations(
                    &self.config.spender,
                    &funding_notes,
                    &allocations,
                    None,
                    self.config.fee_recipient.as_ref(),
                    &self.config.submitter_private_key,
                    self.config.route,
                )
                .await;
            let result = match aggregated {
                Ok(result) => result,
                Err(error) => {
                    if let Some(ambiguous) = curvy_sdk::ambiguous_pix_aggregation(&error) {
                        let mut state = self.state.lock();
                        state.ambiguous_allocation = true;
                        state.ambiguous_inputs = funding.iter().map(|(stored, _, _)| stored.clone()).collect();
                        state.ambiguous_change = Some(StoredNote::from(&ambiguous.result.change));
                        state.ambiguous_emitted = ambiguous
                            .result
                            .emitted_notes
                            .iter()
                            .filter(|note| note.amount != Fr::from(0_u8))
                            .map(StoredNote::from)
                            .collect();
                        state.ambiguous_allocation_ids = allocation_records.iter().map(|record| record.id).collect();
                        self.store.save(&state)?;
                    } else if curvy_sdk::ambiguous_submission(&error).is_some() {
                        let mut state = self.state.lock();
                        state.ambiguous_allocation = true;
                        state.ambiguous_allocation_ids = allocation_records.iter().map(|record| record.id).collect();
                        self.store.save(&state)?;
                    } else {
                        let mut state = self.state.lock();
                        state
                            .allocations
                            .retain(|allocation| !allocation_records.iter().any(|record| record.id == allocation.id));
                        self.store.save(&state)?;
                    }
                    return Err(error.into());
                }
            };
            {
                let mut state = self.state.lock();
                state
                    .funding
                    .retain(|note| !funding.iter().any(|(stored, _, _)| stored == note));
                state.funding.push(StoredNote::from(&result.change));
                state.pending.extend(
                    result
                        .emitted_notes
                        .iter()
                        .filter(|note| note.amount != Fr::from(0_u8))
                        .map(StoredNote::from),
                );
                for allocation in &mut state.allocations {
                    if allocation_records.iter().any(|record| record.id == allocation.id) {
                        allocation.stage = StoredAllocationStage::Completed;
                    }
                }
                self.store.save(&state)?;
            }
            let mut ledger = result.ledger;
            ledger.extend(self.recover_pending().await?);
            receipts.extend(ledger);
        }
        Ok(receipts)
    }

    fn owned_note(note: &CommittedCurvyNote) -> Result<OwnedNote, RsSdkCurvyAdapterError> {
        let view_tag: u8 = fr_to_biguint(&note.note.view_tag)
            .try_into()
            .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("note view tag does not fit one byte".to_owned()))?;
        Ok(OwnedNote {
            owner_pub: note.note.owner_pub,
            shared_secret: note.note.shared_secret,
            ephemeral_key: note.note.ephemeral_key,
            view_tag: view_tag.into(),
            amount: note.note.amount,
            token: note.note.token,
        })
    }

    fn select_notes(
        notes: Vec<CommittedCurvyNote>,
        amount: Option<HoprBalance>,
    ) -> Result<Vec<OwnedNote>, RsSdkCurvyAdapterError> {
        let mut notes = notes.iter().map(Self::owned_note).collect::<Result<Vec<_>, _>>()?;
        let Some(target) = amount else {
            return Ok(notes);
        };
        let target = target
            .amount()
            .try_into()
            .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("withdrawal amount does not fit u128".to_owned()))?;
        notes.sort_by_key(|note| std::cmp::Reverse(fr_to_biguint(&note.amount)));
        let mut selected = Vec::new();
        let mut total = 0_u128;
        for note in notes {
            if total >= target {
                break;
            }
            let value: u128 = fr_to_biguint(&note.amount)
                .try_into()
                .map_err(|_| RsSdkCurvyAdapterError::InvalidValue("note amount does not fit u128".to_owned()))?;
            total = total
                .checked_add(value)
                .ok_or_else(|| RsSdkCurvyAdapterError::InvalidValue("note total overflows u128".to_owned()))?;
            selected.push(note);
        }
        if total < target {
            return Err(RsSdkCurvyAdapterError::InsufficientNotes {
                requested: target,
                available: total,
            });
        }
        if total != target {
            return Err(RsSdkCurvyAdapterError::InexactWithdrawal {
                requested: target,
                selected: total,
            });
        }
        Ok(selected)
    }

    async fn withdraw_notes(
        &self,
        secret: &curvy_core::eddsa::ScalarSigningKey,
        notes: Vec<OwnedNote>,
        destination: Address,
    ) -> Result<CurvyWithdrawalOutcome<Vec<TxLedger>>, RsSdkCurvyAdapterError> {
        let _chain = self.chain.lock().await;
        let mut receipt = Vec::new();
        let mut spent_note_ids = Vec::new();
        for chunk in notes.chunks(MAX_WITHDRAWAL_INPUTS) {
            let spends = chunk.iter().map(|note| (secret, note)).collect::<Vec<_>>();
            let (_, ledger) = self
                .client
                .withdraw_pix_multi_owner(
                    &spends,
                    &destination.to_string(),
                    &self.config.submitter_private_key,
                    self.config.route,
                )
                .await?;
            receipt.extend(ledger);
            spent_note_ids.extend(chunk.iter().map(note_id));
        }
        Ok(CurvyWithdrawalOutcome {
            receipt,
            spent_note_ids,
        })
    }
}

#[async_trait::async_trait]
impl CurvySdkAdapter for RsSdkCurvyAdapter {
    type Error = RsSdkCurvyAdapterError;
    type Receipt = Vec<TxLedger>;

    async fn deposit(
        &self,
        id: PixAddressId,
        dst: BjjPublicKey,
        amount: HoprBalance,
    ) -> Result<Self::Receipt, Self::Error> {
        self.allocate(&[(id, dst, amount)]).await
    }

    async fn deposit_multiple(
        &self,
        deposits: Vec<(PixAddressId, BjjPublicKey, HoprBalance)>,
    ) -> Result<Vec<Self::Receipt>, Self::Error> {
        self.allocate(&deposits)
            .await
            .map(|receipt| if receipt.is_empty() { Vec::new() } else { vec![receipt] })
    }

    async fn withdraw(
        &self,
        secret: &curvy_core::eddsa::ScalarSigningKey,
        notes: Vec<CommittedCurvyNote>,
        dst: Address,
        amount: Option<HoprBalance>,
    ) -> Result<CurvyWithdrawalOutcome<Self::Receipt>, Self::Error> {
        self.withdraw_notes(secret, Self::select_notes(notes, amount)?, dst)
            .await
    }

    async fn withdraw_multiple(
        &self,
        withdrawals: Vec<CurvyWithdrawal>,
        dst: Address,
    ) -> Result<Vec<Result<(Address, CurvyWithdrawalOutcome<Self::Receipt>), Self::Error>>, Self::Error> {
        let mut outcomes = Vec::with_capacity(withdrawals.len());
        for withdrawal in withdrawals {
            outcomes.push(
                self.withdraw_notes(&withdrawal.secret, Self::select_notes(withdrawal.notes, None)?, dst)
                    .await
                    .map(|outcome| (dst, outcome)),
            );
        }
        Ok(outcomes)
    }
}

fn note_id(note: &OwnedNote) -> String {
    fr_to_be_32(&note.note_id())
        .iter()
        .fold(String::from("0x"), |mut encoded, byte| {
            let _ = write!(encoded, "{byte:02x}");
            encoded
        })
}

/// Constructs a Curvy client whose reads and submissions all go through Blokli.
pub fn blokli_curvy_client(
    blokli_url: impl Into<String>,
    aggregator: impl Into<String>,
    portal_factory: impl Into<String>,
    chain_id: u64,
) -> Arc<CurvyClient> {
    let blokli = Arc::new(curvy_chain_blokli::BlokliChain::new(blokli_url));
    Arc::new(CurvyClient::new(
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli.clone(),
        blokli,
        aggregator.into(),
        portal_factory.into(),
        chain_id,
    ))
}

#[cfg(test)]
mod tests {
    use curvy_core::{field::Fr, witness::Note};
    use hopr_api::types::{
        crypto::prelude::{BjjKeypair, Keypair},
        crypto_random::Randomizable,
        internal::prelude::HoprPseudonym,
        primitive::prelude::U256,
    };

    use super::*;
    use crate::pix::OwnedCurvyDeposit;

    #[test]
    fn sdk_note_conversion_preserves_the_complete_note() -> anyhow::Result<()> {
        let committed = fixture(7);
        let converted = RsSdkCurvyAdapter::owned_note(&committed)?;
        let converted = converted.to_core();
        assert_eq!(converted.owner_pub, committed.note.owner_pub);
        assert_eq!(converted.shared_secret, committed.note.shared_secret);
        assert_eq!(converted.ephemeral_key, committed.note.ephemeral_key);
        assert_eq!(converted.view_tag, committed.note.view_tag);
        assert_eq!(converted.amount, committed.note.amount);
        assert_eq!(converted.token, committed.note.token);
        Ok(())
    }

    #[test]
    fn sdk_note_conversion_rejects_a_non_byte_view_tag() {
        let mut committed = fixture(7);
        committed.note.view_tag = Fr::from(256_u64);

        assert!(matches!(
            RsSdkCurvyAdapter::owned_note(&committed),
            Err(RsSdkCurvyAdapterError::InvalidValue(_))
        ));
    }

    #[test]
    fn stored_allocation_binds_id_address_and_amount() -> anyhow::Result<()> {
        let committed = fixture(7);
        let allocation = StoredAllocation::new(
            committed.deposit.id,
            &committed.deposit.address,
            committed.deposit.amount,
        )?;

        assert!(allocation.matches(&committed.deposit.address, committed.deposit.amount));
        assert!(!allocation.matches(&committed.deposit.address, HoprBalance::from(U256::from(8_u8))));
        Ok(())
    }

    #[test]
    fn partial_withdrawal_rejects_an_inexact_whole_note_total() {
        let result = RsSdkCurvyAdapter::select_notes(
            vec![fixture(3), fixture(8), fixture(5)],
            Some(HoprBalance::from(U256::from(10_u8))),
        );
        assert!(matches!(
            result,
            Err(RsSdkCurvyAdapterError::InexactWithdrawal {
                requested: 10,
                selected: 13
            })
        ));
    }

    #[test]
    fn partial_withdrawal_accepts_an_exact_whole_note_total() -> anyhow::Result<()> {
        let selected = RsSdkCurvyAdapter::select_notes(
            vec![fixture(3), fixture(8), fixture(5)],
            Some(HoprBalance::from(U256::from(13_u8))),
        )?;
        let total = selected
            .iter()
            .map(|note| u128::try_from(fr_to_biguint(&note.amount)).unwrap())
            .sum::<u128>();
        assert_eq!(total, 13);
        Ok(())
    }

    fn fixture(amount: u64) -> CommittedCurvyNote {
        let address = *BjjKeypair::from_secret(&[1_u8; 32]).unwrap().public();
        CommittedCurvyNote {
            deposit: OwnedCurvyDeposit {
                id: (HoprPseudonym::random(), std::num::NonZeroU32::new(1).unwrap()).into(),
                address,
                amount: HoprBalance::from(U256::from(amount)),
            },
            note: Note {
                owner_pub: (Fr::from(1_u8), Fr::from(2_u8)),
                shared_secret: Fr::from(amount),
                ephemeral_key: (Fr::from(4_u8), Fr::from(5_u8)),
                view_tag: Fr::from(6_u8),
                amount: Fr::from(amount),
                token: Fr::from(1_u8),
            },
            leaf_index: amount,
        }
    }
}
