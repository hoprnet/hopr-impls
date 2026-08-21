//! Curvy-backed anonymous deposit-pool integration for PIX.
//!
//! Blokli deliberately exposes the global Curvy note index. This module keeps
//! wallet-specific state local: `curvy-core` validates candidates owned by an
//! active PIX deposit address, while the tracker persists exclusive query
//! cursors and correlates pending and committed note IDs.

use std::{
    collections::{HashMap, hash_map::Entry},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use babyjubjub_ec::elliptic_curve::group::GroupEncoding;
use blokli_client::api::{
    BlokliQueryClient,
    types::{CurvyCommittedNote, CurvyEventCursor, CurvyPendingNote, Hex32, Uint64},
};
use curvy_core::{
    babyjubjub::BabyJubPoint,
    cipher::decrypt_amount_token,
    eddsa::ScalarSigningKey,
    field::{Bn254Fr, fr_from_be_32_checked, fr_from_be_bytes_mod, fr_to_be_32, fr_to_biguint},
    stealth,
    witness::{KnownOwner, Note},
};
use hopr_api::{
    chain::{AdditionalDepositData, DepositNotification, DepositPool},
    node::PixAddressId,
    types::{
        crypto::prelude::{BjjKeypair, BjjPublicKey, CurvyScanPublicKey, CurvyScanSecret, Keypair},
        primitive::prelude::*,
    },
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

const CURSOR_TABLE: TableDefinition<u8, Vec<u8>> = TableDefinition::new("curvy_pix_cursor");
const NOTE_ID_SIZE: usize = 32;
const OWNED_NOTE_KEY_SIZE: usize = PixAddressId::SIZE + NOTE_ID_SIZE;
const OWNED_NOTES_TABLE: TableDefinition<[u8; OWNED_NOTE_KEY_SIZE], Vec<u8>> =
    TableDefinition::new("curvy_pix_owned_notes_v2");
const NOTE_SESSIONS_TABLE: TableDefinition<[u8; NOTE_ID_SIZE], [u8; PixAddressId::SIZE]> =
    TableDefinition::new("curvy_pix_note_sessions");
const PENDING_CURSOR_KEY: u8 = 0;
const COMMITTED_CURSOR_KEY: u8 = 1;
const CURSOR_SIZE_WITHOUT_HASH: usize = 32;
const OWNED_NOTE_VERSION: u8 = 1;
const OWNED_NOTE_SIZE: usize = 344;
const QUERY_PAGE_SIZE: u32 = 1_000;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
const DEFAULT_MAX_DEPOSIT_TRACKING_TIME: Duration = Duration::from_secs(60);

/// File name used for the durable Curvy note database beside the ticket database.
pub const CURVY_NOTE_DATABASE_FILE_NAME: &str = "curvy-pix.redb";

/// Deposit metadata retained by the connector for correlation and notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedCurvyDeposit {
    /// PIX session allocation to which the note belongs.
    pub id: PixAddressId,
    /// PIX deposit address to which the note belongs.
    pub address: BjjPublicKey,
    /// Amount contained in the note, denominated in wxHOPR wei.
    pub amount: HoprBalance,
}

/// A complete owned Curvy note validated by the `rs-core` detector.
#[derive(Clone)]
pub struct DetectedCurvyNote {
    /// HOPR-facing deposit metadata.
    pub deposit: OwnedCurvyDeposit,
    /// Full Curvy witness note required for a later reconstructed-key withdrawal.
    pub note: Note,
}

/// A connector-owned note that has appeared in the committed Curvy tree.
#[derive(Clone)]
pub struct CommittedCurvyNote {
    /// HOPR-facing deposit metadata.
    pub deposit: OwnedCurvyDeposit,
    /// Full note required by Curvy withdrawal witness construction.
    pub note: Note,
    /// Leaf index reported by Blokli when the note was committed.
    pub leaf_index: u64,
}

/// One reconstructed PIX key and all committed notes belonging to its session.
pub struct CurvyWithdrawal {
    /// Reconstructed BabyJubJub signing scalar.
    pub secret: ScalarSigningKey,
    /// Notes durably recovered by the connector for this key.
    pub notes: Vec<CommittedCurvyNote>,
}

/// Result of an SDK withdrawal, including the notes whose nullifiers were submitted.
pub struct CurvyWithdrawalOutcome<R> {
    /// SDK-specific transaction receipt.
    pub receipt: R,
    /// Note identifiers that must be removed from the connector's spendable set.
    pub spent_note_ids: Vec<String>,
}

/// Curvy chain operations that require SDK knowledge.
///
/// The connector owns note retrieval, durable note state, cursors, correlation
/// and PIX [`DepositPool`] behavior. Proof generation and contract payload
/// construction remain delegated to the Curvy SDK through this narrow adapter.
/// Candidate ownership validation is implemented locally by
/// [`RsCoreCurvyNoteDetector`] using `curvy-core`.
#[async_trait::async_trait]
pub trait CurvySdkAdapter: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    type Receipt: Default + Send + Sync + 'static;

    /// Deposits funds to one Curvy BJJ address.
    async fn deposit(
        &self,
        id: PixAddressId,
        dst: BjjPublicKey,
        scan_key: CurvyScanPublicKey,
        amount: HoprBalance,
    ) -> Result<Self::Receipt, Self::Error>;

    /// Deposits funds to several Curvy BJJ addresses using the SDK's native batch operation.
    async fn deposit_multiple(
        &self,
        deposits: Vec<(PixAddressId, BjjPublicKey, CurvyScanPublicKey, HoprBalance)>,
    ) -> Result<Vec<Self::Receipt>, Self::Error>;

    /// Withdraws a Curvy note using the recovered PIX secret.
    async fn withdraw(
        &self,
        secret: &ScalarSigningKey,
        notes: Vec<CommittedCurvyNote>,
        dst: Address,
        amount: Option<HoprBalance>,
    ) -> Result<CurvyWithdrawalOutcome<Self::Receipt>, Self::Error>;

    /// Withdraws several Curvy allocations to one Ethereum address. Implementations may
    /// submit one native batch or preserve the logical result order through sequential calls.
    async fn withdraw_multiple(
        &self,
        withdrawals: Vec<CurvyWithdrawal>,
        dst: Address,
    ) -> Result<Vec<Result<(Address, CurvyWithdrawalOutcome<Self::Receipt>), Self::Error>>, Self::Error>;
}

/// Errors produced while validating a Blokli candidate with `curvy-core`.
#[derive(Debug, thiserror::Error)]
pub enum CurvyDetectionError {
    #[error("invalid Curvy detection candidate: {0}")]
    InvalidCandidate(String),
}

/// `rs-core`-backed Curvy ownership and integrity validator.
pub struct RsCoreCurvyNoteDetector {
    expected_token: Bn254Fr,
}

impl RsCoreCurvyNoteDetector {
    /// Creates a detector restricted to one Curvy token identifier.
    pub fn new(expected_token: Bn254Fr) -> Self {
        Self { expected_token }
    }

    /// Construct a detector for a Curvy vault token id.
    pub fn for_token(expected_token: u64) -> Self {
        Self::new(Bn254Fr::from_fr(curvy_core::Fr::from(expected_token)))
    }

    fn detect_owned_note(
        &self,
        candidate: &CurvyPendingNote,
        watched_allocations: &[(PixAddressId, BjjPublicKey, CurvyScanSecret)],
    ) -> Result<Option<DetectedCurvyNote>, CurvyDetectionError> {
        let note_id = parse_curvy_note_id(&candidate.note_id.0)?;
        let encrypted_amount = parse_curvy_field(&candidate.amount.0, "amount")?;
        let encrypted_token = parse_curvy_field(&candidate.token_id.0, "token")?;
        let [ephemeral_x, ephemeral_y] = candidate.ephemeral_key.as_slice() else {
            return Err(CurvyDetectionError::InvalidCandidate(
                "ephemeral key must contain exactly two coordinates".to_owned(),
            ));
        };
        let ephemeral_x = parse_curvy_field(&ephemeral_x.0, "ephemeral key x")?;
        let ephemeral_y = parse_curvy_field(&ephemeral_y.0, "ephemeral key y")?;
        let view_tag_value = u8::try_from(candidate.view_tag)
            .map_err(|_| CurvyDetectionError::InvalidCandidate("view tag must fit into one byte".to_owned()))?;
        let view_tag = Bn254Fr::from_fr(curvy_core::Fr::from(u64::from(view_tag_value)));
        let announcement = format!("{}.{}", ephemeral_x.to_dec(), ephemeral_y.to_dec());
        let scan_tag = format!("{view_tag_value:02x}");
        // The per-SSA viewer can identify and decrypt the candidate, but it has no
        // BJJ signing secret. Integrity is established separately by recomputing the
        // note ID with the SSA-derived public owner.
        for (id, address, scan_key) in watched_allocations {
            let expected_owner = bjj_point(address)
                .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("invalid owner key: {error}")))?;
            // The scan identity travels point-compressed; scanning needs the affine `K`.
            let (kx, ky) = scan_key.public().spend_meta_key().map_err(|error| {
                CurvyDetectionError::InvalidCandidate(format!("invalid Curvy spend meta-key: {error}"))
            })?;
            let spend_meta_key = format!("{}.{}", U256::from_big_endian(&kx), U256::from_big_endian(&ky));
            let view_secret = const_hex::encode(scan_key.view_secret().as_ref());
            let matches = stealth::viewer_scan(
                &view_secret,
                &spend_meta_key,
                std::slice::from_ref(&announcement),
                std::slice::from_ref(&scan_tag),
            )
            .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("Curvy viewer scan failed: {error}")))?;
            let Some(scan_match) = matches.first() else {
                continue;
            };
            if scan_match.index != 0 {
                return Err(CurvyDetectionError::InvalidCandidate(
                    "single-note Curvy viewer scan returned an invalid match index".to_owned(),
                ));
            }
            let shared_secret = shared_secret_from_scan_match(&scan_match.spending_pub_key)?;
            let (amount, token) = decrypt_candidate_amount_token(
                encrypted_amount,
                encrypted_token,
                shared_secret,
                ephemeral_x,
                ephemeral_y,
                candidate.is_plaintext,
            );
            if token != self.expected_token {
                continue;
            }

            let note = KnownOwner::new(expected_owner, shared_secret).note(
                amount.into_inner(),
                token.into_inner(),
                (ephemeral_x.into_inner(), ephemeral_y.into_inner()),
                view_tag.into_inner(),
            );
            if note.id() == note_id.into_inner() {
                let amount = U256::from_big_endian(&fr_to_biguint(&amount.into_inner()).to_bytes_be());
                return Ok(Some(DetectedCurvyNote {
                    deposit: OwnedCurvyDeposit {
                        id: *id,
                        address: *address,
                        amount: HoprBalance::from(amount),
                    },
                    note,
                }));
            }
        }

        Ok(None)
    }
}

fn decrypt_candidate_amount_token(
    encrypted_amount: Bn254Fr,
    encrypted_token: Bn254Fr,
    shared_secret: Bn254Fr,
    ephemeral_x: Bn254Fr,
    ephemeral_y: Bn254Fr,
    is_plaintext: bool,
) -> (Bn254Fr, Bn254Fr) {
    if is_plaintext {
        (encrypted_amount, encrypted_token)
    } else {
        let (amount, token) = decrypt_amount_token(
            encrypted_amount.into_inner(),
            encrypted_token.into_inner(),
            &fr_to_biguint(&shared_secret.into_inner()),
            (
                &fr_to_biguint(&ephemeral_x.into_inner()),
                &fr_to_biguint(&ephemeral_y.into_inner()),
            ),
        );
        (Bn254Fr::from_fr(amount), Bn254Fr::from_fr(token))
    }
}

fn shared_secret_from_scan_match(spending_public_key: &str) -> Result<Bn254Fr, CurvyDetectionError> {
    let (x, y) = spending_public_key.split_once('.').ok_or_else(|| {
        CurvyDetectionError::InvalidCandidate("Curvy scan returned a malformed spending public key".to_owned())
    })?;
    let x = U256::from_str_radix(x, 10).map_err(|error| {
        CurvyDetectionError::InvalidCandidate(format!("invalid scanned spending public key x: {error}"))
    })?;
    U256::from_str_radix(y, 10).map_err(|error| {
        CurvyDetectionError::InvalidCandidate(format!("invalid scanned spending public key y: {error}"))
    })?;
    Ok(Bn254Fr::from_fr(fr_from_be_bytes_mod(&x.to_be_bytes())))
}

fn parse_curvy_field(value: &str, field: &str) -> Result<Bn254Fr, CurvyDetectionError> {
    Bn254Fr::try_from_dec(value)
        .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("invalid {field}: {error}")))
}

fn parse_curvy_note_id(value: &str) -> Result<Bn254Fr, CurvyDetectionError> {
    let encoded = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| {
            CurvyDetectionError::InvalidCandidate("deposit note id must use 0x-prefixed Hex32 encoding".to_owned())
        })?;
    if encoded.len() != 64 {
        return Err(CurvyDetectionError::InvalidCandidate(
            "deposit note id must contain exactly 32 bytes".to_owned(),
        ));
    }
    let note_id = U256::from_str_radix(encoded, 16)
        .map_err(|error| CurvyDetectionError::InvalidCandidate(format!("invalid deposit note id: {error}")))?;
    fr_from_be_32_checked(&note_id.to_be_bytes())
        .map(Bn254Fr::from_fr)
        .ok_or_else(|| {
            CurvyDetectionError::InvalidCandidate("deposit note id is not a canonical BN254 field element".to_owned())
        })
}

fn bjj_point(address: &BjjPublicKey) -> Result<BabyJubPoint, &'static str> {
    let bytes: [u8; 32] = address
        .as_ref()
        .try_into()
        .map_err(|_| "invalid compressed-key length")?;
    let point = Option::<babyjubjub_ec::ProjectivePoint>::from(babyjubjub_ec::ProjectivePoint::from_bytes(
        &babyjubjub_ec::GroupRepr(bytes),
    ))
    .ok_or("invalid compressed point")?;
    let affine = babyjubjub_ec::AffinePoint::from(point);
    BabyJubPoint::try_from_dec(&affine.x().to_string(), &affine.y().to_string())
        .map_err(|_| "point is not in the Curvy BabyJubJub subgroup")
}

/// Persistent state errors for the Curvy lifecycle tracker.
#[derive(Debug, thiserror::Error)]
pub enum CurvyStateError {
    #[error("Curvy PIX state database error: {0}")]
    Database(String),
    #[error("corrupt Curvy PIX state: {0}")]
    Corrupt(String),
}

fn state_db_error(error: impl std::fmt::Display) -> CurvyStateError {
    CurvyStateError::Database(error.to_string())
}

/// Independently checkpointed Curvy event families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurvyEventKind {
    /// Pending notes that still require local ownership detection.
    Pending,
    /// Committed notes that are correlated against retained owned IDs.
    Committed,
}

impl CurvyEventKind {
    fn cursor_key(self) -> u8 {
        match self {
            Self::Pending => PENDING_CURSOR_KEY,
            Self::Committed => COMMITTED_CURSOR_KEY,
        }
    }
}

fn cursor_component(value: &Uint64, name: &str) -> Result<u64, CurvyStateError> {
    value
        .0
        .parse()
        .map_err(|error| CurvyStateError::Corrupt(format!("invalid Curvy cursor {name}: {error}")))
}

fn encode_cursor(cursor: &CurvyEventCursor) -> Result<Vec<u8>, CurvyStateError> {
    let mut encoded =
        Vec::with_capacity(CURSOR_SIZE_WITHOUT_HASH + cursor.block_hash.as_ref().map_or(0, |hash| hash.0.len()));
    encoded.extend_from_slice(&cursor_component(&cursor.block, "block")?.to_be_bytes());
    encoded.extend_from_slice(&cursor_component(&cursor.transaction_index, "transaction index")?.to_be_bytes());
    encoded.extend_from_slice(&cursor_component(&cursor.log_index, "log index")?.to_be_bytes());
    encoded.extend_from_slice(&cursor_component(&cursor.event_item_index, "event item index")?.to_be_bytes());
    if let Some(hash) = &cursor.block_hash {
        encoded.extend_from_slice(hash.0.as_bytes());
    }
    Ok(encoded)
}

fn decode_cursor(encoded: &[u8]) -> Result<CurvyEventCursor, CurvyStateError> {
    if encoded.len() < CURSOR_SIZE_WITHOUT_HASH {
        return Err(CurvyStateError::Corrupt(format!(
            "Curvy cursor has {} bytes, expected at least {CURSOR_SIZE_WITHOUT_HASH}",
            encoded.len()
        )));
    }
    let read_u64 = |offset: usize| {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&encoded[offset..offset + 8]);
        u64::from_be_bytes(bytes)
    };
    let mut cursor = CurvyEventCursor::new(read_u64(0), read_u64(8), read_u64(16), read_u64(24));
    if encoded.len() > CURSOR_SIZE_WITHOUT_HASH {
        cursor.block_hash = Some(Hex32(
            String::from_utf8(encoded[CURSOR_SIZE_WITHOUT_HASH..].to_vec())
                .map_err(|error| CurvyStateError::Corrupt(format!("cursor block hash is not UTF-8: {error}")))?,
        ));
    }
    Ok(cursor)
}

#[derive(Clone)]
struct StoredOwnedNote {
    detected: DetectedCurvyNote,
    committed: bool,
    leaf_index: Option<u64>,
}

fn encode_note_field(encoded: &mut Vec<u8>, value: &curvy_core::Fr) {
    encoded.extend_from_slice(&fr_to_be_32(value));
}

fn decode_note_field(encoded: &[u8], offset: &mut usize, name: &str) -> Result<curvy_core::Fr, CurvyStateError> {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&encoded[*offset..*offset + 32]);
    *offset += 32;
    fr_from_be_32_checked(&bytes)
        .ok_or_else(|| CurvyStateError::Corrupt(format!("owned-note {name} is not a canonical BN254 field element")))
}

fn encode_owned_note(note: &StoredOwnedNote) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(OWNED_NOTE_SIZE);
    encoded.push(OWNED_NOTE_VERSION);
    encoded.extend_from_slice(&note.detected.deposit.id.to_bytes());
    encoded.extend_from_slice(note.detected.deposit.address.as_ref());
    encoded.extend_from_slice(&note.detected.deposit.amount.amount().to_be_bytes());
    encode_note_field(&mut encoded, &note.detected.note.amount);
    encode_note_field(&mut encoded, &note.detected.note.token);
    encode_note_field(&mut encoded, &note.detected.note.owner_pub.0);
    encode_note_field(&mut encoded, &note.detected.note.owner_pub.1);
    encode_note_field(&mut encoded, &note.detected.note.shared_secret);
    encode_note_field(&mut encoded, &note.detected.note.ephemeral_key.0);
    encode_note_field(&mut encoded, &note.detected.note.ephemeral_key.1);
    encode_note_field(&mut encoded, &note.detected.note.view_tag);
    encoded.push(u8::from(note.committed));
    encoded.extend_from_slice(&note.leaf_index.unwrap_or(u64::MAX).to_be_bytes());
    encoded
}

fn decode_owned_note(encoded: &[u8]) -> Result<StoredOwnedNote, CurvyStateError> {
    if encoded.len() != OWNED_NOTE_SIZE {
        return Err(CurvyStateError::Corrupt(format!(
            "owned-note record has {} bytes, expected {OWNED_NOTE_SIZE}",
            encoded.len()
        )));
    }

    if encoded[0] != OWNED_NOTE_VERSION {
        return Err(CurvyStateError::Corrupt(format!(
            "unsupported owned-note record version {}",
            encoded[0]
        )));
    }

    let id = PixAddressId::try_from(&encoded[1..1 + PixAddressId::SIZE])
        .map_err(|error| CurvyStateError::Corrupt(format!("invalid PIX allocation ID: {error}")))?;
    let address_offset = 1 + PixAddressId::SIZE;
    let amount_offset = address_offset + 32;
    let address = BjjPublicKey::try_from(&encoded[address_offset..amount_offset])
        .map_err(|error| CurvyStateError::Corrupt(format!("invalid BJJ address: {error}")))?;
    let fields_offset = amount_offset + 32;
    let amount = HoprBalance::from(U256::from_be_bytes(&encoded[amount_offset..fields_offset]));
    let mut offset = fields_offset;
    let note = Note {
        amount: decode_note_field(encoded, &mut offset, "amount")?,
        token: decode_note_field(encoded, &mut offset, "token")?,
        owner_pub: (
            decode_note_field(encoded, &mut offset, "owner x")?,
            decode_note_field(encoded, &mut offset, "owner y")?,
        ),
        shared_secret: decode_note_field(encoded, &mut offset, "shared secret")?,
        ephemeral_key: (
            decode_note_field(encoded, &mut offset, "ephemeral key x")?,
            decode_note_field(encoded, &mut offset, "ephemeral key y")?,
        ),
        view_tag: decode_note_field(encoded, &mut offset, "view tag")?,
    };
    let committed = match encoded[offset] {
        0 => false,
        1 => true,
        value => {
            return Err(CurvyStateError::Corrupt(format!(
                "invalid owned-note committed flag {value}"
            )));
        }
    };
    let mut leaf_index_bytes = [0_u8; 8];
    leaf_index_bytes.copy_from_slice(&encoded[offset + 1..offset + 9]);
    let raw_leaf_index = u64::from_be_bytes(leaf_index_bytes);
    let leaf_index = (raw_leaf_index != u64::MAX).then_some(raw_leaf_index);
    if committed != leaf_index.is_some() {
        return Err(CurvyStateError::Corrupt(
            "owned-note commitment flag and leaf index disagree".to_owned(),
        ));
    }

    Ok(StoredOwnedNote {
        detected: DetectedCurvyNote {
            deposit: OwnedCurvyDeposit { id, address, amount },
            note,
        },
        committed,
        leaf_index,
    })
}

fn note_id_key(note_id: &str) -> Result<[u8; NOTE_ID_SIZE], CurvyStateError> {
    parse_curvy_note_id(note_id)
        .map(|note_id| fr_to_be_32(&note_id.into_inner()))
        .map_err(|error| CurvyStateError::Corrupt(error.to_string()))
}

fn owned_note_key(id: &PixAddressId, note_id: &str) -> Result<[u8; OWNED_NOTE_KEY_SIZE], CurvyStateError> {
    let mut key = [0_u8; OWNED_NOTE_KEY_SIZE];
    key[..PixAddressId::SIZE].copy_from_slice(&id.to_bytes());
    key[PixAddressId::SIZE..].copy_from_slice(&note_id_key(note_id)?);
    Ok(key)
}

fn session_note_range(id: &PixAddressId) -> ([u8; OWNED_NOTE_KEY_SIZE], [u8; OWNED_NOTE_KEY_SIZE]) {
    let mut start = [0_u8; OWNED_NOTE_KEY_SIZE];
    let mut end = [u8::MAX; OWNED_NOTE_KEY_SIZE];
    let id = id.to_bytes();
    start[..PixAddressId::SIZE].copy_from_slice(&id);
    end[..PixAddressId::SIZE].copy_from_slice(&id);
    (start, end)
}

/// Storage used by [`CurvyDepositPool`] for crash-safe query resumption and note correlation.
pub trait CurvyDepositState: Send + Sync + 'static {
    fn cursor(&self, kind: CurvyEventKind) -> Result<Option<CurvyEventCursor>, CurvyStateError>;

    /// Records an owned candidate and advances the cursor atomically.
    fn record_owned_candidate(
        &self,
        note_id: &str,
        note: DetectedCurvyNote,
        cursor: &CurvyEventCursor,
    ) -> Result<(), CurvyStateError>;

    /// Marks a known note committed and advances the cursor atomically.
    fn record_completion(
        &self,
        note_id: &str,
        leaf_index: u64,
        cursor: &CurvyEventCursor,
    ) -> Result<Option<CommittedCurvyNote>, CurvyStateError>;

    /// Advances past an event which does not belong to this node.
    fn advance_cursor(&self, kind: CurvyEventKind, cursor: &CurvyEventCursor) -> Result<(), CurvyStateError>;

    /// Returns the total value of all committed notes owned by one PIX allocation.
    fn committed_amount(&self, id: &PixAddressId) -> Result<HoprBalance, CurvyStateError>;

    /// Loads complete committed notes for a reconstructed PIX allocation.
    fn committed_notes(&self, id: &PixAddressId) -> Result<Vec<CommittedCurvyNote>, CurvyStateError>;

    /// Removes notes after their nullifiers have been accepted by the SDK submission flow.
    fn remove_spent_notes(&self, id: &PixAddressId, note_ids: &[String]) -> Result<(), CurvyStateError>;
}

/// Redb-backed Curvy lifecycle state.
///
/// Owned notes remain stored after commitment. Reopening the same database and
/// reusing the same reconstructed BJJ session key therefore makes those notes
/// available to both [`DepositPool::notify_deposit`] and withdrawal after a node
/// restart.
pub struct RedbCurvyDepositState {
    db: Arc<redb::Database>,
}

impl RedbCurvyDepositState {
    /// Opens the durable note store beside the node's ticket Redb file.
    ///
    /// Keeping the path derivation here gives the composition layer a stable,
    /// restart-safe location without coupling Curvy tables to the ticket schema.
    pub fn open_next_to(ticket_database_path: impl AsRef<Path>) -> Result<Self, CurvyStateError> {
        Self::open(
            ticket_database_path
                .as_ref()
                .with_file_name(CURVY_NOTE_DATABASE_FILE_NAME),
        )
    }

    /// Opens the durable note store at a node-stable path.
    ///
    /// The composition layer must reuse this path across restarts; an ephemeral
    /// path would intentionally lose the connector's private note state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CurvyStateError> {
        let db = redb::Database::create(path).map_err(state_db_error)?;
        let write = db.begin_write().map_err(state_db_error)?;
        write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
        write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
        write.commit().map_err(state_db_error)?;
        Ok(Self { db: Arc::new(db) })
    }

    #[cfg(feature = "pix-curvy-sdk")]
    pub(crate) fn shared_database(&self) -> Arc<redb::Database> {
        Arc::clone(&self.db)
    }

    fn put_cursor(
        cursor_table: &mut redb::Table<'_, u8, Vec<u8>>,
        kind: CurvyEventKind,
        cursor: &CurvyEventCursor,
    ) -> Result<(), CurvyStateError> {
        cursor_table
            .insert(kind.cursor_key(), encode_cursor(cursor)?)
            .map_err(state_db_error)?;
        Ok(())
    }
}

impl CurvyDepositState for RedbCurvyDepositState {
    fn cursor(&self, kind: CurvyEventKind) -> Result<Option<CurvyEventCursor>, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(CURSOR_TABLE).map_err(state_db_error)?;
        table
            .get(kind.cursor_key())
            .map_err(state_db_error)?
            .map(|value| decode_cursor(&value.value()))
            .transpose()
    }

    fn record_owned_candidate(
        &self,
        note_id: &str,
        note: DetectedCurvyNote,
        cursor: &CurvyEventCursor,
    ) -> Result<(), CurvyStateError> {
        let id = note.deposit.id;
        let note_id_key = note_id_key(note_id)?;
        let owned_note_key = owned_note_key(&id, note_id)?;
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut notes = write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
            if notes.get(owned_note_key).map_err(state_db_error)?.is_none() {
                notes
                    .insert(
                        owned_note_key,
                        encode_owned_note(&StoredOwnedNote {
                            detected: note,
                            committed: false,
                            leaf_index: None,
                        }),
                    )
                    .map_err(state_db_error)?;
            }
            let mut sessions = write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
            sessions.insert(note_id_key, id.to_bytes()).map_err(state_db_error)?;
            let mut cursor_table = write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
            Self::put_cursor(&mut cursor_table, CurvyEventKind::Pending, cursor)?;
        }
        write.commit().map_err(state_db_error)
    }

    fn record_completion(
        &self,
        note_id: &str,
        leaf_index: u64,
        cursor: &CurvyEventCursor,
    ) -> Result<Option<CommittedCurvyNote>, CurvyStateError> {
        let note_id_key = note_id_key(note_id)?;
        let write = self.db.begin_write().map_err(state_db_error)?;
        let detected = {
            let sessions = write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
            let id = sessions
                .get(note_id_key)
                .map_err(state_db_error)?
                .map(|value| PixAddressId::try_from(value.value().as_slice()))
                .transpose()
                .map_err(|error| CurvyStateError::Corrupt(format!("invalid note session ID: {error}")))?;
            let mut notes = write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
            let key = id.as_ref().map(|id| owned_note_key(id, note_id)).transpose()?;
            let stored = if let Some(key) = key {
                notes
                    .get(key)
                    .map_err(state_db_error)?
                    .map(|value| decode_owned_note(&value.value()))
                    .transpose()?
            } else {
                None
            };

            let detected = stored.as_ref().map(|note| CommittedCurvyNote {
                deposit: note.detected.deposit,
                note: note.detected.note.clone(),
                leaf_index,
            });
            if let (Some(key), Some(note)) = (key, stored) {
                notes
                    .insert(
                        key,
                        encode_owned_note(&StoredOwnedNote {
                            committed: true,
                            leaf_index: Some(leaf_index),
                            ..note
                        }),
                    )
                    .map_err(state_db_error)?;
            }
            let mut cursor_table = write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
            Self::put_cursor(&mut cursor_table, CurvyEventKind::Committed, cursor)?;
            detected
        };
        write.commit().map_err(state_db_error)?;
        Ok(detected)
    }

    fn advance_cursor(&self, kind: CurvyEventKind, cursor: &CurvyEventCursor) -> Result<(), CurvyStateError> {
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut table = write.open_table(CURSOR_TABLE).map_err(state_db_error)?;
            Self::put_cursor(&mut table, kind, cursor)?;
        }
        write.commit().map_err(state_db_error)
    }

    fn committed_amount(&self, id: &PixAddressId) -> Result<HoprBalance, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        let mut total = HoprBalance::zero();
        let (start, end) = session_note_range(id);
        for entry in table.range(start..=end).map_err(state_db_error)? {
            let (_, value) = entry.map_err(state_db_error)?;
            let note = decode_owned_note(&value.value())?;
            if note.committed {
                total += note.detected.deposit.amount;
            }
        }
        Ok(total)
    }

    fn committed_notes(&self, id: &PixAddressId) -> Result<Vec<CommittedCurvyNote>, CurvyStateError> {
        let read = self.db.begin_read().map_err(state_db_error)?;
        let table = read.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
        let mut notes = Vec::new();
        let (start, end) = session_note_range(id);
        for entry in table.range(start..=end).map_err(state_db_error)? {
            let (_, value) = entry.map_err(state_db_error)?;
            let stored = decode_owned_note(&value.value())?;
            if let Some(leaf_index) = stored.leaf_index {
                notes.push(CommittedCurvyNote {
                    deposit: stored.detected.deposit,
                    note: stored.detected.note,
                    leaf_index,
                });
            }
        }
        Ok(notes)
    }

    fn remove_spent_notes(&self, id: &PixAddressId, note_ids: &[String]) -> Result<(), CurvyStateError> {
        let write = self.db.begin_write().map_err(state_db_error)?;
        {
            let mut notes = write.open_table(OWNED_NOTES_TABLE).map_err(state_db_error)?;
            let mut sessions = write.open_table(NOTE_SESSIONS_TABLE).map_err(state_db_error)?;
            for note_id in note_ids {
                notes.remove(owned_note_key(id, note_id)?).map_err(state_db_error)?;
                sessions.remove(note_id_key(note_id)?).map_err(state_db_error)?;
            }
        }
        write.commit().map_err(state_db_error)
    }
}

#[derive(Debug)]
struct DepositWaiter {
    minimum: HoprBalance,
    sender: futures::channel::oneshot::Sender<HoprBalance>,
}

#[derive(Debug)]
struct WatchedAllocation {
    address: BjjPublicKey,
    scan_key: CurvyScanSecret,
    waiters: Vec<DepositWaiter>,
}

#[derive(Debug, thiserror::Error)]
enum CurvyLifecycleError {
    #[error(transparent)]
    Detection(#[from] CurvyDetectionError),
    #[error(transparent)]
    State(#[from] CurvyStateError),
}

struct CurvyLifecycleTracker<S> {
    detector: Arc<RsCoreCurvyNoteDetector>,
    state: Arc<S>,
    waiters: parking_lot::Mutex<HashMap<PixAddressId, WatchedAllocation>>,
    replay_history: AtomicBool,
}

impl<S> CurvyLifecycleTracker<S>
where
    S: CurvyDepositState,
{
    fn new(detector: Arc<RsCoreCurvyNoteDetector>, state: Arc<S>) -> Self {
        Self {
            detector,
            state,
            waiters: Default::default(),
            replay_history: AtomicBool::new(false),
        }
    }

    fn watch(
        &self,
        id: PixAddressId,
        address: BjjPublicKey,
        scan_key: CurvyScanSecret,
        minimum: HoprBalance,
    ) -> Result<futures::channel::oneshot::Receiver<HoprBalance>, CurvyStateError> {
        let (sender, receiver) = futures::channel::oneshot::channel();
        // Serialize the persisted-state check with completion notifications. This
        // prevents a completion from landing between the check and waiter insert.
        let mut waiters = self.waiters.lock();
        let committed = self.state.committed_amount(&id)?;
        if committed >= minimum {
            let _ = sender.send(committed);
        } else {
            match waiters.entry(id) {
                Entry::Occupied(mut entry) => {
                    if entry.get().address != address {
                        return Err(CurvyStateError::Corrupt(
                            "PIX allocation ID was registered with two different addresses".to_owned(),
                        ));
                    }
                    if entry.get().scan_key.public() != scan_key.public() {
                        return Err(CurvyStateError::Corrupt(
                            "PIX allocation ID was registered with two different Curvy scan identities".to_owned(),
                        ));
                    }
                    entry.get_mut().waiters.push(DepositWaiter { minimum, sender });
                }
                Entry::Vacant(entry) => {
                    entry.insert(WatchedAllocation {
                        address,
                        scan_key,
                        waiters: vec![DepositWaiter { minimum, sender }],
                    });
                }
            }
            // A shared stream cursor may already have advanced past this address's
            // allocation. Force one historical pass with the complete current watch
            // set. An epoch-like boolean is sufficient: if registration races a pass,
            // the worker observes it on the next outer iteration.
            self.replay_history.store(true, Ordering::Release);
        }
        Ok(receiver)
    }

    fn watched_allocations(&self) -> Vec<(PixAddressId, BjjPublicKey, CurvyScanSecret)> {
        let mut waiters = self.waiters.lock();
        waiters.retain(|_, allocation| {
            allocation.waiters.retain(|waiter| !waiter.sender.is_canceled());
            !allocation.waiters.is_empty()
        });
        waiters
            .iter()
            .map(|(id, allocation)| (*id, allocation.address, allocation.scan_key.clone()))
            .collect()
    }

    /// Starts both event families from genesis when a newly registered
    /// allocation requests historical recovery. Replaying only pending events is
    /// insufficient: the committed cursor may already have advanced past the
    /// recovered note while another allocation was being watched.
    fn catch_up_cursor(
        &self,
        kind: CurvyEventKind,
        replay_history: bool,
    ) -> Result<Option<CurvyEventCursor>, CurvyStateError> {
        if replay_history {
            Ok(None)
        } else {
            self.state.cursor(kind)
        }
    }

    /// A historical replay is an at-least-once request. If any indexer or state
    /// operation interrupts the pass, retain the request so the next worker
    /// iteration starts both event families from genesis again.
    fn restore_failed_replay(&self, replay_history: bool) {
        if replay_history {
            self.replay_history.store(true, Ordering::Release);
        }
    }

    fn notify_waiters(&self, id: PixAddressId, committed: HoprBalance) {
        let mut waiters = self.waiters.lock();
        let mut remove_allocation = false;
        if let Some(allocation) = waiters.get_mut(&id) {
            let mut pending = Vec::with_capacity(allocation.waiters.len());
            for waiter in allocation.waiters.drain(..) {
                if committed >= waiter.minimum {
                    let _ = waiter.sender.send(committed);
                } else if !waiter.sender.is_canceled() {
                    pending.push(waiter);
                }
            }
            allocation.waiters = pending;
            remove_allocation = allocation.waiters.is_empty();
        }
        if remove_allocation {
            waiters.remove(&id);
        }
    }

    /// Returns `false` when processing must pause because no deposit address is
    /// currently registered. In that case the cursor is intentionally left
    /// untouched so the event is replayed after a waiter is added.
    async fn process_candidate(&self, candidate: CurvyPendingNote) -> Result<bool, CurvyLifecycleError> {
        let watched = self.watched_allocations();
        if watched.is_empty() {
            return Ok(false);
        }

        let cursor = CurvyEventCursor::from(&candidate.position);

        let detected = match self.detector.detect_owned_note(&candidate, &watched) {
            Ok(detected) => detected,
            Err(CurvyDetectionError::InvalidCandidate(error)) => {
                tracing::error!(
                    note_id = %candidate.note_id.0,
                    %error,
                    "quarantining malformed public Curvy pending-note event"
                );
                self.state.advance_cursor(CurvyEventKind::Pending, &cursor)?;
                return Ok(true);
            }
        };

        match detected {
            Some(note) => {
                let allocation = note.deposit.id;
                self.state
                    .record_owned_candidate(&candidate.note_id.0, note, &cursor)
                    .map_err(CurvyLifecycleError::from)?;
                tracing::info!(
                    note_id = %candidate.note_id.0,
                    allocation = ?allocation,
                    "discovered Curvy PIX pending note through Blokli"
                );
            }
            None => self.state.advance_cursor(CurvyEventKind::Pending, &cursor)?,
        };
        Ok(true)
    }

    async fn process_completion(&self, completion: CurvyCommittedNote) -> Result<(), CurvyLifecycleError> {
        let cursor = CurvyEventCursor::from(&completion.position);
        let leaf_index = match completion.leaf_index.0.parse() {
            Ok(leaf_index) => leaf_index,
            Err(error) => {
                tracing::error!(
                    note_id = %completion.note_id.0,
                    %error,
                    "quarantining malformed public Curvy committed-note leaf index"
                );
                self.state.advance_cursor(CurvyEventKind::Committed, &cursor)?;
                return Ok(());
            }
        };
        if let Err(error) = note_id_key(&completion.note_id.0) {
            tracing::error!(
                note_id = %completion.note_id.0,
                %error,
                "quarantining malformed public Curvy committed-note ID"
            );
            self.state.advance_cursor(CurvyEventKind::Committed, &cursor)?;
            return Ok(());
        }
        if let Some(note) = self
            .state
            .record_completion(&completion.note_id.0, leaf_index, &cursor)?
        {
            tracing::info!(
                note_id = %completion.note_id.0,
                allocation = ?note.deposit.id,
                leaf_index,
                "correlated committed Curvy PIX note through Blokli"
            );
            let committed = self.state.committed_amount(&note.deposit.id)?;
            self.notify_waiters(note.deposit.id, committed);
        }
        Ok(())
    }
}

/// Errors returned by the Curvy-backed PIX deposit pool.
#[derive(Debug, thiserror::Error)]
pub enum CurvyDepositPoolError<E: std::error::Error + 'static> {
    #[error("Curvy SDK operation failed: {0}")]
    Adapter(#[source] E),
    #[error(transparent)]
    State(#[from] CurvyStateError),
    #[error("invalid reconstructed BabyJubJub PIX withdrawal key: {0}")]
    InvalidReconstructedSecret(String),
    #[error("Curvy allocation is missing its per-SSA public scan identity")]
    MissingScanIdentity,
    #[error("invalid Curvy scan identity data: {0}")]
    InvalidScanIdentity(String),
    #[error("Curvy SDK returned {actual} withdrawal results for {expected} inputs")]
    InvalidBatchResult { expected: usize, actual: usize },
    #[error("Curvy deposit watcher stopped before the deposit was committed")]
    WatcherStopped,
    #[error("Curvy indexer query failed: {0}")]
    Indexer(String),
    #[error("timed out waiting for a Curvy deposit to be committed")]
    DepositTimeout,
    #[error(
        "Curvy pool-to-pool transfer is not supported; PIX settlement withdraws reconstructed deposits to the Safe"
    )]
    UnsupportedPoolTransfer,
}

/// Runtime behavior owned by the Curvy deposit pool.
#[derive(Clone, Copy, Debug)]
pub struct CurvyDepositPoolConfig {
    /// Maximum time returned deposit notifications may remain pending.
    pub max_deposit_tracking_time: Duration,
}

impl Default for CurvyDepositPoolConfig {
    fn default() -> Self {
        Self {
            max_deposit_tracking_time: DEFAULT_MAX_DEPOSIT_TRACKING_TIME,
        }
    }
}

/// Anonymous Curvy implementation of the PIX [`DepositPool`].
pub struct CurvyDepositPool<C, A, S> {
    client: Arc<C>,
    adapter: Arc<A>,
    tracker: Arc<CurvyLifecycleTracker<S>>,
    config: CurvyDepositPoolConfig,
    watcher: parking_lot::Mutex<Option<hopr_utils::runtime::AbortHandle>>,
}

impl<C, A, S> CurvyDepositPool<C, A, S>
where
    C: BlokliQueryClient + Send + Sync + 'static,
    A: CurvySdkAdapter,
    S: CurvyDepositState,
{
    pub fn new(client: Arc<C>, adapter: A, detector: RsCoreCurvyNoteDetector, state: S) -> Self {
        Self::new_with_config(client, adapter, detector, state, CurvyDepositPoolConfig::default())
    }

    pub fn new_with_config(
        client: Arc<C>,
        adapter: A,
        detector: RsCoreCurvyNoteDetector,
        state: S,
        config: CurvyDepositPoolConfig,
    ) -> Self {
        let adapter = Arc::new(adapter);
        Self {
            client,
            tracker: Arc::new(CurvyLifecycleTracker::new(Arc::new(detector), Arc::new(state))),
            adapter,
            config,
            watcher: Default::default(),
        }
    }

    fn bjj_secret(key: &BjjKeypair) -> Result<ScalarSigningKey, CurvyDepositPoolError<A::Error>> {
        let mut bytes: [u8; 32] = key.secret().as_ref().try_into().map_err(|_| {
            CurvyDepositPoolError::InvalidReconstructedSecret("secret must contain 32 bytes".to_owned())
        })?;
        // HOPR deposit secrets are big-endian; Curvy's signing-key boundary is little-endian.
        bytes.reverse();
        ScalarSigningKey::from_le_bytes(bytes)
            .map_err(|error| CurvyDepositPoolError::InvalidReconstructedSecret(error.to_string()))
    }

    async fn reconcile_spent_notes(
        &self,
        id: &PixAddressId,
        notes: Vec<CommittedCurvyNote>,
    ) -> Result<Vec<CommittedCurvyNote>, CurvyDepositPoolError<A::Error>> {
        let mut spent_ids = Vec::new();
        let mut unspent = Vec::with_capacity(notes.len());
        for note in notes {
            let nullifier = U256::from_be_bytes(fr_to_be_32(&note.note.nullifier()));
            if self
                .client
                .query_curvy_nullifier_spent(format!("{nullifier:#066x}"))
                .await
                .map_err(|error| CurvyDepositPoolError::Indexer(error.to_string()))?
            {
                let note_id = U256::from_be_bytes(fr_to_be_32(&note.note.id()));
                spent_ids.push(format!("{note_id:#066x}"));
            } else {
                unspent.push(note);
            }
        }
        if !spent_ids.is_empty() {
            self.remove_spent_notes_retry(id, &spent_ids)?;
        }
        Ok(unspent)
    }

    fn remove_spent_notes_retry(
        &self,
        id: &PixAddressId,
        note_ids: &[String],
    ) -> Result<(), CurvyDepositPoolError<A::Error>> {
        let mut last_error = None;
        for _ in 0..3 {
            match self.tracker.state.remove_spent_notes(id, note_ids) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("at least one cleanup attempt was made").into())
    }

    fn ensure_watcher(&self) {
        let mut watcher = self.watcher.lock();
        if watcher.as_ref().is_some_and(|handle| !handle.is_aborted()) {
            return;
        }

        let client = self.client.clone();
        let tracker = self.tracker.clone();
        let (abort_handle, abort_registration) = hopr_utils::runtime::AbortHandle::new_pair();
        hopr_utils::runtime::prelude::spawn(async move {
            let worker = async move {
                loop {
                    if tracker.watched_allocations().is_empty() {
                        hopr_utils::runtime::prelude::sleep(RECONNECT_DELAY).await;
                        continue;
                    }

                    // Catch pending notes up first. A committed note can then only
                    // correlate with an ownership decision that is already durable.
                    let replay_history = tracker.replay_history.swap(false, Ordering::AcqRel);
                    let catch_up = async {
                        let mut pending_after = tracker
                            .catch_up_cursor(CurvyEventKind::Pending, replay_history)
                            .map_err(|error| error.to_string())?;
                        loop {
                            let page = client
                                .query_curvy_pending_notes(None, pending_after.clone(), QUERY_PAGE_SIZE)
                                .await
                                .map_err(|error| error.to_string())?;
                            let page_len = page.notes.len();
                            for note in page.notes {
                                pending_after = Some(CurvyEventCursor::from(&note.position));
                                if !tracker
                                    .process_candidate(note)
                                    .await
                                    .map_err(|error| error.to_string())?
                                {
                                    return Ok::<(), String>(());
                                }
                            }
                            if page_len < QUERY_PAGE_SIZE as usize {
                                break;
                            }
                        }

                        let chain_info = client.query_chain_info().await.map_err(|error| error.to_string())?;
                        let indexed_block = u64::try_from(chain_info.block_number)
                            .map_err(|_| "Blokli returned a negative indexed block number".to_owned())?;
                        let finality =
                            cursor_component(&chain_info.finality, "finality").map_err(|error| error.to_string())?;
                        let finalized_through = indexed_block.saturating_sub(finality);
                        let mut committed_after = tracker
                            .catch_up_cursor(CurvyEventKind::Committed, replay_history)
                            .map_err(|error| error.to_string())?;
                        loop {
                            let page = client
                                .query_curvy_committed_notes(None, committed_after.clone(), QUERY_PAGE_SIZE)
                                .await
                                .map_err(|error| error.to_string())?;
                            let page_len = page.notes.len();
                            let mut reached_unfinalized = false;
                            for note in page.notes {
                                let event_block = cursor_component(&note.position.block, "completion block")
                                    .map_err(|error| error.to_string())?;
                                if event_block > finalized_through {
                                    reached_unfinalized = true;
                                    break;
                                }
                                let cursor = CurvyEventCursor::from(&note.position);
                                tracker
                                    .process_completion(note)
                                    .await
                                    .map_err(|error| error.to_string())?;
                                committed_after = Some(cursor);
                            }
                            if reached_unfinalized || page_len < QUERY_PAGE_SIZE as usize {
                                break;
                            }
                        }
                        Ok::<(), String>(())
                    }
                    .await;
                    if let Err(error) = catch_up {
                        tracker.restore_failed_replay(replay_history);
                        tracing::warn!(
                            %error,
                            replay_history,
                            "failed to catch up Curvy PIX notes; retrying without losing historical replay"
                        );
                    }
                    hopr_utils::runtime::prelude::sleep(RECONNECT_DELAY).await;
                }
            };
            let _ = futures::stream::Abortable::new(worker, abort_registration).await;
        });
        *watcher = Some(abort_handle);
    }
}

impl<C, A, S> Drop for CurvyDepositPool<C, A, S> {
    fn drop(&mut self) {
        if let Some(handle) = self.watcher.lock().take() {
            handle.abort();
        }
    }
}

#[async_trait::async_trait]
impl<C, A, S> DepositPool<BjjKeypair> for CurvyDepositPool<C, A, S>
where
    C: BlokliQueryClient + Send + Sync + 'static,
    A: CurvySdkAdapter,
    S: CurvyDepositState,
{
    type Error = CurvyDepositPoolError<A::Error>;
    type Receipt = A::Receipt;

    async fn deposit_funds_to(
        &self,
        id: PixAddressId,
        dst: BjjPublicKey,
        additional_data: Option<AdditionalDepositData>,
        amount: HoprBalance,
    ) -> Result<Self::Receipt, Self::Error> {
        let scan_key = additional_data
            .ok_or(CurvyDepositPoolError::MissingScanIdentity)
            .and_then(|bytes| {
                CurvyScanPublicKey::try_from(bytes.as_ref())
                    .map_err(|error| CurvyDepositPoolError::InvalidScanIdentity(error.to_string()))
            })?;
        self.adapter
            .deposit(id, dst, scan_key, amount)
            .await
            .map_err(CurvyDepositPoolError::Adapter)
    }

    async fn deposit_funds_to_multiple(
        &self,
        deposits: Vec<(PixAddressId, BjjPublicKey, Option<AdditionalDepositData>, HoprBalance)>,
    ) -> Result<Vec<Self::Receipt>, Self::Error> {
        let deposits = deposits
            .into_iter()
            .map(|(id, dst, additional_data, amount)| {
                additional_data
                    .ok_or(CurvyDepositPoolError::MissingScanIdentity)
                    .and_then(|bytes| {
                        CurvyScanPublicKey::try_from(bytes.as_ref())
                            .map_err(|error| CurvyDepositPoolError::InvalidScanIdentity(error.to_string()))
                    })
                    .map(|scan_key| (id, dst, scan_key, amount))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.adapter
            .deposit_multiple(deposits)
            .await
            .map_err(CurvyDepositPoolError::Adapter)
    }

    fn notify_deposit(
        &self,
        id: PixAddressId,
        dst: BjjPublicKey,
        additional_data: Option<AdditionalDepositData>,
        min_amount: HoprBalance,
    ) -> Result<DepositNotification<'static, BjjPublicKey, Self::Error>, Self::Error> {
        let scan_secret = additional_data
            .ok_or(CurvyDepositPoolError::MissingScanIdentity)
            .and_then(|bytes| {
                CurvyScanSecret::try_from(bytes.as_ref())
                    .map_err(|error| CurvyDepositPoolError::InvalidScanIdentity(error.to_string()))
            })?;
        let receiver = self.tracker.watch(id, dst, scan_secret, min_amount)?;
        let timeout = self.config.max_deposit_tracking_time;
        self.ensure_watcher();
        Ok(Box::pin(async move {
            let timer = hopr_utils::runtime::prelude::sleep(timeout);
            futures::pin_mut!(timer);
            futures::pin_mut!(receiver);
            match futures::future::select(receiver, timer).await {
                futures::future::Either::Left((Ok(amount), _)) => Ok((id, dst, amount)),
                futures::future::Either::Left((Err(_), _)) => Err(CurvyDepositPoolError::WatcherStopped),
                futures::future::Either::Right(_) => Err(CurvyDepositPoolError::DepositTimeout),
            }
        }))
    }

    async fn withdraw_deposit(
        &self,
        id: PixAddressId,
        key: &BjjKeypair,
        dst: Address,
        amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        let secret = Self::bjj_secret(key)?;
        let notes = self
            .reconcile_spent_notes(&id, self.tracker.state.committed_notes(&id)?)
            .await?;
        if notes.is_empty() {
            return Ok(A::Receipt::default());
        }
        let outcome = self
            .adapter
            .withdraw(&secret, notes, dst, amount)
            .await
            .map_err(CurvyDepositPoolError::Adapter)?;
        self.remove_spent_notes_retry(&id, &outcome.spent_note_ids)?;
        Ok(outcome.receipt)
    }

    async fn withdraw_multiple_deposits(
        &self,
        deposits: &[(PixAddressId, BjjKeypair)],
        dst: Address,
    ) -> Result<Vec<Result<(Address, Self::Receipt), Self::Error>>, Self::Error> {
        let mut active = Vec::new();
        let mut withdrawals = Vec::new();
        let mut logical_results: Vec<Option<Result<(Address, A::Receipt), CurvyDepositPoolError<A::Error>>>> =
            (0..deposits.len()).map(|_| None).collect();
        for (index, (id, key)) in deposits.iter().enumerate() {
            let notes = self
                .reconcile_spent_notes(id, self.tracker.state.committed_notes(id)?)
                .await?;
            if notes.is_empty() {
                logical_results[index] = Some(Ok((dst, A::Receipt::default())));
            } else {
                active.push((index, *id));
                withdrawals.push(CurvyWithdrawal {
                    secret: Self::bjj_secret(key)?,
                    notes,
                });
            }
        }
        let results = self
            .adapter
            .withdraw_multiple(withdrawals, dst)
            .await
            .map_err(CurvyDepositPoolError::Adapter)?;
        if results.len() != active.len() {
            return Err(CurvyDepositPoolError::InvalidBatchResult {
                expected: active.len(),
                actual: results.len(),
            });
        }
        for (result, (index, id)) in results.into_iter().zip(active) {
            logical_results[index] = Some(match result {
                Ok((address, outcome)) => {
                    self.remove_spent_notes_retry(&id, &outcome.spent_note_ids)?;
                    Ok((address, outcome.receipt))
                }
                Err(error) => Err(CurvyDepositPoolError::Adapter(error)),
            });
        }
        Ok(logical_results
            .into_iter()
            .map(|result| result.expect("every batch result slot is filled"))
            .collect())
    }

    async fn pool_transfer(
        &self,
        _source_id: PixAddressId,
        _key: &BjjKeypair,
        _destination_id: PixAddressId,
        _dst: BjjPublicKey,
        _destination_data: Option<AdditionalDepositData>,
        _amount: Option<HoprBalance>,
    ) -> Result<Self::Receipt, Self::Error> {
        Err(CurvyDepositPoolError::UnsupportedPoolTransfer)
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, sync::Arc};

    use blokli_client::api::types::{CurvyEventPosition, Uint256};
    use hopr_api::types::{
        crypto::prelude::{BjjKeypair, CurvyScanPublicKey, CurvyScanSecret, Keypair, SecretKey},
        crypto_random::Randomizable,
        internal::prelude::HoprPseudonym,
    };

    use super::*;

    struct OwnedCandidateFixture {
        id: PixAddressId,
        address: BjjPublicKey,
        detector: RsCoreCurvyNoteDetector,
        scan_key: CurvyScanSecret,
        note: CurvyPendingNote,
        note_id: String,
    }

    fn pix_id(index: u32) -> PixAddressId {
        PixAddressId::new(
            HoprPseudonym::random(),
            NonZeroU32::new(index).expect("non-zero PIX allocation index"),
        )
    }

    fn position(block: u64) -> CurvyEventPosition {
        CurvyEventPosition {
            transaction_hash: Hex32(format!("0x{:064x}", block + 1)),
            block_hash: Hex32(format!("0x{:064x}", block + 2)),
            block: Uint64(block.to_string()),
            transaction_index: Uint64("0".to_owned()),
            log_index: Uint64("0".to_owned()),
            event_item_index: Uint64("0".to_owned()),
        }
    }

    fn scan_secret(spend_private_key: &str, view_private_key: &str) -> anyhow::Result<CurvyScanSecret> {
        let (spend_meta_key, view_public_key) = stealth::get_meta(spend_private_key, view_private_key)?;
        let point_bytes = |point: &str| -> anyhow::Result<([u8; 32], [u8; 32])> {
            let (x, y) = point
                .split_once('.')
                .ok_or_else(|| anyhow::anyhow!("malformed Curvy point"))?;
            Ok((
                U256::from_str_radix(x, 10)?.to_be_bytes(),
                U256::from_str_radix(y, 10)?.to_be_bytes(),
            ))
        };
        let (kx, ky) = point_bytes(&spend_meta_key)?;
        let (vx, vy) = point_bytes(&view_public_key)?;
        let public = CurvyScanPublicKey::from_affine_coordinates((&kx, &ky), (&vx, &vy))?;
        let view_secret = U256::from_str_radix(view_private_key, 16)?.to_be_bytes();
        Ok(CurvyScanSecret::new(SecretKey::from(view_secret), public))
    }

    fn owned_candidate(block: u64) -> anyhow::Result<OwnedCandidateFixture> {
        let id = pix_id(1);
        let mut secret = [0_u8; 32];
        secret[31] = 1;
        let keypair = BjjKeypair::from_secret(&secret)?;
        let address = *keypair.public();
        let scan_key = scan_secret("01", "02")?;
        let owner = bjj_point(&address).map_err(anyhow::Error::msg)?;
        let (big_k, big_v) = stealth::get_meta("01", "02")?;
        let announcement = stealth::send_with_r("3", &big_k, &big_v)?;
        let (ephemeral_x, ephemeral_y) = announcement
            .big_r
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("malformed Curvy fixture announcement"))?;
        let ephemeral_x_field = Bn254Fr::try_from_dec(ephemeral_x)?;
        let ephemeral_y_field = Bn254Fr::try_from_dec(ephemeral_y)?;
        let shared_secret =
            shared_secret_from_scan_match(&announcement.spending_pub_key).map_err(anyhow::Error::new)?;
        let amount = Bn254Fr::try_from_dec("10")?;
        let token = Bn254Fr::try_from_dec("4")?;
        let view_tag_value = u16::from_str_radix(&announcement.view_tag, 16)?;
        let view_tag = Bn254Fr::from_fr(curvy_core::Fr::from(u64::from(view_tag_value)));
        let owned_note = KnownOwner::new(owner, shared_secret).note(
            amount.into_inner(),
            token.into_inner(),
            (ephemeral_x_field.into_inner(), ephemeral_y_field.into_inner()),
            view_tag.into_inner(),
        );
        let note_id = format!(
            "0x{:064x}",
            U256::from_be_bytes(curvy_core::field::fr_to_be_32(&owned_note.id()))
        );
        let encrypted = curvy_core::cipher::encrypt_amount_token(
            amount.into_inner(),
            token.into_inner(),
            &fr_to_biguint(&shared_secret.into_inner()),
            (
                &fr_to_biguint(&ephemeral_x_field.into_inner()),
                &fr_to_biguint(&ephemeral_y_field.into_inner()),
            ),
        );

        let detector = RsCoreCurvyNoteDetector::new(token);
        let note = CurvyPendingNote {
            note_id: Hex32(note_id.clone()),
            ephemeral_key: vec![Uint256(ephemeral_x.to_owned()), Uint256(ephemeral_y.to_owned())],
            view_tag: i32::from(view_tag_value),
            token_id: Uint256(curvy_core::field::fr_to_dec(&encrypted.encrypted_token)),
            amount: Uint256(curvy_core::field::fr_to_dec(&encrypted.encrypted_amount)),
            is_plaintext: false,
            position: position(block),
        };

        Ok(OwnedCandidateFixture {
            id,
            address,
            detector,
            scan_key,
            note,
            note_id,
        })
    }

    fn completion(note_id: &str, block: u64) -> CurvyCommittedNote {
        CurvyCommittedNote {
            note_id: Hex32(note_id.to_owned()),
            batch_index: Hex32(format!("0x{:064x}", 1)),
            leaf_index: Uint64("7".to_owned()),
            position: position(block),
        }
    }

    #[test]
    fn per_ssa_viewer_discovers_note_without_the_bjj_secret() -> anyhow::Result<()> {
        let fixture = owned_candidate(1)?;
        let detected = fixture
            .detector
            .detect_owned_note(
                &fixture.note,
                &[(fixture.id, fixture.address, fixture.scan_key.clone())],
            )?
            .ok_or_else(|| anyhow::anyhow!("viewer-owned allocation was not detected"))?;

        assert_eq!(detected.deposit.id, fixture.id);
        assert_eq!(detected.deposit.address, fixture.address);
        assert_eq!(detected.deposit.amount, HoprBalance::from(U256::from(10_u8)));
        let unrelated_scan_key = scan_secret("03", "04")?;
        assert!(
            fixture
                .detector
                .detect_owned_note(&fixture.note, &[(pix_id(2), fixture.address, unrelated_scan_key)],)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn redb_state_recovers_complete_notes_for_withdrawal_after_restart() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("curvy-pix.redb");
        let fixture = owned_candidate(1)?;
        let id = fixture.id;
        let address = fixture.address;
        let detected = fixture
            .detector
            .detect_owned_note(&fixture.note, &[(id, address, fixture.scan_key.clone())])?
            .ok_or_else(|| anyhow::anyhow!("fixture note was not detected"))?;
        let amount = detected.deposit.amount;
        let expected_note_id = detected.note.id();
        let candidate_cursor = CurvyEventCursor::from(&position(1));
        let completion_cursor = CurvyEventCursor::from(&position(2));

        {
            let state = RedbCurvyDepositState::open(&path)?;
            state.record_owned_candidate(&fixture.note_id, detected, &candidate_cursor)?;
            assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(candidate_cursor));
            assert_eq!(state.committed_amount(&id)?, HoprBalance::zero());

            assert_eq!(
                state
                    .record_completion(&fixture.note_id, 7, &completion_cursor)?
                    .map(|note| (note.deposit, note.leaf_index)),
                Some((OwnedCurvyDeposit { id, address, amount }, 7))
            );
            assert_eq!(state.committed_amount(&id)?, amount);
        }

        let reopened = RedbCurvyDepositState::open(&path)?;
        assert_eq!(reopened.cursor(CurvyEventKind::Committed)?, Some(completion_cursor));
        assert_eq!(reopened.committed_amount(&id)?, amount);
        let notes = reopened.committed_notes(&id)?;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note.id(), expected_note_id);
        assert_eq!(notes[0].leaf_index, 7);
        reopened.remove_spent_notes(&id, &[fixture.note_id])?;
        drop(reopened);

        let spent_reopened = RedbCurvyDepositState::open(&path)?;
        assert_eq!(spent_reopened.committed_amount(&id)?, HoprBalance::zero());
        assert!(spent_reopened.committed_notes(&id)?.is_empty());
        Ok(())
    }

    #[test]
    fn redb_state_opens_next_to_the_ticket_database() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let ticket_database = dir.path().join("tickets.redb");

        let _state = RedbCurvyDepositState::open_next_to(ticket_database)?;

        assert!(dir.path().join(CURVY_NOTE_DATABASE_FILE_NAME).is_file());
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn tracker_filters_correlates_and_notifies_locally() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
        let fixture = owned_candidate(2)?;
        let id = fixture.id;
        let address = fixture.address;
        let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());
        let receiver = tracker.watch(
            id,
            address,
            fixture.scan_key.clone(),
            HoprBalance::from(U256::from(10u8)),
        )?;

        let unrelated_cursor = CurvyEventCursor::from(&position(1));
        let mut unrelated = fixture.note.clone();
        unrelated.note_id = Hex32(format!("0x{:064x}", 0));
        unrelated.position = position(1);
        assert!(tracker.process_candidate(unrelated).await?);
        assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(unrelated_cursor));

        let candidate_cursor = CurvyEventCursor::from(&position(2));
        assert!(tracker.process_candidate(fixture.note).await?);
        assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(candidate_cursor));
        assert_eq!(state.committed_amount(&id)?, HoprBalance::zero());

        let completion_cursor = CurvyEventCursor::from(&position(3));
        tracker.process_completion(completion(&fixture.note_id, 3)).await?;
        assert_eq!(receiver.await?, HoprBalance::from(U256::from(10u8)));
        assert_eq!(state.cursor(CurvyEventKind::Committed)?, Some(completion_cursor));
        assert_eq!(state.committed_amount(&id)?, HoprBalance::from(U256::from(10u8)));
        Ok(())
    }

    #[tokio::test]
    async fn tracker_does_not_advance_without_registered_addresses() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
        let fixture = owned_candidate(1)?;
        let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());

        assert!(!tracker.process_candidate(fixture.note).await?);
        assert_eq!(state.cursor(CurvyEventKind::Pending)?, None);
        Ok(())
    }

    #[tokio::test]
    async fn tracker_quarantines_malformed_public_candidates() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
        let mut fixture = owned_candidate(4)?;
        let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());
        let _receiver = tracker.watch(
            fixture.id,
            fixture.address,
            fixture.scan_key.clone(),
            HoprBalance::from(U256::from(10u8)),
        )?;
        fixture.note.view_tag = 256;
        let cursor = CurvyEventCursor::from(&fixture.note.position);

        assert!(tracker.process_candidate(fixture.note).await?);
        assert_eq!(state.cursor(CurvyEventKind::Pending)?, Some(cursor));
        Ok(())
    }

    #[test]
    fn registering_an_address_requests_a_historical_lifecycle_pass() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
        let fixture = owned_candidate(1)?;
        let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state);

        let _receiver = tracker.watch(
            fixture.id,
            fixture.address,
            fixture.scan_key.clone(),
            HoprBalance::from(U256::from(10u8)),
        )?;

        assert!(tracker.replay_history.load(Ordering::Acquire));
        Ok(())
    }

    #[test]
    fn interrupted_historical_pass_remains_requested() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
        let fixture = owned_candidate(1)?;
        let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state);

        let _receiver = tracker.watch(
            fixture.id,
            fixture.address,
            fixture.scan_key.clone(),
            HoprBalance::from(U256::from(10_u8)),
        )?;
        let replay_history = tracker.replay_history.swap(false, Ordering::AcqRel);
        assert!(replay_history);
        assert!(!tracker.replay_history.load(Ordering::Acquire));

        tracker.restore_failed_replay(replay_history);
        assert!(tracker.replay_history.load(Ordering::Acquire));

        // A non-historical failure must not clear a newer registration's request.
        tracker.restore_failed_replay(false);
        assert!(tracker.replay_history.load(Ordering::Acquire));
        Ok(())
    }

    #[test_log::test(tokio::test)]
    async fn late_registration_replays_pending_and_committed_history() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let state = Arc::new(RedbCurvyDepositState::open(dir.path().join("curvy-pix.redb"))?);
        let fixture = owned_candidate(2)?;
        let id = fixture.id;
        let address = fixture.address;
        let tracker = CurvyLifecycleTracker::new(Arc::new(fixture.detector), state.clone());

        // A completion can be skipped while a different allocation is active,
        // advancing the shared committed cursor before this allocation is known.
        tracker.process_completion(completion(&fixture.note_id, 3)).await?;
        assert_eq!(
            state.cursor(CurvyEventKind::Committed)?,
            Some(CurvyEventCursor::from(&position(3)))
        );
        assert_eq!(state.committed_amount(&id)?, HoprBalance::zero());

        let receiver = tracker.watch(
            id,
            address,
            fixture.scan_key.clone(),
            HoprBalance::from(U256::from(10_u8)),
        )?;
        let replay_history = tracker.replay_history.swap(false, Ordering::AcqRel);
        assert!(replay_history);
        assert_eq!(tracker.catch_up_cursor(CurvyEventKind::Pending, replay_history)?, None);
        assert_eq!(
            tracker.catch_up_cursor(CurvyEventKind::Committed, replay_history)?,
            None
        );

        // The worker performs these in this order during the historical pass.
        assert!(tracker.process_candidate(fixture.note).await?);
        tracker.process_completion(completion(&fixture.note_id, 3)).await?;

        assert_eq!(receiver.await?, HoprBalance::from(U256::from(10_u8)));
        assert_eq!(state.committed_amount(&id)?, HoprBalance::from(U256::from(10_u8)));
        Ok(())
    }

    #[test]
    fn hopr_and_rs_core_use_the_same_babyjubjub_scalar_profile() -> anyhow::Result<()> {
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        let hopr = BjjKeypair::from_secret(&scalar)?;
        let hopr_point = bjj_point(hopr.public()).map_err(anyhow::Error::msg)?;
        scalar.reverse();
        let curvy = ScalarSigningKey::from_le_bytes(scalar)?;

        assert_eq!(hopr_point.as_tuple(), curvy.verifying_key().as_tuple());
        Ok(())
    }
}
