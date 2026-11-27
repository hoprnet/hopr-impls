# hopr-ticket-manager

Manages outgoing ticket indices and incoming redeemable tickets

Part of the [HOPR](https://hoprnet.org/) protocol implementation.

## Features

| Feature   | Default | Provides                                                                 |
| --------- | ------- | ------------------------------------------------------------------------ |
| `manager` | yes     | `HoprTicketManager`, incoming ticket queues, `ticket_manager_from_chain` |
| `redb`    | yes     | `RedbStore`, durable outgoing indices (and ticket queues with `manager`) |
| `cli`     | yes     | `ticket-inspector` binary (implies `manager`, needs `redb`)              |
| `serde`   | no      | serde support                                                            |

Entry nodes only issue tickets. Build with `default-features = false, features = ["redb"]` to get the `HoprTicketFactory`,
`ticket_factory_from_chain` and the outgoing index stores without the manager side.

## License

GPL-3.0-only
