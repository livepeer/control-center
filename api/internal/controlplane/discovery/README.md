# Discovery package

This package owns the Node Collector, source reconciliation, scoped transport
credentials, cached publication and diagnostics. It imports Node's public
`discovery/shared` and `destination` packages. The parent control plane owns
configuration, admin authorization, HTTP routes, workers and the tunnel ledger
and encrypted credential adapters; this package does not provision tunnels.

Configure the manager before `Run` and reconcile authoritative snapshots through
the existing configuration worker. `ServeHTTP` reads cached inventory and
`Status` reports collection state. Cancel and join `Run` on shutdown; `Close`
also cancels and joins pending collection after startup failure. Production
leaves `Dependencies.Transport` unset for Node's destination policy and verified
TLS; tests can supply an in-process transport.

See the [operator guide](../../../../docs/fleet-discovery.md) for configuration,
credential handling and release checks.
