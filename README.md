# Livepeer Control Center

Control Center manages onboarding and configuration for Livepeer orchestrators.

## Connect a node

Sign in to Control Center and copy your enrollment command. Prepare the
[prerequisite packages](runtime/README.md#prerequisites) on a Debian or Ubuntu
amd64 systemd host with 2 CPUs, 4 GiB RAM, and 10 GiB free. Run as root:

```sh
# Disable shell tracing before entering the token.
set +x
curl -fsSL https://controlcenter.livepeer.live/bootstrap.sh | LIVEPEER_ENROLLMENT_TOKEN='<TOKEN>' sh -
```

The loader downloads and verifies a complete release bundle. See the [Runtime guide](runtime/README.md) for more details.

## Architecture

Clients discover available apps through Control Center, pay through a
clearinghouse, and send application traffic to orchestrators.

```mermaid
flowchart LR
    client["Client / SDK"]
    cc["Control Center"]
    orch["Orchestrators"]
    signer["Remote signer"]
    ch["Clearinghouse"]

    client -->|Fleet discovery| cc
    client <-->|Sessions and application traffic| orch
    cc -->|Configuration and app assignments| orch
    orch -->|Status and discovery inventory| cc
    client <-->|Discovery and signed payments| signer
    signer -->|Fleet discovery| cc
    signer <-->|Payment authorization and usage accounting| ch
```

### Control Center and Runtime

Each managed host runs Runtime on K3s. Its management agent polls Control Center
for desired configuration and reports applied state. Flux deploys workloads; the
App Reconciler manages app instances and their registration with Livepeer Node,
which owns sessions, capacity, and private proxying to app Pods. The bundled
Runtime starts Node in offchain mode.

```mermaid
flowchart TB
    subgraph control["Control Center"]
        ui["Web UI"]
        api["Go API<br/>App catalog, assignments and configuration"]
        db[(PostgreSQL)]
        discovery["Fleet discovery collector"]
        ui --> api
        api <--> db
        api --> discovery
    end

    subgraph host["Orchestrator host / Runtime (K3s)"]
        agent["Management agent<br/>HTTP configuration adapter"]
        flux["Flux"]
        reconciler["App Reconciler"]
        node["Livepeer Node<br/>Orchestrator"]
        apps["Application Pods<br/>gVisor isolation"]

        agent -->|Management bundles| flux
        agent -->|App intent| reconciler
        reconciler -->|App snapshots| flux
        flux -->|Deploy and update| reconciler
        flux -->|Deploy and update| node
        flux -->|Deploy and remove| apps
        reconciler <-->|Registration, capacity and drain| node
        node -->|Private proxy| apps
        reconciler -->|Status and cleanup receipts| agent
    end

    api -->|Desired configuration, polled by agent| agent
    agent -->|Applied state and status| api
    discovery -->|Poll protected discovery| node
```

## Documentation

- [Managed onchain operation](docs/onchain-operation.md): configure fresh deployments and inspect payment readiness.
- [App registry](docs/app-registry.md): publish app definitions and assign revisions to machines.
- [Fleet discovery](docs/fleet-discovery.md): expose managed orchestrators through an aggregate inventory.
- [Machine status](docs/machine-status.md): inspect rollout, configured health, registration, discovery and cleanup evidence.
- [Machine ingress](docs/machine-tunnels.md): configure protected tunnels and routing.
- [Operations](docs/operations.md): configure authentication and administrator access.
- [Development](docs/development.md): run locally, build, and test.
