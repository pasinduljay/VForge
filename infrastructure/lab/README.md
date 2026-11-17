# VForge Isolated Learning Lab (`infrastructure/lab/`)

This directory defines the **strictly isolated, opt-in Learning Lab** for VForge Phase 13 (`REQ-022`, Architecture §27).

## Security & Isolation Guarantees

- **Separate Compose Project (`vforge-lab`):** Never merged into the VForge control-plane Compose project or PostgreSQL/RabbitMQ/Valkey/OPA networks.
- **Default-Deny Outbound Egress (`internal: true`):** All vulnerable containers attach solely to `lab_internal`, an internal Docker bridge with zero external internet routing.
- **No Public Exposure:** Optional local bindings attach strictly to loopback (`127.0.0.1:3100`, `127.0.0.1:3101`, `127.0.0.1:3102`).
- **Immutable Pinned Digests:** Every target container (`bkimminich/juice-shop`, `webgoat/webgoat`, `crapi/crapi-web`, `crapi/crapi-identity`, and disposable `crapi-db`) is pinned to an immutable `@sha256:` digest tracked in `../../lifecycle/image-lock/phase13-images.json`.
- **Disposable & Resettable State:** State is stored exclusively in ephemeral `tmpfs` mounts; recreating the stack (`down` + `up`) restores a completely clean baseline state.

## Usage

```powershell
# Start isolated lab targets (explicit opt-in profile required)
docker compose -f infrastructure/lab/compose.lab.yaml --profile lab up -d

# Reset all lab containers and wipe disposable tmpfs databases back to clean baseline
docker compose -f infrastructure/lab/compose.lab.yaml --profile lab down
docker compose -f infrastructure/lab/compose.lab.yaml --profile lab up -d
```
