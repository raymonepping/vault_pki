# Podman Migration

## What was generated
- `podman-compose.yml` (derived from your Compose file)

## Why this exists
Podman often uses `host.containers.internal` instead of `host.docker.internal`, especially when running via a VM on macOS.
This keeps your Docker workflow intact while enabling a reliable Podman path.

## Run (podman-compose)
From repo root:

```bash
podman --version
podman ps
podman-compose -f podman-compose.yml up -d --build
podman-compose -f podman-compose.yml logs -f
```

## Stop
```bash
podman-compose -f podman-compose.yml down
```

## Changes made
No changes were required.

## Notes
- If your healthcheck uses curl, make sure the image includes curl. If the container restarts immediately, check logs first.
