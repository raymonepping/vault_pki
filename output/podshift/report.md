# Podshift Report

## Inputs
- Compose: `/Users/raymon.epping/Documents/VSC/HashiCorp/vault_pki/docker-compose.yml`
- Repo root: `/Users/raymon.epping/Documents/VSC/HashiCorp/vault_pki`

## Recommendation
- Verdict: **GREEN**
- Strategy: **podman-compose**

## Services
- **vault** | build: no | image: yes
  - Ports: `8200:8200`
  - environment: `{"VAULT_ADDR":"http://127.0.0.1:8200"}`
  - restart: `unless-stopped`
- **nginx** | build: no | image: yes
  - Ports: `8080:80`
  - restart: `unless-stopped`

## Findings
No issues detected.

## Next step
Proceed with migration, but address the findings first.
