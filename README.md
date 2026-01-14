# Vault PKI Lab (Podman)
A hands-on Vault PKI lab that issues real TLS certificates for nginx, plus a small dashboard that shows certificate metadata (CN, issuer, expiry, chain length) in the browser.

## What you get
- Vault running locally (file storage)
- A Vault-backed PKI chain:
  - Root CA (pki-root)
  - Intermediate CA (pki-int)
  - Leaf cert for `nginx.lab.local`
- nginx serving HTTPS on `https://nginx.lab.local:8443`
- A “PKI dashboard” page served by nginx
- A small Node helper (`certinfo`) that exposes `/cert` JSON via nginx proxy

## Architecture
- `vault` issues and stores PKI material
- `nginx` serves the dashboard over TLS using Vault-issued certs
- `certinfo` reads cert files from `./shared/certs` and returns metadata at `/cert`

```

Browser -> [https://nginx.lab.local:8443](https://nginx.lab.local:8443)
|
+-> GET /        (static dashboard HTML)
+-> GET /cert    (nginx proxies to certinfo)

````

## Repo layout
- `podman-compose.yml` Podman compose stack
- `vault/config/vault.hcl` Vault config
- `shared/certs/` generated PKI artifacts (mostly ignored by git)
- `shared/nginx/conf.d/` nginx config
- `shared/www/` dashboard HTML
- `certinfo/` Node service that returns cert metadata

## Prereqs
- Podman (Podman Machine on macOS is fine)
- `podman compose` (or your local compose provider)
- Vault CLI (`vault`)
- `openssl`
- Optional: `jq` for nicer JSON output

## Quickstart

### 1) Start the stack
From repo root:
```bash
podman compose -f podman-compose.yml up -d
podman ps
````

Vault should be on `http://127.0.0.1:8200` and nginx on:

- [http://127.0.0.1:8080](http://127.0.0.1:8080)
- [https://127.0.0.1:8443](https://127.0.0.1:8443) (hostname validation needs the next step)

### 2) Add hostname to `/etc/hosts` (macOS)

Browsers will not accept curl-style `--resolve`, so map the lab hostname locally:

```bash
sudo sh -c 'echo "127.0.0.1 nginx.lab.local" >> /etc/hosts'
```

### 3) Initialize and unseal Vault (lab mode)

Exec into the Vault container:

```bash
podman exec -it vault sh
```

Inside the container:

```sh
export VAULT_ADDR="http://127.0.0.1:8200"

# Example: single share for a lab
vault operator init -key-shares=1 -key-threshold=1 > /shared/init.txt
cat /shared/init.txt

# Unseal with the key from init.txt
vault operator unseal <UNSEAL_KEY>

# Login with the root token from init.txt
vault login <ROOT_TOKEN>
vault status
```

Important: `shared/init.txt` contains sensitive material. Do not commit it.

### 4) Create Root + Intermediate PKI and issue an nginx cert

You can run these from inside the Vault container (recommended for this lab).

Enable PKI mounts:

```sh
vault secrets enable -path=pki-root pki
vault secrets tune -max-lease-ttl=87600h pki-root

vault secrets enable -path=pki-int pki
vault secrets tune -max-lease-ttl=43800h pki-int
```

Generate root CA:

```sh
vault write -field=certificate pki-root/root/generate/internal \
  common_name="lab.local Root CA" \
  issuer_name="lab-root" \
  ttl=87600h > /shared/certs/lab-root-ca.pem
```

Generate intermediate CSR:

```sh
vault write -format=json pki-int/intermediate/generate/internal \
  common_name="lab.local Intermediate CA" \
  issuer_name="lab-int" \
  ttl=43800h > /shared/certs/lab-int.csr.json

cat /shared/certs/lab-int.csr.json | jq -r .data.csr > /shared/certs/lab-int.csr.pem
```

Sign intermediate with the root and set it:

```sh
vault write -format=json pki-root/root/sign-intermediate \
  issuer_ref="lab-root" \
  csr=@/shared/certs/lab-int.csr.pem \
  format=pem_bundle \
  ttl=43800h > /shared/certs/lab-int.signed.json

cat /shared/certs/lab-int.signed.json | jq -r .data.certificate > /shared/certs/lab-int-ca.pem
vault write pki-int/intermediate/set-signed certificate=@/shared/certs/lab-int-ca.pem
```

Configure issuing and CRL URLs:

```sh
vault write pki-int/config/urls \
  issuing_certificates="http://127.0.0.1:8200/v1/pki-int/ca" \
  crl_distribution_points="http://127.0.0.1:8200/v1/pki-int/crl"
```

Create a role for nginx certs:

```sh
vault write pki-int/roles/nginx \
  allowed_domains="lab.local" \
  allow_subdomains=true \
  allow_localhost=true \
  max_ttl="72h"
```

Issue a leaf cert (short TTL recommended for demos):

```sh
vault write -format=json pki-int/issue/nginx \
  common_name="nginx.lab.local" \
  alt_names="localhost" \
  ip_sans="127.0.0.1" \
  ttl="24h" > /shared/certs/nginx-leaf.json

cat /shared/certs/nginx-leaf.json | jq -r .data.certificate > /shared/certs/nginx.crt
cat /shared/certs/nginx-leaf.json | jq -r .data.private_key > /shared/certs/nginx.key
cat /shared/certs/nginx-leaf.json | jq -r .data.issuing_ca > /shared/certs/lab-int-issuing-ca.pem

cat /shared/certs/nginx.crt /shared/certs/lab-int-issuing-ca.pem > /shared/certs/nginx.chain.crt
```

Restart nginx to pick up the certs:

```bash
podman compose -f podman-compose.yml up -d --force-recreate nginx certinfo
```

### 5) Trust the lab Root CA (macOS)

This removes the browser “Not Secure” warning:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ./shared/certs/lab-root-ca.pem
```

### 6) Open the dashboard

- [https://nginx.lab.local:8443](https://nginx.lab.local:8443)

You can also query the JSON endpoint:

```bash
curl -sS https://nginx.lab.local:8443/cert | jq .
```

## Useful checks

### Verify TLS chain with OpenSSL

```bash
openssl s_client -connect 127.0.0.1:8443 -servername nginx.lab.local \
  -CAfile ./shared/certs/lab-root-ca.pem -verify_return_error < /dev/null \
  | grep -E "Verify return code|subject=|issuer="
```

### Confirm curl trusts it

```bash
curl -sS --resolve nginx.lab.local:8443:127.0.0.1 \
  --cacert ./shared/certs/lab-root-ca.pem \
  https://nginx.lab.local:8443/ -o /dev/null -w "%{ssl_verify_result}\n"
```

Expect `0`.

## Security notes (seriously)

- `shared/init.txt` contains unseal key + root token. Never commit it.
- Do not commit private keys such as `shared/certs/nginx.key`.
- If you accidentally exposed a Vault root token, revoke it and regenerate.

## Troubleshooting

### Browser still says “certificate not trusted”

- Confirm `lab-root-ca.pem` exists and is a CA:

  ```bash
  openssl x509 -in ./shared/certs/lab-root-ca.pem -noout -text | grep -E "CA:TRUE|Basic Constraints" -n
  ```

- Confirm it is in the System keychain:

  ```bash
  security find-certificate -c "lab.local Root CA" /Library/Keychains/System.keychain
  ```

### `/cert` returns an error

- Check logs:

  ```bash
  podman logs certinfo --tail 100
  podman logs nginx --tail 100
  ```

- Confirm files exist inside certinfo:

  ```bash
  podman exec -it certinfo sh -lc 'ls -la /shared/certs'
  ```

## Next steps

- Add certificate rotation and nginx reload without downtime
- Add revocation + CRL verification demo
- Optional: move `certinfo` to call Vault directly (auth story required)
