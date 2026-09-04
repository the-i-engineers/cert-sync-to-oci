# AGENTS.md

## Purpose and Scope

This repo contains `sync.py`: a Python script that syncs cert-manager-issued TLS
certificates to OCI Certificate Service (IMPORTED cert type). It runs as a daily
Kubernetes CronJob, enabling an OCI Load Balancer to serve Let's Encrypt certificates
managed by cert-manager.

Deployed via ArgoCD or any GitOps toolchain by adding the CronJob manifest to your
platform cluster.

## Repository Shape

```
sync.py                     # main sync script (entrypoint)
Dockerfile                  # multi-arch image published to ghcr.io/the-i-engineers/cert-sync-to-oci
requirements.txt            # runtime deps: oci, kubernetes
requirements_dev.txt        # dev deps: ruff, pytest, pytest-cov
tests/
  test_sync.py              # unit tests (all functions mocked, no real OCI/k8s)
.python-version             # pinned Python version
.github/
  workflows/
    ci.yml                  # lint + test on every PR
    _status-check.yml       # local fork of reusable-workflows' status-check.yml (called by ci.yml)
    lint-pr-title.yml       # Conventional Commits PR title check
    daily-tag-release.yml   # daily semver tag via reusable workflow → fires release.yml
    release.yml             # builds multi-arch Docker image → pushes to GHCR
  dependabot.yml            # Actions weekly, pip weekly, docker weekly
```

## How It Works

1. cert-manager `Certificate` objects are annotated with the target OCI cert name + compartment (or legacy OCID):
   ```yaml
   annotations:
     oci-cert-sync/certificate-name: "my-oci-cert-name"
     oci-cert-sync/compartment-id:   "ocid1.compartment.oc1..aaa..."
   ```
2. The CronJob runs daily, lists all annotated `Certificate` objects cluster-wide,
   reads their K8s TLS Secrets, and calls the OCI Certificates Management API to
   create or update the IMPORTED certificate.
3. OCI LB automatically picks up the latest certificate version — no Terraform change needed on rotation.
4. Authentication: **OKE Workload Identity exclusively** (`OkeWorkloadIdentityResourcePrincipalSigner`).
   The CronJob SA must be annotated with `oci.oraclecloud.com/workload-identity: "true"`.
   No API key credentials or instance principal are used.

## Key Code Paths

- **`list_annotated_certificates(custom_api)`** — lists all `cert-manager.io/v1` Certificate
  objects cluster-wide; yields 6-tuples `(namespace, name, secretName, ociCertOcid, ociCertName, ociCompartmentId)`
  for annotated ones.
- **`build_oci_client_workload_identity()`** — creates a single shared `CertificatesManagementClient`
  using `OkeWorkloadIdentityResourcePrincipalSigner`. Called once in `main()` before the sync loop.
- **`read_tls_secret(core_api, namespace, secret_name)`** — reads K8s Secret, base64-decodes
  `tls.crt` and `tls.key`.
- **`find_oci_cert(certs_client, compartment_id, cert_name)`** — looks up an OCI Certificate by name.
- **`create_oci_cert(certs_client, compartment_id, cert_name, tls_crt, tls_key)`** — creates a new IMPORTED OCI Certificate; uses a deterministic `opc_retry_token` and handles 409 conflicts idempotently.
- **`ensure_oci_cert(certs_client, compartment_id, cert_name, tls_crt, tls_key)`** — find-or-create wrapper; returns `(ocid, was_created)`.
- **`push_to_oci(certs_client, oci_cert_id, tls_crt, tls_key)`** — calls
  `update_certificate()` with `UpdateCertificateByImportingConfigDetails` (config_type=IMPORTED).
- **`main()`** — creates one shared WI client, iterates annotated certs, calls ensure/push; exits 1 if any cert fails (others still sync).

## OCI SDK Notes

- Use `CertificatesManagementClient.update_certificate()` with `UpdateCertificateDetails` +
  `UpdateCertificateByImportingConfigDetails`. Do NOT use `create_certificate_version()` —
  that method does not exist in the OCI Python SDK.
- `cert_chain_pem` and `certificate_pem` both receive the full chain PEM from `tls.crt`
  (leaf + intermediates). This is safe and avoids having to split the chain.

## Developer Workflows

### Run tests

```bash
pip install -r requirements_dev.txt
pytest tests/ -v
```

### Lint

```bash
ruff check --line-length=120 .
ruff format --check --line-length=120 .
```

### Local Docker build

```bash
docker build -t cert-sync-to-oci:dev .
```

## CI / Release Pipeline

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `ci.yml` | PR to `main` | ruff lint + pytest |
| `lint-pr-title.yml` | PR to `main` | Enforces Conventional Commits PR title |
| `daily-tag-release.yml` | Cron 03:30 UTC + `workflow_dispatch` | Creates semver tag via reusable workflow; tag fires `release.yml` |
| `release.yml` | `release: published` + `workflow_dispatch` | Builds multi-arch Docker image → pushes to `ghcr.io/the-i-engineers/cert-sync-to-oci` |

**Bump rules** (Conventional Commits on commits since last tag):

| Pattern | Bump |
|---------|------|
| `type!:` or `BREAKING CHANGE:` in footer | major |
| `feat:` / `feat(scope):` | minor |
| `fix:`, `chore:`, `ci:`, `docs:`, others | patch |

## Agent Change Checklist

Before pushing any change:

- [ ] `pytest tests/ -v` — all tests pass
- [ ] `ruff check --line-length=120 .` — no issues
- [ ] `ruff format --check --line-length=120 .` — no formatting drift
- [ ] If changing `push_to_oci()`: use `update_certificate()` not `create_certificate_version()`
- [ ] If changing annotation keys: update both `sync.py` and `tests/test_sync.py`
- [ ] PR title follows Conventional Commits (`type(scope): description`)
- [ ] Never commit OCI credentials, kubeconfig, or internal OCID values
