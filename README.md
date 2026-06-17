# cert-sync-to-oci

[![CI](https://github.com/the-i-engineers/cert-sync-to-oci/actions/workflows/ci.yml/badge.svg)](https://github.com/the-i-engineers/cert-sync-to-oci/actions/workflows/ci.yml)

A Python CronJob that syncs [cert-manager](https://cert-manager.io/) TLS secrets to [OCI Certificate Service](https://docs.oracle.com/en-us/iaas/Content/certificates/home.htm) as IMPORTED certificate versions. When cert-manager renews a certificate, the CronJob automatically pushes the new TLS data to the corresponding OCI Certificate — keeping load balancer listeners and other OCI resources that reference the certificate up to date without manual intervention.

## How it works

The sync is annotation-driven. For each `Certificate` object in the cluster, cert-sync-to-oci looks for one of two annotation modes:

**Name-based mode (recommended)** — the OCI certificate is created automatically on first run if it doesn't exist:

1. Reads `oci-cert-sync/certificate-name` and `oci-cert-sync/compartment-id` annotations.
2. Looks up the OCI certificate by name in the given compartment.
3. If not found, creates a new IMPORTED certificate with the current TLS data.
4. If already present, pushes a new IMPORTED certificate version.

**OCID mode (legacy)** — the OCI certificate must be pre-created:

1. Reads `oci-cert-sync/certificate-ocid` annotation.
2. Calls the OCI Certificate Service API to create a new **IMPORTED** certificate version.

The CronJob runs on a schedule (e.g. daily) so that newly renewed certificates are pushed within 24 hours.

## Authentication

cert-sync-to-oci uses **OKE Workload Identity** exclusively. No credentials are stored in the cluster or in Git.

At runtime the OCI SDK exchanges the pod's projected OIDC service-account token for a short-lived OCI session token (`OkeWorkloadIdentityResourcePrincipalSigner`). The CronJob service account must carry the `oci.oraclecloud.com/workload-identity: "true"` annotation.

## Prerequisites

### OCI IAM policy

An IAM policy must grant `manage leaf-certificate-family` in the target compartment, scoped to the workload identity:

```
Allow any-user to manage leaf-certificate-family in compartment id <compartment-ocid>
  where all {
    request.principal.type        = 'workload',
    request.principal.cluster_id  = '<cluster-ocid>',
    request.principal.namespace   = 'cert-manager',
    request.principal.service_account = 'cert-sync-to-oci'
  }
```

### cert-manager

cert-manager must be installed and managing `Certificate` resources in the cluster.

## Usage / Deployment

Deploy the CronJob manifest to your cluster (e.g. via ArgoCD, Flux, or `kubectl apply`). The Docker image is published to:

```
ghcr.io/the-i-engineers/cert-sync-to-oci:main
```

### Name-based mode (auto-creates OCI cert)

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  namespace: my-namespace
  annotations:
    oci-cert-sync/certificate-name: "my-oci-certificate-name"
    oci-cert-sync/compartment-id:   "ocid1.compartment.oc1..aaa..."
spec:
  secretName: my-cert-tls
  # ... rest of spec
```

### OCID mode (pre-created OCI cert)

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  namespace: my-namespace
  annotations:
    oci-cert-sync/certificate-ocid: "ocid1.certificate.oc1..<region>.amaaaa..."
spec:
  secretName: my-cert-tls
  # ... rest of spec
```

## Annotations reference

| Annotation | Mode | Description |
|---|---|---|
| `oci-cert-sync/certificate-name` | name-based | Name of the OCI Certificate to look up or create. Requires `compartment-id`. |
| `oci-cert-sync/compartment-id` | name-based | OCID of the compartment where the OCI Certificate lives or should be created. |
| `oci-cert-sync/certificate-ocid` | OCID | OCID of an existing OCI Certificate to update. Cannot be combined with `certificate-name`. |

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `CERT_SYNC_CHECK_FRESHNESS` | _(unset)_ | When set to any non-empty value, skip the push if the CURRENT OCI cert version was already created today (UTC). Useful for manual re-runs where idempotency is preferred. By default (unset) every run always pushes. |

## Manual runs / forcing a re-sync

To trigger a one-off sync outside the regular CronJob schedule, use `kubectl create job`:

```bash
kubectl create job cert-sync-manual \
  --from=cronjob/cert-sync-to-oci \
  -n cert-manager
```

This runs with the same image and environment as the scheduled job and always pushes
(default behaviour, no freshness check).

To run idempotently — skipping certs whose CURRENT OCI version was already pushed today —
patch in `CERT_SYNC_CHECK_FRESHNESS`:

```bash
kubectl create job cert-sync-manual-idempotent \
  --from=cronjob/cert-sync-to-oci \
  -n cert-manager \
  --dry-run=client -o yaml \
| kubectl patch --local -f - \
    --patch '{"spec":{"template":{"spec":{"containers":[{"name":"cert-sync-to-oci","env":[{"name":"CERT_SYNC_CHECK_FRESHNESS","value":"1"}]}]}}}}' \
    -o yaml \
| kubectl apply -f -
```

> **Tip:** the job name must be unique; delete it once done with
> `kubectl delete job cert-sync-manual -n cert-manager`.

## Development

```bash
pip install -r requirements_dev.txt
pytest tests/
```

Run linting:

```bash
ruff check --line-length=120 .
ruff format --line-length=120 .
```

## Docker image

```
ghcr.io/the-i-engineers/cert-sync-to-oci:main       # latest main build
ghcr.io/the-i-engineers/cert-sync-to-oci:v1.2.3     # pinned release
```
