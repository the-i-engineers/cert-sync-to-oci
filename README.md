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

## Prerequisites

### OCI IAM policy

The identity used for OCI API calls must be granted permission to manage leaf certificates in the target compartment:

```
Allow <principal> to manage leaf-certificate-family in compartment <compartment>
```

For instance-principal auth, `<principal>` is `dynamic-group <node-dynamic-group>`.  
For API key auth, `<principal>` is `group <svc-group>`.

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
    # optional: API key auth via K8s Secret (omit for instance principal)
    oci-cert-sync/oci-profile-secret: "oci-credentials"
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
| `oci-cert-sync/oci-profile-secret` | both | Name of a K8s Secret (in the Certificate's namespace) with OCI API key credentials. Omit to use instance principal auth. |

### OCI profile secret keys

The secret referenced by `oci-cert-sync/oci-profile-secret` must contain these keys (base64-encoded, matching the cert-manager-webhook-oci convention):

| Key | Required | Description |
|---|---|---|
| `tenancy` | ✓ | OCI tenancy OCID |
| `user` | ✓ | OCI user OCID |
| `region` | ✓ | OCI region identifier (e.g. `eu-zurich-1`) |
| `fingerprint` | ✓ | API key fingerprint |
| `privateKey` | ✓ | PEM-encoded private key |
| `privateKeyPassphrase` | — | Passphrase for encrypted private keys |

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
