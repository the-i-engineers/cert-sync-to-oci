# cert-sync-to-oci

[![CI/CD](https://github.com/the-i-engineers/cert-sync-to-oci/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/the-i-engineers/cert-sync-to-oci/actions/workflows/ci-cd.yml)

A Python CronJob that syncs [cert-manager](https://cert-manager.io/) TLS secrets to [OCI Certificate Service](https://docs.oracle.com/en-us/iaas/Content/certificates/home.htm) as IMPORTED certificate versions. When cert-manager renews a certificate, the CronJob automatically pushes the new TLS data to the corresponding OCI Certificate — keeping load balancer listeners and other OCI resources that reference the certificate up to date without manual intervention.

## How it works

The sync is annotation-driven. For each `Certificate` object in the cluster, if the annotation `oci-cert-sync/certificate-ocid` is present, the script:

1. Reads the corresponding Kubernetes TLS Secret (`spec.secretName`).
2. Calls the OCI Certificate Service API to create a new **IMPORTED** certificate version using the decoded PEM data.

The CronJob runs on a schedule (e.g. daily) so that newly renewed certificates are pushed within 24 hours.

## Prerequisites

### OCI IAM policy

The OKE node pool's instance principal (dynamic group) must be granted permission to manage certificate versions:

```
Allow dynamic-group <node-dynamic-group> to manage certificate-versions in compartment <compartment>
```

### cert-manager

cert-manager must be installed and managing `Certificate` resources in the cluster.

## Usage / Deployment

The CronJob is deployed via the `k8s-public-platform-system` ArgoCD addon. The Docker image is published to:

```
ghcr.io/the-i-engineers/cert-sync-to-oci:main
```

To enable syncing for a certificate, annotate the `Certificate` object:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-cert
  namespace: my-namespace
  annotations:
    oci-cert-sync/certificate-ocid: "ocid1.certificate.oc1.eu-frankfurt-1.amaaaa..."
spec:
  secretName: my-cert-tls
  # ... rest of spec
```

## Configuration

| Annotation | Description |
|---|---|
| `oci-cert-sync/certificate-ocid` | OCID of the OCI Certificate to update. If absent, the certificate is skipped. |

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
