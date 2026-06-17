#!/usr/bin/env python3
"""
cert-sync-to-oci: sync cert-manager TLS secrets to OCI Certificate Service.

Iterates all cert-manager Certificate objects cluster-wide. For each object
annotated with the required annotations, reads the K8s TLS Secret and either
creates or updates an IMPORTED certificate in OCI Certificate Service.

## Annotations

### Name-based mode (recommended — auto-creates the OCI cert on first run)

    oci-cert-sync/certificate-name: <oci-cert-name>
    oci-cert-sync/compartment-id:   <compartment-ocid>

The OCI certificate is looked up by name in the given compartment. If it does
not exist it is created automatically (IMPORTED type). The TLS secret content
is set at creation time, so no extra update call is made. On subsequent runs
the existing cert is updated with a new version.

### OCID mode (legacy — requires pre-created OCI cert)

    oci-cert-sync/certificate-ocid: <ocid>

The OCI certificate must already exist. A new IMPORTED version is pushed on
every run. Cannot be combined with certificate-name — set one or the other.

## Authentication

OKE Workload Identity (OIDC token exchange). The CronJob's service account
(`cert-sync-to-oci`) must be annotated with
`oci.oraclecloud.com/workload-identity: "true"` and an IAM policy must grant
`manage leaf-certificate-family` in the target compartment scoped to this
cluster, namespace, and service account.
"""

import base64
import hashlib
import sys
from datetime import datetime, timedelta, timezone

import oci
from kubernetes import client, config as k8s_config

ANNOTATION_CERT_OCID = "oci-cert-sync/certificate-ocid"
ANNOTATION_CERT_NAME = "oci-cert-sync/certificate-name"
ANNOTATION_COMPARTMENT_ID = "oci-cert-sync/compartment-id"

# Alias for backwards compatibility with external code that imports sync.ANNOTATION.
ANNOTATION = ANNOTATION_CERT_OCID


def load_k8s_client():
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CoreV1Api(), client.CustomObjectsApi()


def list_annotated_certificates(custom_api):
    """Yield one entry per actionable Certificate object.

    Yields 6-tuples:
        (namespace, cert_name, secret_name, oci_cert_id, oci_cert_name, oci_compartment_id)

    Exactly one of (oci_cert_id) or (oci_cert_name + oci_compartment_id) will
    be non-None per yielded entry. Invalid combinations are skipped with a
    warning printed to stderr.
    """
    certs = custom_api.list_cluster_custom_object(
        group="cert-manager.io",
        version="v1",
        plural="certificates",
    )
    for cert in certs.get("items", []):
        annotations = cert.get("metadata", {}).get("annotations", {})
        ns = cert["metadata"]["namespace"]
        name = cert["metadata"]["name"]
        ref = f"{ns}/{name}"

        oci_cert_id = annotations.get(ANNOTATION_CERT_OCID, "").strip() or None
        oci_cert_name = annotations.get(ANNOTATION_CERT_NAME, "").strip() or None
        oci_compartment_id = annotations.get(ANNOTATION_COMPARTMENT_ID, "").strip() or None

        if not oci_cert_id and not oci_cert_name:
            continue  # no relevant annotation

        if oci_cert_id and oci_cert_name:
            print(
                f"  ⚠ SKIP {ref}: both '{ANNOTATION_CERT_OCID}' and '{ANNOTATION_CERT_NAME}' "
                f"are set — use one or the other",
                file=sys.stderr,
            )
            continue

        if oci_cert_name and not oci_compartment_id:
            print(
                f"  ⚠ SKIP {ref}: '{ANNOTATION_CERT_NAME}' requires '{ANNOTATION_COMPARTMENT_ID}' to also be set",
                file=sys.stderr,
            )
            continue

        yield (
            ns,
            name,
            cert["spec"]["secretName"],
            oci_cert_id,
            oci_cert_name,
            oci_compartment_id,
        )


def build_oci_client_workload_identity():
    """Build a CertificatesManagementClient using OKE Workload Identity (OIDC token exchange).

    The CronJob service account must be annotated with
    oci.oraclecloud.com/workload-identity: "true" and a matching IAM workload
    identity policy must be in place. No credentials are stored in the cluster.
    """
    signer = oci.auth.signers.get_oke_workload_identity_resource_principal_signer()
    return oci.certificates_management.CertificatesManagementClient(
        config={"region": signer.region},
        signer=signer,
        retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
    )


def read_tls_secret(core_api, namespace, secret_name):
    secret = core_api.read_namespaced_secret(secret_name, namespace)
    tls_crt = base64.b64decode(secret.data["tls.crt"]).decode()
    tls_key = base64.b64decode(secret.data["tls.key"]).decode()
    return tls_crt, tls_key


def find_oci_cert(certs_client, compartment_id, cert_name):
    """Look up an OCI Certificate by name in a compartment.

    Returns the certificate OCID if exactly one match is found, or None if no
    certificates with that name exist. Raises ValueError if multiple certificates
    share the same name (which OCI allows but is ambiguous for our purposes).
    """
    response = certs_client.list_certificates(
        compartment_id=compartment_id,
        name=cert_name,
    )
    items = response.data.items
    if not items:
        return None
    if len(items) > 1:
        raise ValueError(
            f"Found {len(items)} OCI certificates named '{cert_name}' in compartment "
            f"{compartment_id} — names must be unique for auto-create to work"
        )
    return items[0].id


def create_oci_cert(certs_client, compartment_id, cert_name, tls_crt, tls_key):
    """Create a new IMPORTED OCI Certificate with the given PEM content.

    Returns the OCID of the newly created certificate.

    A deterministic opc_retry_token (SHA-256 of compartment_id+cert_name) is
    passed so that OCI deduplicates retries of the same logical create request.
    If OCI returns a conflict (409) indicating a cert with this name was created
    concurrently, find_oci_cert is called to retrieve the existing cert's OCID,
    making the create path effectively idempotent.

    LE tls.crt contains the full chain (leaf + intermediates). OCI expects
    cert_chain_pem = intermediates and certificate_pem = leaf. Passing the
    full chain for both is accepted and safe.
    """
    retry_token = hashlib.sha256(f"{compartment_id}:{cert_name}".encode()).hexdigest()[:64]
    create_details = oci.certificates_management.models.CreateCertificateDetails(
        name=cert_name,
        compartment_id=compartment_id,
        certificate_config=oci.certificates_management.models.CreateCertificateByImportingConfigDetails(
            config_type="IMPORTED",
            cert_chain_pem=tls_crt,
            certificate_pem=tls_crt,
            private_key_pem=tls_key,
        ),
    )
    try:
        response = certs_client.create_certificate(
            create_certificate_details=create_details,
            opc_retry_token=retry_token,
        )
        return response.data.id
    except oci.exceptions.ServiceError as exc:
        if exc.status == 409:
            # A cert with this name was created concurrently (or a previous run
            # succeeded after a transient failure hid the response). Re-look up
            # by name to retrieve the existing cert's OCID.
            existing_ocid = find_oci_cert(certs_client, compartment_id, cert_name)
            if existing_ocid is not None:
                return existing_ocid
        raise


def ensure_oci_cert(certs_client, compartment_id, cert_name, tls_crt, tls_key):
    """Find or create an IMPORTED OCI Certificate by name.

    Returns (ocid, was_created):
      - was_created=True  → certificate was just created; PEM content is already
                            set at creation time, no update call is needed.
      - was_created=False → certificate already existed; caller should call
                            push_to_oci to upload a new version.
    """
    ocid = find_oci_cert(certs_client, compartment_id, cert_name)
    if ocid is not None:
        return ocid, False
    ocid = create_oci_cert(certs_client, compartment_id, cert_name, tls_crt, tls_key)
    return ocid, True


def prune_old_versions(certs_client, cert_id, keep=5):
    """Schedule deletion of old certificate versions, keeping the newest `keep`.

    Called before push_to_oci while the cert is in ACTIVE state — scheduling
    deletions is rejected by OCI when the cert is in UPDATING state. Errors
    are non-fatal (logged as warnings).
    """
    try:
        response = certs_client.list_certificate_versions(certificate_id=cert_id)
        versions = sorted(response.data.items, key=lambda v: v.version_number, reverse=True)
        to_delete = [v for v in versions[keep:] if "CURRENT" not in (v.stages or [])]
        deletion_time = datetime.now(timezone.utc) + timedelta(days=1)
        for v in to_delete:
            certs_client.schedule_certificate_version_deletion(
                certificate_id=cert_id,
                certificate_version_number=v.version_number,
                schedule_certificate_version_deletion_details=oci.certificates_management.models.ScheduleCertificateVersionDeletionDetails(
                    time_of_deletion=deletion_time,
                ),
            )
            print(f"  ✓ scheduled deletion of cert version {v.version_number}")
    except Exception as exc:
        print(f"  ⚠ WARNING: could not prune old versions for {cert_id}: {exc}", file=sys.stderr)


def cert_pushed_today(certs_client, cert_id):
    """Return True if the CURRENT cert version was already created today (UTC).

    Called after prune_old_versions to avoid pushing when the cert is already
    up to date for the day. Uses the same list_certificate_versions call target
    as prune but issues a separate request.
    # ponytail: two list_certificate_versions calls per cert (prune + freshness);
    #           combine into one if OCI rate limits become a problem.
    """
    response = certs_client.list_certificate_versions(certificate_id=cert_id)
    current = next((v for v in response.data.items if "CURRENT" in (v.stages or [])), None)
    if current is None:
        return False
    return current.time_created.date() == datetime.now(timezone.utc).date()


def push_to_oci(certs_client, oci_cert_id, tls_crt, tls_key):
    # LE tls.crt contains the full chain (leaf + intermediates).
    # OCI expects cert_chain_pem = intermediates; certificate_pem = leaf.
    # Passing the full chain for both is accepted and safe.
    update_details = oci.certificates_management.models.UpdateCertificateDetails(
        certificate_config=oci.certificates_management.models.UpdateCertificateByImportingConfigDetails(
            config_type="IMPORTED",
            cert_chain_pem=tls_crt,
            certificate_pem=tls_crt,
            private_key_pem=tls_key,
        )
    )
    certs_client.update_certificate(
        certificate_id=oci_cert_id,
        update_certificate_details=update_details,
    )
    print(f"  ✓ pushed new cert version to OCI cert {oci_cert_id}")


def main():
    print("=== cert-sync-to-oci starting ===")

    core_api, custom_api = load_k8s_client()

    certs_client = build_oci_client_workload_identity()

    errors = []
    synced = 0

    for (
        ns,
        cert_name,
        secret_name,
        oci_cert_id,
        oci_cert_name,
        oci_compartment_id,
    ) in list_annotated_certificates(custom_api):
        mode = f"name={oci_cert_name}" if oci_cert_name else f"ocid={oci_cert_id}"
        print(f"Syncing {ns}/{cert_name} (secret: {secret_name}, {mode})")
        try:
            tls_crt, tls_key = read_tls_secret(core_api, ns, secret_name)

            # Push content to OCI.
            if oci_cert_name:
                oci_cert_id, created = ensure_oci_cert(
                    certs_client, oci_compartment_id, oci_cert_name, tls_crt, tls_key
                )
                if created:
                    print(f"  ✓ created new OCI cert '{oci_cert_name}' ({oci_cert_id})")
                    synced += 1
                    continue  # content already set at creation time; no old versions to prune
            prune_old_versions(certs_client, oci_cert_id)  # prune before push: cert is ACTIVE, not UPDATING
            if cert_pushed_today(certs_client, oci_cert_id):
                print(f"  ↩ already synced today, skipping push")
                synced += 1
                continue
            try:
                push_to_oci(certs_client, oci_cert_id, tls_crt, tls_key)
                synced += 1
            except Exception as push_exc:
                print(f"  ✗ ERROR: {push_exc}", file=sys.stderr)
                errors.append(f"{ns}/{cert_name}: {push_exc}")
        except Exception as exc:
            print(f"  ✗ ERROR: {exc}", file=sys.stderr)
            errors.append(f"{ns}/{cert_name}: {exc}")

    print(f"=== done: {synced} synced, {len(errors)} errors ===")
    if errors:
        for e in errors:
            print(f"  ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
