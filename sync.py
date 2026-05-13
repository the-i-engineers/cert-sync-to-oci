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

## Authentication (per Certificate)

  - If annotated with `oci-cert-sync/oci-profile-secret: <secret-name>`,
    reads that K8s Secret (in the same namespace as the Certificate) for OCI
    API key credentials. Allows certs to be pushed to any OCI tenancy.
  - Otherwise falls back to OCI instance principal (OKE node identity).
    The instance principal client is created lazily and shared across all certs
    that do not specify a profile secret.

## OCI profile secret keys (matching cert-manager-webhook-oci convention)

  tenancy, user, region, fingerprint, privateKey, privateKeyPassphrase (optional)
"""

import base64
import sys

import oci
from kubernetes import client, config as k8s_config

ANNOTATION_CERT_OCID = "oci-cert-sync/certificate-ocid"
ANNOTATION_CERT_NAME = "oci-cert-sync/certificate-name"
ANNOTATION_COMPARTMENT_ID = "oci-cert-sync/compartment-id"
OCI_PROFILE_SECRET_ANNOTATION = "oci-cert-sync/oci-profile-secret"

# Keep the old constant as an alias so existing tests that import `sync.ANNOTATION` still work.
ANNOTATION = ANNOTATION_CERT_OCID


def load_k8s_client():
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CoreV1Api(), client.CustomObjectsApi()


def list_annotated_certificates(custom_api):
    """Yield one entry per actionable Certificate object.

    Yields 7-tuples:
        (namespace, cert_name, secret_name, oci_cert_id, oci_profile_secret,
         oci_cert_name, oci_compartment_id)

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

        oci_cert_id = annotations.get(ANNOTATION_CERT_OCID)
        oci_cert_name = annotations.get(ANNOTATION_CERT_NAME)
        oci_compartment_id = annotations.get(ANNOTATION_COMPARTMENT_ID)

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
            annotations.get(OCI_PROFILE_SECRET_ANNOTATION),  # None → instance principal
            oci_cert_name,
            oci_compartment_id,
        )


def read_tls_secret(core_api, namespace, secret_name):
    secret = core_api.read_namespaced_secret(secret_name, namespace)
    tls_crt = base64.b64decode(secret.data["tls.crt"]).decode()
    tls_key = base64.b64decode(secret.data["tls.key"]).decode()
    return tls_crt, tls_key


_REQUIRED_SECRET_KEYS = ("tenancy", "user", "region", "fingerprint", "privateKey")


def build_oci_client_from_secret(core_api, namespace, secret_name):
    """Build a CertificatesManagementClient from OCI API key credentials in a K8s Secret.

    Secret keys (matching cert-manager-webhook-oci):
      tenancy, user, region, fingerprint, privateKey, privateKeyPassphrase (optional)

    Raises ValueError with a descriptive message if required keys are missing or
    if any value cannot be base64/UTF-8 decoded.
    """
    secret = core_api.read_namespaced_secret(secret_name, namespace)
    data = secret.data or {}
    ref = f"{namespace}/{secret_name}"

    missing = [k for k in _REQUIRED_SECRET_KEYS if k not in data]
    if missing:
        raise ValueError(
            f"Secret {ref} is missing required key(s): {missing}. Required keys: {list(_REQUIRED_SECRET_KEYS)}"
        )

    def field(key):
        try:
            return base64.b64decode(data[key], validate=True).decode()
        except Exception as exc:
            raise ValueError(f"Secret {ref} key '{key}': {exc}") from exc

    config = {
        "tenancy": field("tenancy"),
        "user": field("user"),
        "fingerprint": field("fingerprint"),
        "region": field("region"),
        "key_content": field("privateKey"),
    }
    raw_passphrase = data.get("privateKeyPassphrase")
    if raw_passphrase:
        try:
            passphrase = base64.b64decode(raw_passphrase, validate=True).decode().strip()
        except Exception as exc:
            raise ValueError(f"Secret {ref} key 'privateKeyPassphrase': {exc}") from exc
        if passphrase:
            config["pass_phrase"] = passphrase

    return oci.certificates_management.CertificatesManagementClient(config=config)


def build_oci_client_instance_principal():
    """Build a CertificatesManagementClient using OKE instance principal (node identity)."""
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    return oci.certificates_management.CertificatesManagementClient(config={}, signer=signer)


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

    LE tls.crt contains the full chain (leaf + intermediates). OCI expects
    cert_chain_pem = intermediates and certificate_pem = leaf. Passing the
    full chain for both is accepted and safe.
    """
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
    response = certs_client.create_certificate(create_certificate_details=create_details)
    return response.data.id


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

    # Lazily-created clients:
    # - instance_principal_client: shared across all certs with no profile secret
    # - api_key_clients: cached per (namespace, secret_name) to avoid re-reading
    #   the same K8s Secret for every cert that shares the same credentials.
    instance_principal_client = None
    api_key_clients: dict = {}

    errors = []
    synced = 0

    for (
        ns,
        cert_name,
        secret_name,
        oci_cert_id,
        oci_profile_secret,
        oci_cert_name,
        oci_compartment_id,
    ) in list_annotated_certificates(custom_api):
        mode = f"name={oci_cert_name}" if oci_cert_name else f"ocid={oci_cert_id}"
        print(f"Syncing {ns}/{cert_name} (secret: {secret_name}, {mode})")
        try:
            tls_crt, tls_key = read_tls_secret(core_api, ns, secret_name)

            # Build OCI client (API key or instance principal).
            if oci_profile_secret is not None:
                oci_profile_secret = oci_profile_secret.strip()
                if not oci_profile_secret:
                    raise ValueError(
                        f"{ns}/{cert_name}: annotation '{OCI_PROFILE_SECRET_ANNOTATION}' is present but empty"
                    )
                cache_key = (ns, oci_profile_secret)
                if cache_key not in api_key_clients:
                    api_key_clients[cache_key] = build_oci_client_from_secret(core_api, ns, oci_profile_secret)
                certs_client = api_key_clients[cache_key]
            else:
                if instance_principal_client is None:
                    instance_principal_client = build_oci_client_instance_principal()
                certs_client = instance_principal_client

            # Push content to OCI.
            if oci_cert_name:
                oci_cert_id, created = ensure_oci_cert(
                    certs_client, oci_compartment_id, oci_cert_name, tls_crt, tls_key
                )
                if created:
                    print(f"  ✓ created new OCI cert '{oci_cert_name}' ({oci_cert_id})")
                    synced += 1
                    continue  # content already set at creation time
            push_to_oci(certs_client, oci_cert_id, tls_crt, tls_key)
            synced += 1
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
