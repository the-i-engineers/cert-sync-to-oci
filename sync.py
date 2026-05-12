#!/usr/bin/env python3
"""
cert-sync-to-oci: sync cert-manager TLS secrets to OCI Certificate Service.

Iterates all cert-manager Certificate objects cluster-wide. For each object
annotated with `oci-cert-sync/certificate-ocid: <ocid>`, reads the K8s TLS
Secret and pushes a new imported cert version to OCI Certificate Service.

Authentication (per certificate):
  - If the Certificate is annotated with `oci-cert-sync/oci-profile-secret: <name>`,
    reads that K8s Secret (same namespace as the Certificate) for OCI API key
    credentials. This allows certs to be pushed to any OCI tenancy, including
    sovereign cloud tenancies.
  - Otherwise falls back to OCI instance principal (OKE node identity).
    The instance principal client is created lazily and shared across all certs
    that do not specify a profile secret.

OCI profile secret keys (matching cert-manager-webhook-oci convention):
  tenancy, user, region, fingerprint, privateKey, privateKeyPassphrase (optional)
"""

import base64
import sys

import oci
from kubernetes import client, config as k8s_config

ANNOTATION = "oci-cert-sync/certificate-ocid"
OCI_PROFILE_SECRET_ANNOTATION = "oci-cert-sync/oci-profile-secret"


def load_k8s_client():
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CoreV1Api(), client.CustomObjectsApi()


def list_annotated_certificates(custom_api):
    certs = custom_api.list_cluster_custom_object(
        group="cert-manager.io",
        version="v1",
        plural="certificates",
    )
    for cert in certs.get("items", []):
        annotations = cert.get("metadata", {}).get("annotations", {})
        oci_cert_id = annotations.get(ANNOTATION)
        if oci_cert_id:
            yield (
                cert["metadata"]["namespace"],
                cert["metadata"]["name"],
                cert["spec"]["secretName"],
                oci_cert_id,
                annotations.get(OCI_PROFILE_SECRET_ANNOTATION),  # None → instance principal
            )


def read_tls_secret(core_api, namespace, secret_name):
    secret = core_api.read_namespaced_secret(secret_name, namespace)
    tls_crt = base64.b64decode(secret.data["tls.crt"]).decode()
    tls_key = base64.b64decode(secret.data["tls.key"]).decode()
    return tls_crt, tls_key


def build_oci_client_from_secret(core_api, namespace, secret_name):
    """Build a CertificatesManagementClient from OCI API key credentials in a K8s Secret.

    Secret keys (matching cert-manager-webhook-oci):
      tenancy, user, region, fingerprint, privateKey, privateKeyPassphrase (optional)
    """
    secret = core_api.read_namespaced_secret(secret_name, namespace)

    def field(key):
        return base64.b64decode(secret.data[key]).decode()

    config = {
        "tenancy": field("tenancy"),
        "user": field("user"),
        "fingerprint": field("fingerprint"),
        "region": field("region"),
        "key_content": field("privateKey"),
    }
    raw_passphrase = secret.data.get("privateKeyPassphrase")
    if raw_passphrase:
        passphrase = base64.b64decode(raw_passphrase).decode().strip()
        if passphrase:
            config["pass_phrase"] = passphrase

    return oci.certificates_management.CertificatesManagementClient(config=config)


def build_oci_client_instance_principal():
    """Build a CertificatesManagementClient using OKE instance principal (node identity)."""
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    return oci.certificates_management.CertificatesManagementClient(config={}, signer=signer)


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

    # Instance principal client is created lazily so that clusters running
    # entirely on API key auth don't fail at startup if instance principal
    # metadata is unavailable.
    instance_principal_client = None

    errors = []
    synced = 0

    for ns, cert_name, secret_name, oci_cert_id, oci_profile_secret in list_annotated_certificates(custom_api):
        print(f"Syncing {ns}/{cert_name} (secret: {secret_name}) -> {oci_cert_id}")
        try:
            tls_crt, tls_key = read_tls_secret(core_api, ns, secret_name)
            if oci_profile_secret:
                certs_client = build_oci_client_from_secret(core_api, ns, oci_profile_secret)
            else:
                if instance_principal_client is None:
                    instance_principal_client = build_oci_client_instance_principal()
                certs_client = instance_principal_client
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
