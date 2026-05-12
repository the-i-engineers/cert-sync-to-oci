import base64
import types

import pytest

import sync


# ---------------------------------------------------------------------------
# list_annotated_certificates
# ---------------------------------------------------------------------------


def _make_cert(ns, name, secret_name, annotation_value=None):
    metadata = {"namespace": ns, "name": name, "annotations": {}}
    if annotation_value:
        metadata["annotations"][sync.ANNOTATION] = annotation_value
    return {"metadata": metadata, "spec": {"secretName": secret_name}}


class FakeCustomApi:
    def __init__(self, items):
        self._items = items

    def list_cluster_custom_object(self, **kwargs):
        return {"items": self._items}


def test_list_annotated_certificates_returns_annotated_only():
    certs = [
        _make_cert("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa"),
        _make_cert("ns2", "cert-b", "secret-b"),  # no annotation
        _make_cert("ns3", "cert-c", "secret-c", "ocid1.certificate.oc1..ccc"),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))

    assert len(results) == 2
    assert results[0] == ("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa")
    assert results[1] == ("ns3", "cert-c", "secret-c", "ocid1.certificate.oc1..ccc")


def test_list_annotated_certificates_no_annotations():
    certs = [
        _make_cert("ns1", "cert-a", "secret-a"),
        _make_cert("ns2", "cert-b", "secret-b"),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))
    assert results == []


def test_list_annotated_certificates_empty_list():
    api = FakeCustomApi([])
    results = list(sync.list_annotated_certificates(api))
    assert results == []


# ---------------------------------------------------------------------------
# read_tls_secret
# ---------------------------------------------------------------------------


def test_read_tls_secret_decodes_base64():
    crt_pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
    key_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"

    fake_secret = types.SimpleNamespace(
        data={
            "tls.crt": base64.b64encode(crt_pem.encode()).decode(),
            "tls.key": base64.b64encode(key_pem.encode()).decode(),
        }
    )

    class FakeCoreApi:
        def read_namespaced_secret(self, name, namespace):
            return fake_secret

    tls_crt, tls_key = sync.read_tls_secret(FakeCoreApi(), "mynamespace", "mysecret")
    assert tls_crt == crt_pem
    assert tls_key == key_pem


# ---------------------------------------------------------------------------
# push_to_oci
# ---------------------------------------------------------------------------


def test_push_to_oci_calls_create_certificate_version(monkeypatch):
    calls = []

    class FakeCertsClient:
        def update_certificate(self, certificate_id, update_certificate_details):
            calls.append(
                {
                    "certificate_id": certificate_id,
                    "details": update_certificate_details,
                }
            )

    # Stub out the OCI model constructors so we don't need a real OCI SDK
    monkeypatch.setattr(
        "oci.certificates_management.models.UpdateCertificateByImportingConfigDetails",
        lambda **kw: types.SimpleNamespace(**kw),
    )
    monkeypatch.setattr(
        "oci.certificates_management.models.UpdateCertificateDetails",
        lambda **kw: types.SimpleNamespace(**kw),
    )

    client = FakeCertsClient()
    sync.push_to_oci(client, "ocid1.certificate.oc1..test", "CERT_PEM", "KEY_PEM")

    assert len(calls) == 1
    assert calls[0]["certificate_id"] == "ocid1.certificate.oc1..test"
    cfg = calls[0]["details"].certificate_config
    assert cfg.config_type == "IMPORTED"
    assert cfg.cert_chain_pem == "CERT_PEM"
    assert cfg.private_key_pem == "KEY_PEM"


# ---------------------------------------------------------------------------
# main — error path
# ---------------------------------------------------------------------------


def test_main_exits_nonzero_on_error(monkeypatch):
    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("oci.auth.signers.InstancePrincipalsSecurityTokenSigner", lambda: object())
    monkeypatch.setattr(
        "oci.certificates_management.CertificatesManagementClient",
        lambda config, signer: object(),
    )
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa")]),
    )
    monkeypatch.setattr(
        "sync.read_tls_secret",
        lambda core_api, ns, name: (_ for _ in ()).throw(RuntimeError("connection refused")),
    )

    with pytest.raises(SystemExit) as exc_info:
        sync.main()

    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# main — happy path
# ---------------------------------------------------------------------------


def test_main_success(monkeypatch):
    pushed = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("oci.auth.signers.InstancePrincipalsSecurityTokenSigner", lambda: object())
    monkeypatch.setattr(
        "oci.certificates_management.CertificatesManagementClient",
        lambda config, signer: object(),
    )
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa"),
                ("ns2", "cert-b", "secret-b", "ocid1.certificate.oc1..bbb"),
            ]
        ),
    )
    monkeypatch.setattr(
        "sync.read_tls_secret",
        lambda core_api, ns, name: ("CERT_PEM", "KEY_PEM"),
    )
    monkeypatch.setattr(
        "sync.push_to_oci",
        lambda certs_client, oci_cert_id, tls_crt, tls_key: pushed.append(oci_cert_id),
    )

    sync.main()  # should not raise

    assert len(pushed) == 2
    assert "ocid1.certificate.oc1..aaa" in pushed
    assert "ocid1.certificate.oc1..bbb" in pushed
