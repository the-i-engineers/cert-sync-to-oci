import base64
import types

import oci
import pytest

import sync


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cert(
    ns,
    name,
    secret_name,
    annotation_value=None,
    profile_secret=None,
    cert_name=None,
    compartment_id=None,
):
    metadata = {"namespace": ns, "name": name, "annotations": {}}
    if annotation_value:
        metadata["annotations"][sync.ANNOTATION_CERT_OCID] = annotation_value
    if profile_secret:
        metadata["annotations"][sync.OCI_PROFILE_SECRET_ANNOTATION] = profile_secret
    if cert_name:
        metadata["annotations"][sync.ANNOTATION_CERT_NAME] = cert_name
    if compartment_id:
        metadata["annotations"][sync.ANNOTATION_COMPARTMENT_ID] = compartment_id
    return {"metadata": metadata, "spec": {"secretName": secret_name}}


class FakeCustomApi:
    def __init__(self, items):
        self._items = items

    def list_cluster_custom_object(self, **kwargs):
        return {"items": self._items}


# ---------------------------------------------------------------------------
# list_annotated_certificates
# ---------------------------------------------------------------------------


def test_list_annotated_certificates_returns_annotated_only():
    certs = [
        _make_cert("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa"),
        _make_cert("ns2", "cert-b", "secret-b"),  # no annotation
        _make_cert("ns3", "cert-c", "secret-c", "ocid1.certificate.oc1..ccc"),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))

    assert len(results) == 2
    assert results[0] == ("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", None, None, None)
    assert results[1] == ("ns3", "cert-c", "secret-c", "ocid1.certificate.oc1..ccc", None, None, None)


def test_list_annotated_certificates_with_oci_profile_secret():
    certs = [
        _make_cert("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", "oci-creds"),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))

    assert len(results) == 1
    assert results[0] == ("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", "oci-creds", None, None)


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
# build_oci_client_from_secret
# ---------------------------------------------------------------------------


def _make_oci_profile_secret(tenancy, user, region, fingerprint, private_key, passphrase=None):
    def enc(s):
        return base64.b64encode(s.encode()).decode()

    data = {
        "tenancy": enc(tenancy),
        "user": enc(user),
        "region": enc(region),
        "fingerprint": enc(fingerprint),
        "privateKey": enc(private_key),
    }
    if passphrase is not None:
        data["privateKeyPassphrase"] = enc(passphrase)
    return types.SimpleNamespace(data=data)


def test_build_oci_client_from_secret(monkeypatch):
    captured_config = {}

    class FakeCertsManagementClient:
        def __init__(self, config):
            captured_config.update(config)

    monkeypatch.setattr(
        "oci.certificates_management.CertificatesManagementClient",
        FakeCertsManagementClient,
    )

    fake_secret = _make_oci_profile_secret(
        tenancy="ocid1.tenancy.oc1..t",
        user="ocid1.user.oc1..u",
        region="us-phoenix-1",
        fingerprint="aa:bb:cc",
        private_key="-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----\n",
        passphrase="s3cr3t",
    )

    class FakeCoreApi:
        def read_namespaced_secret(self, name, namespace):
            return fake_secret

    sync.build_oci_client_from_secret(FakeCoreApi(), "ns1", "oci-creds")

    assert captured_config["tenancy"] == "ocid1.tenancy.oc1..t"
    assert captured_config["user"] == "ocid1.user.oc1..u"
    assert captured_config["region"] == "us-phoenix-1"
    assert captured_config["fingerprint"] == "aa:bb:cc"
    assert "KEY" in captured_config["key_content"]
    assert captured_config["pass_phrase"] == "s3cr3t"


def test_build_oci_client_from_secret_no_passphrase(monkeypatch):
    captured_config = {}

    class FakeCertsManagementClient:
        def __init__(self, config):
            captured_config.update(config)

    monkeypatch.setattr(
        "oci.certificates_management.CertificatesManagementClient",
        FakeCertsManagementClient,
    )

    fake_secret = _make_oci_profile_secret(
        tenancy="ocid1.tenancy.oc1..t",
        user="ocid1.user.oc1..u",
        region="us-phoenix-1",
        fingerprint="aa:bb:cc",
        private_key="KEY_PEM",
        # no passphrase key
    )

    class FakeCoreApi:
        def read_namespaced_secret(self, name, namespace):
            return fake_secret

    sync.build_oci_client_from_secret(FakeCoreApi(), "ns1", "oci-creds")

    assert "pass_phrase" not in captured_config


def test_build_oci_client_from_secret_missing_one_key(monkeypatch):
    monkeypatch.setattr("oci.certificates_management.CertificatesManagementClient", lambda **kw: None)
    fake_secret = _make_oci_profile_secret(
        tenancy="ocid1.tenancy.oc1..t",
        user="ocid1.user.oc1..u",
        region="us-phoenix-1",
        fingerprint="aa:bb:cc",
        private_key="KEY_PEM",
    )
    # Remove one required key
    del fake_secret.data["privateKey"]

    class FakeCoreApi:
        def read_namespaced_secret(self, name, namespace):
            return fake_secret

    with pytest.raises(ValueError) as exc_info:
        sync.build_oci_client_from_secret(FakeCoreApi(), "cert-manager", "oci-creds")

    msg = str(exc_info.value)
    assert "cert-manager/oci-creds" in msg
    assert "privateKey" in msg
    assert "Required keys:" in msg


def test_build_oci_client_from_secret_missing_multiple_keys(monkeypatch):
    monkeypatch.setattr("oci.certificates_management.CertificatesManagementClient", lambda **kw: None)
    fake_secret = _make_oci_profile_secret(
        tenancy="ocid1.tenancy.oc1..t",
        user="ocid1.user.oc1..u",
        region="us-phoenix-1",
        fingerprint="aa:bb:cc",
        private_key="KEY_PEM",
    )
    del fake_secret.data["tenancy"]
    del fake_secret.data["fingerprint"]

    class FakeCoreApi:
        def read_namespaced_secret(self, name, namespace):
            return fake_secret

    with pytest.raises(ValueError) as exc_info:
        sync.build_oci_client_from_secret(FakeCoreApi(), "ns1", "oci-creds")

    msg = str(exc_info.value)
    assert "tenancy" in msg
    assert "fingerprint" in msg


def test_build_oci_client_from_secret_invalid_base64(monkeypatch):
    monkeypatch.setattr("oci.certificates_management.CertificatesManagementClient", lambda **kw: None)
    fake_secret = _make_oci_profile_secret(
        tenancy="ocid1.tenancy.oc1..t",
        user="ocid1.user.oc1..u",
        region="us-phoenix-1",
        fingerprint="aa:bb:cc",
        private_key="KEY_PEM",
    )
    # Corrupt the tenancy value (not valid base64)
    fake_secret.data["tenancy"] = "!!!not-base64!!!"

    class FakeCoreApi:
        def read_namespaced_secret(self, name, namespace):
            return fake_secret

    with pytest.raises(ValueError) as exc_info:
        sync.build_oci_client_from_secret(FakeCoreApi(), "ns1", "oci-creds")

    msg = str(exc_info.value)
    assert "ns1/oci-creds" in msg
    assert "'tenancy'" in msg


# ---------------------------------------------------------------------------
# push_to_oci
# ---------------------------------------------------------------------------


def test_push_to_oci_calls_update_certificate(monkeypatch):
    calls = []

    class FakeCertsClient:
        def update_certificate(self, certificate_id, update_certificate_details):
            calls.append(
                {
                    "certificate_id": certificate_id,
                    "details": update_certificate_details,
                }
            )

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
# main — instance principal path (no oci-profile-secret annotation)
# ---------------------------------------------------------------------------


def test_main_uses_instance_principal_when_no_profile_secret(monkeypatch):
    built = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_instance_principal", lambda: built.append("ip") or object())
    monkeypatch.setattr(
        "sync.build_oci_client_from_secret", lambda *a: (_ for _ in ()).throw(AssertionError("should not be called"))
    )
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", None, None, None)]),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.push_to_oci", lambda *a: None)

    sync.main()
    assert built == ["ip"]


def test_main_instance_principal_created_once_for_multiple_certs(monkeypatch):
    built = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_instance_principal", lambda: built.append("ip") or object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", "ocid1..aaa", None, None, None),
                ("ns2", "cert-b", "secret-b", "ocid1..bbb", None, None, None),
            ]
        ),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.push_to_oci", lambda *a: None)

    sync.main()
    assert len(built) == 1  # created once, reused


# ---------------------------------------------------------------------------
# main — API key path (oci-profile-secret annotation present)
# ---------------------------------------------------------------------------


def test_main_uses_api_key_when_profile_secret_set(monkeypatch):
    built_from_secret = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr(
        "sync.build_oci_client_instance_principal",
        lambda: (_ for _ in ()).throw(AssertionError("should not be called")),
    )
    monkeypatch.setattr(
        "sync.build_oci_client_from_secret",
        lambda core_api, ns, name: built_from_secret.append((ns, name)) or object(),
    )
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", "oci-creds", None, None)]),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.push_to_oci", lambda *a: None)

    sync.main()
    assert built_from_secret == [("ns1", "oci-creds")]


# ---------------------------------------------------------------------------
# main — error path
# ---------------------------------------------------------------------------


def test_main_exits_nonzero_on_error(monkeypatch):
    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_instance_principal", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", None, None, None)]),
    )
    monkeypatch.setattr(
        "sync.read_tls_secret",
        lambda core_api, ns, name: (_ for _ in ()).throw(RuntimeError("connection refused")),
    )

    with pytest.raises(SystemExit) as exc_info:
        sync.main()

    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# main — happy path (mixed auth)
# ---------------------------------------------------------------------------


def test_main_success_mixed_auth(monkeypatch):
    pushed = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_instance_principal", lambda: object())
    monkeypatch.setattr("sync.build_oci_client_from_secret", lambda *a: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", "ocid1..aaa", None, None, None),  # instance principal
                ("ns2", "cert-b", "secret-b", "ocid1..bbb", "oci-creds", None, None),  # API key
            ]
        ),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT_PEM", "KEY_PEM"))
    monkeypatch.setattr(
        "sync.push_to_oci",
        lambda certs_client, oci_cert_id, tls_crt, tls_key: pushed.append(oci_cert_id),
    )

    sync.main()

    assert len(pushed) == 2
    assert "ocid1..aaa" in pushed
    assert "ocid1..bbb" in pushed


# ---------------------------------------------------------------------------
# main — empty annotation value raises error
# ---------------------------------------------------------------------------


def test_main_empty_profile_secret_annotation_raises_error(monkeypatch):
    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr(
        "sync.build_oci_client_instance_principal",
        lambda: (_ for _ in ()).throw(AssertionError("should not fall back to instance principal")),
    )
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        # annotation present but empty (whitespace)
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1..aaa", "  ", None, None)]),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))

    with pytest.raises(SystemExit) as exc_info:
        sync.main()

    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# main — API key client cached across certs sharing same secret
# ---------------------------------------------------------------------------


def test_main_api_key_client_cached_for_same_secret(monkeypatch):
    build_calls = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_instance_principal", lambda: object())
    monkeypatch.setattr(
        "sync.build_oci_client_from_secret",
        lambda core_api, ns, name: build_calls.append((ns, name)) or object(),
    )
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", "ocid1..aaa", "oci-creds", None, None),
                ("ns1", "cert-b", "secret-b", "ocid1..bbb", "oci-creds", None, None),  # same secret
                ("ns1", "cert-c", "secret-c", "ocid1..ccc", "other-creds", None, None),  # different secret
            ]
        ),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.push_to_oci", lambda *a: None)

    sync.main()

    # oci-creds built once, other-creds built once → 2 total builds
    assert build_calls == [("ns1", "oci-creds"), ("ns1", "other-creds")]


# ---------------------------------------------------------------------------
# list_annotated_certificates — name-based mode
# ---------------------------------------------------------------------------


def test_list_annotated_certificates_with_cert_name():
    certs = [
        _make_cert("ns1", "cert-a", "secret-a", cert_name="my-oci-cert", compartment_id="ocid1.compartment..cmp"),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))

    assert len(results) == 1
    assert results[0] == ("ns1", "cert-a", "secret-a", None, None, "my-oci-cert", "ocid1.compartment..cmp")


def test_list_annotated_certificates_cert_name_without_compartment_skips(capsys):
    certs = [
        _make_cert("ns1", "cert-a", "secret-a", cert_name="my-oci-cert"),  # missing compartment-id
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))

    assert results == []
    captured = capsys.readouterr()
    assert "compartment-id" in captured.err


def test_list_annotated_certificates_both_annotations_skips(capsys):
    certs = [
        _make_cert(
            "ns1",
            "cert-a",
            "secret-a",
            annotation_value="ocid1.certificate..aaa",
            cert_name="my-oci-cert",
            compartment_id="ocid1.compartment..cmp",
        ),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))

    assert results == []
    captured = capsys.readouterr()
    assert "both" in captured.err


# ---------------------------------------------------------------------------
# find_oci_cert
# ---------------------------------------------------------------------------


def _make_cert_summary(ocid, name):
    return types.SimpleNamespace(id=ocid, name=name)


def _make_list_response(items):
    return types.SimpleNamespace(data=types.SimpleNamespace(items=items))


def test_find_oci_cert_found():
    class FakeClient:
        def list_certificates(self, compartment_id, name):
            return _make_list_response([_make_cert_summary("ocid1.cert..aaa", name)])

    result = sync.find_oci_cert(FakeClient(), "ocid1.compartment..cmp", "my-cert")
    assert result == "ocid1.cert..aaa"


def test_find_oci_cert_not_found():
    class FakeClient:
        def list_certificates(self, compartment_id, name):
            return _make_list_response([])

    result = sync.find_oci_cert(FakeClient(), "ocid1.compartment..cmp", "my-cert")
    assert result is None


def test_find_oci_cert_multiple_matches_raises():
    class FakeClient:
        def list_certificates(self, compartment_id, name):
            return _make_list_response(
                [
                    _make_cert_summary("ocid1.cert..aaa", name),
                    _make_cert_summary("ocid1.cert..bbb", name),
                ]
            )

    with pytest.raises(ValueError, match="2 OCI certificates"):
        sync.find_oci_cert(FakeClient(), "ocid1.compartment..cmp", "my-cert")


# ---------------------------------------------------------------------------
# create_oci_cert
# ---------------------------------------------------------------------------


def test_create_oci_cert_calls_api(monkeypatch):
    calls = []

    class FakeCreateConfigDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class FakeCreateDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateByImportingConfigDetails",
        lambda **kw: FakeCreateConfigDetails(**kw),
    )
    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateDetails",
        lambda **kw: FakeCreateDetails(**kw),
    )

    class FakeClient:
        def create_certificate(self, create_certificate_details, opc_retry_token=None):
            calls.append(create_certificate_details)
            return types.SimpleNamespace(data=types.SimpleNamespace(id="ocid1.cert..new"))

    result = sync.create_oci_cert(FakeClient(), "ocid1.compartment..cmp", "my-cert", "CERT_PEM", "KEY_PEM")

    assert result == "ocid1.cert..new"
    assert len(calls) == 1
    assert calls[0].name == "my-cert"
    assert calls[0].compartment_id == "ocid1.compartment..cmp"
    cfg = calls[0].certificate_config
    assert cfg.config_type == "IMPORTED"
    assert cfg.cert_chain_pem == "CERT_PEM"
    assert cfg.certificate_pem == "CERT_PEM"
    assert cfg.private_key_pem == "KEY_PEM"


# ---------------------------------------------------------------------------
# ensure_oci_cert
# ---------------------------------------------------------------------------


def test_ensure_oci_cert_returns_existing(monkeypatch):
    monkeypatch.setattr("sync.find_oci_cert", lambda client, cmp, name: "ocid1.cert..existing")
    monkeypatch.setattr(
        "sync.create_oci_cert",
        lambda *a: (_ for _ in ()).throw(AssertionError("should not create")),
    )

    ocid, created = sync.ensure_oci_cert(object(), "ocid1.compartment..cmp", "my-cert", "CERT", "KEY")
    assert ocid == "ocid1.cert..existing"
    assert created is False


def test_ensure_oci_cert_creates_when_not_found(monkeypatch):
    monkeypatch.setattr("sync.find_oci_cert", lambda client, cmp, name: None)
    monkeypatch.setattr("sync.create_oci_cert", lambda *a: "ocid1.cert..new")

    ocid, created = sync.ensure_oci_cert(object(), "ocid1.compartment..cmp", "my-cert", "CERT", "KEY")
    assert ocid == "ocid1.cert..new"
    assert created is True


# ---------------------------------------------------------------------------
# main — name-based mode
# ---------------------------------------------------------------------------


def test_main_name_based_creates_and_skips_push(monkeypatch):
    """When ensure_oci_cert creates a new cert, push_to_oci must NOT be called."""
    push_calls = []
    ensure_calls = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_instance_principal", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", None, None, "my-oci-cert", "ocid1.compartment..cmp"),
            ]
        ),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr(
        "sync.ensure_oci_cert",
        lambda client, cmp, name, crt, key: ensure_calls.append(name) or ("ocid1.cert..new", True),
    )
    monkeypatch.setattr(
        "sync.push_to_oci",
        lambda *a: push_calls.append(a),
    )

    sync.main()

    assert ensure_calls == ["my-oci-cert"]
    assert push_calls == []  # skipped because was_created=True


def test_main_name_based_existing_calls_push(monkeypatch):
    """When ensure_oci_cert finds an existing cert, push_to_oci must be called."""
    push_calls = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_instance_principal", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", None, None, "my-oci-cert", "ocid1.compartment..cmp"),
            ]
        ),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr(
        "sync.ensure_oci_cert",
        lambda client, cmp, name, crt, key: ("ocid1.cert..existing", False),
    )
    monkeypatch.setattr(
        "sync.push_to_oci",
        lambda client, ocid, crt, key: push_calls.append(ocid),
    )

    sync.main()

    assert push_calls == ["ocid1.cert..existing"]


# ---------------------------------------------------------------------------
# list_annotated_certificates — whitespace normalization
# ---------------------------------------------------------------------------


def test_list_annotated_certificates_whitespace_ocid_skips():
    """A certificate-ocid annotation containing only whitespace is treated as absent."""
    certs = [_make_cert("ns1", "cert-a", "secret-a", annotation_value="   ")]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))
    assert results == []


def test_list_annotated_certificates_whitespace_cert_name_skips(capsys):
    """A certificate-name annotation containing only whitespace is treated as absent."""
    certs = [_make_cert("ns1", "cert-a", "secret-a", cert_name="  ", compartment_id="ocid1.compartment..cmp")]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))
    assert results == []


def test_list_annotated_certificates_whitespace_compartment_id_skips(capsys):
    """A compartment-id annotation containing only whitespace is treated as absent → skip with warning."""
    certs = [_make_cert("ns1", "cert-a", "secret-a", cert_name="my-cert", compartment_id="  ")]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))
    assert results == []
    captured = capsys.readouterr()
    assert "compartment-id" in captured.err


def test_list_annotated_certificates_strips_annotation_values():
    """Leading/trailing whitespace on valid annotations is stripped before yielding."""
    certs = [
        _make_cert("ns1", "cert-a", "secret-a", annotation_value="  ocid1.cert..aaa  "),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))
    assert len(results) == 1
    assert results[0][3] == "ocid1.cert..aaa"  # oci_cert_id stripped


def test_list_annotated_certificates_strips_cert_name_and_compartment():
    """Leading/trailing whitespace on certificate-name and compartment-id is stripped."""
    certs = [
        _make_cert(
            "ns1",
            "cert-a",
            "secret-a",
            cert_name="  my-cert  ",
            compartment_id="  ocid1.compartment..cmp  ",
        ),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))
    assert len(results) == 1
    assert results[0][5] == "my-cert"  # oci_cert_name stripped
    assert results[0][6] == "ocid1.compartment..cmp"  # oci_compartment_id stripped


# ---------------------------------------------------------------------------
# create_oci_cert — retry token + 409 conflict idempotency
# ---------------------------------------------------------------------------


def test_create_oci_cert_passes_retry_token(monkeypatch):
    """create_oci_cert passes a deterministic opc_retry_token derived from compartment+name."""
    import hashlib

    tokens_seen = []

    class FakeCreateConfigDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class FakeCreateDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateByImportingConfigDetails",
        lambda **kw: FakeCreateConfigDetails(**kw),
    )
    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateDetails",
        lambda **kw: FakeCreateDetails(**kw),
    )

    class FakeClient:
        def create_certificate(self, create_certificate_details, opc_retry_token=None):
            tokens_seen.append(opc_retry_token)
            return types.SimpleNamespace(data=types.SimpleNamespace(id="ocid1.cert..new"))

    sync.create_oci_cert(FakeClient(), "ocid1.compartment..cmp", "my-cert", "CERT", "KEY")

    assert len(tokens_seen) == 1
    expected = hashlib.sha256("ocid1.compartment..cmp:my-cert".encode()).hexdigest()[:64]
    assert tokens_seen[0] == expected


def test_create_oci_cert_409_conflict_returns_existing(monkeypatch):
    """On 409 from OCI, create_oci_cert re-looks up the existing cert and returns its OCID."""

    class FakeCreateConfigDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class FakeCreateDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateByImportingConfigDetails",
        lambda **kw: FakeCreateConfigDetails(**kw),
    )
    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateDetails",
        lambda **kw: FakeCreateDetails(**kw),
    )

    conflict_error = oci.exceptions.ServiceError(status=409, code="Conflict", headers={}, message="already exists")

    class FakeClient:
        def create_certificate(self, create_certificate_details, opc_retry_token=None):
            raise conflict_error

        def list_certificates(self, compartment_id, name):
            return _make_list_response([_make_cert_summary("ocid1.cert..existing", name)])

    result = sync.create_oci_cert(FakeClient(), "ocid1.compartment..cmp", "my-cert", "CERT", "KEY")
    assert result == "ocid1.cert..existing"


def test_create_oci_cert_non_409_raises(monkeypatch):
    """Non-409 ServiceErrors from OCI are re-raised."""

    class FakeCreateConfigDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class FakeCreateDetails:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateByImportingConfigDetails",
        lambda **kw: FakeCreateConfigDetails(**kw),
    )
    monkeypatch.setattr(
        "oci.certificates_management.models.CreateCertificateDetails",
        lambda **kw: FakeCreateDetails(**kw),
    )

    auth_error = oci.exceptions.ServiceError(
        status=403, code="NotAuthorizedOrNotFound", headers={}, message="not authorized"
    )

    class FakeClient:
        def create_certificate(self, create_certificate_details, opc_retry_token=None):
            raise auth_error

    with pytest.raises(oci.exceptions.ServiceError) as exc_info:
        sync.create_oci_cert(FakeClient(), "ocid1.compartment..cmp", "my-cert", "CERT", "KEY")

    assert exc_info.value.status == 403
