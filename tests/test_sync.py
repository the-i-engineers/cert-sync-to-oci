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
    cert_name=None,
    compartment_id=None,
):
    metadata = {"namespace": ns, "name": name, "annotations": {}}
    if annotation_value:
        metadata["annotations"][sync.ANNOTATION_CERT_OCID] = annotation_value
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
    assert results[0] == ("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", None, None)
    assert results[1] == ("ns3", "cert-c", "secret-c", "ocid1.certificate.oc1..ccc", None, None)


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
# build_oci_client_workload_identity
# ---------------------------------------------------------------------------


def test_build_oci_client_workload_identity(monkeypatch):
    signer_calls = []
    client_calls = []

    fake_signer = types.SimpleNamespace(region="eu-zurich-1")

    monkeypatch.setattr(
        "oci.auth.signers.get_oke_workload_identity_resource_principal_signer",
        lambda **kw: signer_calls.append(1) or fake_signer,
    )

    class FakeCertsClient:
        def __init__(self, config, signer, retry_strategy=None):
            client_calls.append((config, signer, retry_strategy))

    monkeypatch.setattr("oci.certificates_management.CertificatesManagementClient", FakeCertsClient)

    sync.build_oci_client_workload_identity()

    assert len(signer_calls) == 1
    assert len(client_calls) == 1
    assert client_calls[0][0] == {"region": "eu-zurich-1"}  # region propagated from signer
    assert client_calls[0][1] is fake_signer
    assert client_calls[0][2] is oci.retry.DEFAULT_RETRY_STRATEGY  # retry strategy wired up


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
# _oci_error
# ---------------------------------------------------------------------------


def test_oci_error_formats_service_error():
    exc = oci.exceptions.ServiceError(409, "IncorrectState", {}, "conflicting lifecycle state")
    assert sync._oci_error(exc) == "409 IncorrectState: conflicting lifecycle state"


def test_oci_error_falls_back_to_str_for_other_exceptions():
    assert sync._oci_error(ValueError("boom")) == "boom"


# ---------------------------------------------------------------------------
# prune_old_versions
# ---------------------------------------------------------------------------


def _make_version(version_number, stages=None, time_of_deletion=None):
    return types.SimpleNamespace(version_number=version_number, stages=stages or [], time_of_deletion=time_of_deletion)


def test_prune_old_versions_schedules_deletion_beyond_keep(monkeypatch):
    deleted = []

    class FakeCertsClient:
        def list_certificate_versions(self, certificate_id):
            # 7 versions; newest first after sorting
            items = [_make_version(i) for i in range(1, 8)]
            return types.SimpleNamespace(data=types.SimpleNamespace(items=items))

        def schedule_certificate_version_deletion(
            self, certificate_id, certificate_version_number, schedule_certificate_version_deletion_details
        ):
            deleted.append(certificate_version_number)

    monkeypatch.setattr(
        "oci.certificates_management.models.ScheduleCertificateVersionDeletionDetails",
        lambda **kw: types.SimpleNamespace(**kw),
    )

    sync.prune_old_versions(FakeCertsClient(), "ocid1.cert.test", keep=5)

    # versions 1 and 2 should be scheduled for deletion (oldest two)
    assert sorted(deleted) == [1, 2]


def test_prune_old_versions_skips_current_stage(monkeypatch):
    deleted = []

    class FakeCertsClient:
        def list_certificate_versions(self, certificate_id):
            items = [
                _make_version(1, stages=["CURRENT"]),  # should be skipped
                _make_version(2),
                _make_version(3),
                _make_version(4),
                _make_version(5),
                _make_version(6),
            ]
            return types.SimpleNamespace(data=types.SimpleNamespace(items=items))

        def schedule_certificate_version_deletion(
            self, certificate_id, certificate_version_number, schedule_certificate_version_deletion_details
        ):
            deleted.append(certificate_version_number)

    monkeypatch.setattr(
        "oci.certificates_management.models.ScheduleCertificateVersionDeletionDetails",
        lambda **kw: types.SimpleNamespace(**kw),
    )

    sync.prune_old_versions(FakeCertsClient(), "ocid1.cert.test", keep=5)

    # version 1 is beyond keep=5 but has CURRENT stage — must not be deleted
    assert deleted == []


def test_prune_old_versions_non_fatal_on_error(capsys):
    class BrokenClient:
        def list_certificate_versions(self, **kw):
            raise RuntimeError("OCI down")

    sync.prune_old_versions(BrokenClient(), "ocid1.cert.test")

    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "OCI down" in captured.err


def test_prune_old_versions_continues_after_per_version_failure(monkeypatch, capsys):
    """A deletion failure on one version must not abort pruning of remaining versions."""
    deleted = []
    fail_on = {2}  # version 2 will raise; version 1 (also beyond keep=5) should still be deleted

    monkeypatch.setattr(
        "oci.certificates_management.models.ScheduleCertificateVersionDeletionDetails",
        lambda **kw: types.SimpleNamespace(**kw),
    )

    class FakeCertsClient:
        def list_certificate_versions(self, certificate_id):
            items = [_make_version(n) for n in range(1, 8)]  # versions 1-7, keep=5 → delete 1,2
            return types.SimpleNamespace(data=types.SimpleNamespace(items=items))

        def schedule_certificate_version_deletion(self, certificate_id, certificate_version_number, **kw):
            if certificate_version_number in fail_on:
                raise oci.exceptions.ServiceError(409, "IncorrectState", {}, "conflicting state")
            deleted.append(certificate_version_number)

    sync.prune_old_versions(FakeCertsClient(), "ocid1.cert.test", keep=5)

    assert deleted == [1]  # version 1 succeeded despite version 2 failing
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "409 IncorrectState" in captured.err


def test_prune_old_versions_warning_includes_version_number(monkeypatch, capsys):
    """Warning message for a deletion failure must include the failing version number."""

    monkeypatch.setattr(
        "oci.certificates_management.models.ScheduleCertificateVersionDeletionDetails",
        lambda **kw: types.SimpleNamespace(**kw),
    )

    class FakeCertsClient:
        def list_certificate_versions(self, certificate_id):
            items = [_make_version(n) for n in range(1, 8)]
            return types.SimpleNamespace(data=types.SimpleNamespace(items=items))

        def schedule_certificate_version_deletion(self, certificate_id, certificate_version_number, **kw):
            raise oci.exceptions.ServiceError(409, "IncorrectState", {}, "conflicting state")

    sync.prune_old_versions(FakeCertsClient(), "ocid1.cert.test", keep=5)

    captured = capsys.readouterr()
    assert "version 2" in captured.err or "version 1" in captured.err


def test_prune_old_versions_skips_already_scheduled(monkeypatch):
    """Versions with time_of_deletion already set must not be re-scheduled."""
    deleted = []

    monkeypatch.setattr(
        "oci.certificates_management.models.ScheduleCertificateVersionDeletionDetails",
        lambda **kw: types.SimpleNamespace(**kw),
    )

    class FakeCertsClient:
        def list_certificate_versions(self, certificate_id):
            items = [
                _make_version(1, time_of_deletion="2026-06-18T00:00:00Z"),  # already scheduled
                _make_version(2),  # not yet scheduled → should be deleted
                _make_version(3),
                _make_version(4),
                _make_version(5),
                _make_version(6),
                _make_version(7),
            ]
            return types.SimpleNamespace(data=types.SimpleNamespace(items=items))

        def schedule_certificate_version_deletion(self, certificate_id, certificate_version_number, **kw):
            deleted.append(certificate_version_number)

    sync.prune_old_versions(FakeCertsClient(), "ocid1.cert.test", keep=5)

    assert deleted == [2]  # version 1 skipped (already scheduled); version 2 scheduled
    assert 1 not in deleted


# ---------------------------------------------------------------------------
# main — workload identity path
# ---------------------------------------------------------------------------


def test_main_uses_workload_identity(monkeypatch):
    built = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: built.append("wi") or object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", None, None)]),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.push_to_oci", lambda *a: None)

    sync.main()
    assert built == ["wi"]


def test_main_workload_identity_client_created_once(monkeypatch):
    built = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: built.append("wi") or object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", "ocid1..aaa", None, None),
                ("ns2", "cert-b", "secret-b", "ocid1..bbb", None, None),
            ]
        ),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.push_to_oci", lambda *a: None)

    sync.main()
    assert len(built) == 1  # created once, reused


# ---------------------------------------------------------------------------
# main — error path
# ---------------------------------------------------------------------------


def test_main_exits_nonzero_on_error(monkeypatch):
    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1.certificate.oc1..aaa", None, None)]),
    )
    monkeypatch.setattr(
        "sync.read_tls_secret",
        lambda core_api, ns, name: (_ for _ in ()).throw(RuntimeError("connection refused")),
    )

    with pytest.raises(SystemExit) as exc_info:
        sync.main()

    assert exc_info.value.code == 1


def test_main_prune_called_even_when_push_fails(monkeypatch):
    """prune_old_versions runs before push_to_oci, so it always runs even when push raises."""
    pruned = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1..aaa", None, None)]),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr(
        "sync.push_to_oci",
        lambda *a: (_ for _ in ()).throw(RuntimeError("LimitExceeded")),
    )
    monkeypatch.setattr("sync.prune_old_versions", lambda client, cert_id: pruned.append(cert_id))

    with pytest.raises(SystemExit) as exc_info:
        sync.main()

    assert exc_info.value.code == 1  # push failure → non-zero exit
    assert pruned == ["ocid1..aaa"]  # prune ran before push


def test_main_prune_runs_before_push(monkeypatch):
    """prune_old_versions must be called before push_to_oci (cert is ACTIVE, not UPDATING)."""
    order = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1..aaa", None, None)]),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.prune_old_versions", lambda *a: order.append("prune"))
    monkeypatch.setattr("sync.push_to_oci", lambda *a: order.append("push"))

    sync.main()

    assert order == ["prune", "push"]


# ---------------------------------------------------------------------------
# main — happy path
# ---------------------------------------------------------------------------


def test_main_logs_pushing_before_push(monkeypatch, capsys):
    """main() must emit a 'pushing' log line before push_to_oci is called."""
    log_at_push_time = []

    def fake_push(*a):
        log_at_push_time.append(capsys.readouterr().out)

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter([("ns1", "cert-a", "secret-a", "ocid1..aaa", None, None)]),
    )
    monkeypatch.setattr("sync.read_tls_secret", lambda *a: ("CERT", "KEY"))
    monkeypatch.setattr("sync.prune_old_versions", lambda *a: None)
    monkeypatch.setattr("sync.push_to_oci", fake_push)

    sync.main()

    assert log_at_push_time, "push_to_oci was never called"
    assert "pushing" in log_at_push_time[0].lower()


def test_main_success(monkeypatch):
    pushed = []

    monkeypatch.setattr("sync.load_k8s_client", lambda: (object(), object()))
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", "ocid1..aaa", None, None),
                ("ns2", "cert-b", "secret-b", "ocid1..bbb", None, None),
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
# list_annotated_certificates — name-based mode
# ---------------------------------------------------------------------------


def test_list_annotated_certificates_with_cert_name():
    certs = [
        _make_cert("ns1", "cert-a", "secret-a", cert_name="my-oci-cert", compartment_id="ocid1.compartment..cmp"),
    ]
    api = FakeCustomApi(certs)
    results = list(sync.list_annotated_certificates(api))

    assert len(results) == 1
    assert results[0] == ("ns1", "cert-a", "secret-a", None, "my-oci-cert", "ocid1.compartment..cmp")


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
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", None, "my-oci-cert", "ocid1.compartment..cmp"),
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
    monkeypatch.setattr("sync.build_oci_client_workload_identity", lambda: object())
    monkeypatch.setattr(
        "sync.list_annotated_certificates",
        lambda api: iter(
            [
                ("ns1", "cert-a", "secret-a", None, "my-oci-cert", "ocid1.compartment..cmp"),
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
    assert results[0][4] == "my-cert"  # oci_cert_name stripped
    assert results[0][5] == "ocid1.compartment..cmp"  # oci_compartment_id stripped


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
