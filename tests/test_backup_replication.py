import base64
import hashlib
import json
import math
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

import httpx
import pytest
from typer.testing import CliRunner

import autocontribute.backup_replication as backup_replication_module
import autocontribute.cli as cli
from autocontribute.backup import create_state_bundle
from autocontribute.backup_replication import (
    BackupReplicaReceipt,
    BackupReplicationRecord,
    PendingStateBundleReplication,
    StateBundlePruneReport,
    _Credentials,
    _S3ObjectLockClient,
    prune_replicated_state_bundles,
    replicate_state_bundle_to_s3,
    select_next_state_bundle_for_s3,
    verify_latest_state_bundle_replication,
    write_backup_replication_record,
)
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore

_NOW = datetime(2026, 7, 23, 8, 30, tzinfo=UTC)
_RETAIN_UNTIL = _NOW + timedelta(days=90)
_ACCOUNT_ID = "123456789012"
_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
_RUNNER = CliRunner()


class _ObjectLockS3:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.objects: dict[str, tuple[str, bytes, httpx.Headers]] = {}
        self.version = 0
        self.tamper_bundle_read_back = False
        self.omit_compliance_mode = False
        self.collide_first_bundle_upload = False
        self.retain_until = _RETAIN_UNTIL

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, str(request.url)))
        assert request.url.scheme == "https"
        assert request.url.host == "backup-vault.s3.ca-central-1.amazonaws.com"
        assert request.headers["authorization"].startswith(
            f"AWS4-HMAC-SHA256 Credential={_ACCESS_KEY}/20260723/ca-central-1/s3/aws4_request"
        )
        assert request.headers["x-amz-content-sha256"]
        assert request.headers["x-amz-date"] == "20260723T083000Z"
        assert request.headers["x-amz-expected-bucket-owner"] == _ACCOUNT_ID
        assert _SECRET_KEY not in str(request.url)
        assert _SECRET_KEY not in request.headers["authorization"]

        if request.url.path == "/" and "versioning" in request.url.params:
            return httpx.Response(
                200,
                content=(
                    b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    b"<Status>Enabled</Status></VersioningConfiguration>"
                ),
            )
        if request.url.path == "/" and "object-lock" in request.url.params:
            return httpx.Response(
                200,
                content=(
                    b'<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    b"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"
                    b"</ObjectLockConfiguration>"
                ),
            )

        key = unquote(request.url.path.removeprefix("/"))
        if request.method == "PUT":
            body = request.read()
            digest = hashlib.sha256(body).hexdigest()
            assert request.headers["if-none-match"] == "*"
            assert request.headers["x-amz-checksum-sha256"] == _checksum(digest)
            assert request.headers["x-amz-sdk-checksum-algorithm"] == "SHA256"
            assert request.headers["x-amz-meta-autocontribute-sha256"] == digest
            assert request.headers["x-amz-object-lock-mode"] == "COMPLIANCE"
            assert request.headers["x-amz-object-lock-retain-until-date"] == self._retention()
            assert request.headers["x-amz-server-side-encryption"] == "AES256"
            self.version += 1
            version = f"version-{self.version}"
            headers = self._object_headers(
                body,
                version=version,
                kind=request.headers["x-amz-meta-autocontribute-kind"],
            )
            self.objects[key] = (version, body, headers)
            if self.collide_first_bundle_upload and key.endswith(".bundle.zip"):
                self.collide_first_bundle_upload = False
                return httpx.Response(
                    412,
                    content=b"<Error><Code>PreconditionFailed</Code></Error>",
                )
            return httpx.Response(200, headers={"x-amz-version-id": version})

        version, body, headers = self.objects[key]
        requested_version = request.url.params.get("versionId")
        if requested_version is not None:
            assert requested_version == version
        if request.method == "HEAD":
            response_headers = dict(headers)
            if self.omit_compliance_mode:
                response_headers.pop("x-amz-object-lock-mode")
            return httpx.Response(200, headers=response_headers)
        if request.method == "GET":
            if self.tamper_bundle_read_back and key.endswith(".bundle.zip"):
                body = body + b"tampered"
            return httpx.Response(200, headers=headers, content=body)
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    def _object_headers(self, body: bytes, *, version: str, kind: str) -> httpx.Headers:
        digest = hashlib.sha256(body).hexdigest()
        return httpx.Headers(
            {
                "content-length": str(len(body)),
                "x-amz-checksum-sha256": _checksum(digest),
                "x-amz-meta-autocontribute-kind": kind,
                "x-amz-meta-autocontribute-sha256": digest,
                "x-amz-object-lock-mode": "COMPLIANCE",
                "x-amz-object-lock-retain-until-date": self._retention(),
                "x-amz-server-side-encryption": "AES256",
                "x-amz-version-id": version,
            }
        )

    def _retention(self) -> str:
        return self.retain_until.isoformat(timespec="seconds").replace("+00:00", "Z")


def _checksum(digest: str) -> str:
    return base64.b64encode(bytes.fromhex(digest)).decode("ascii")


def test_s3_sigv4_matches_independent_botocore_known_answer() -> None:
    """Vector generated independently with botocore 1.38.46 S3SigV4Auth."""

    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500))) as client:
        s3 = _S3ObjectLockClient(
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            credentials=_Credentials(_ACCESS_KEY, _SECRET_KEY),
            client=client,
            clock=lambda: _NOW,
        )
        url, headers = s3._signed_request(
            "GET",
            key="production/bundles/sha256/abc.bundle.zip",
            query=(("versionId", "version +/="),),
            headers={"x-amz-checksum-mode": "ENABLED"},
            payload_sha256=hashlib.sha256(b"").hexdigest(),
            now=_NOW,
        )

    assert url == (
        "https://backup-vault.s3.ca-central-1.amazonaws.com/"
        "production/bundles/sha256/abc.bundle.zip?versionId=version%20%2B%2F%3D"
    )
    assert headers["authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20260723/ca-central-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-checksum-mode;x-amz-content-sha256;x-amz-date;"
        "x-amz-expected-bucket-owner, "
        "Signature=d8813f55d7d8dd3ff30faeb984d6546c7ef81d3b2585c352b43b0f91596a4f80"
    )


@pytest.mark.parametrize(
    "value",
    ["123", "12345678901a", " 123456789012", "1234567890123"],
)
def test_s3_client_requires_exact_expected_bucket_owner(value: str) -> None:
    with (
        httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500))) as client,
        pytest.raises(StateError, match="12-digit AWS account ID"),
    ):
        _S3ObjectLockClient(
            bucket="backup-vault",
            expected_bucket_owner=value,
            region="ca-central-1",
            credentials=_Credentials(_ACCESS_KEY, _SECRET_KEY),
            client=client,
            clock=lambda: _NOW,
        )


@pytest.mark.parametrize(
    "region",
    ["cn-north-1", "us-gov-west-1", "us-iso-east-1", "eusc-de-east-1"],
)
def test_s3_client_rejects_noncommercial_aws_partition(region: str) -> None:
    with (
        httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500))) as client,
        pytest.raises(StateError, match="standard commercial AWS partition"),
    ):
        _S3ObjectLockClient(
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region=region,
            credentials=_Credentials(_ACCESS_KEY, _SECRET_KEY),
            client=client,
            clock=lambda: _NOW,
        )


def _bundle(tmp_path: Path) -> Path:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    store.write_artifact(run.run_id, "operator-note.txt", "durable evidence\n")
    return create_state_bundle(store, tmp_path / "local" / "state.bundle.zip")


def _scratch(tmp_path: Path) -> Path:
    scratch = tmp_path / "replication-scratch"
    scratch.mkdir(mode=0o700, exist_ok=True)
    scratch.chmod(0o700)
    return scratch


def _replicate(
    bundle: Path,
    backend: _ObjectLockS3,
    *,
    record_destination: Path | None = None,
    retain_until: datetime = _RETAIN_UNTIL,
    scratch_directory: Path | None = None,
) -> BackupReplicationRecord:
    with httpx.Client(transport=httpx.MockTransport(backend)) as client:
        return replicate_state_bundle_to_s3(
            bundle,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=retain_until - _NOW,
            scratch_directory=scratch_directory or _scratch(bundle.parents[1]),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            session_token="temporary-session-token",
            prefix="autocontribute/production",
            record_destination=record_destination,
            client=client,
            now=_NOW,
        )


def _production_bundle(
    tmp_path: Path,
    timestamp: str,
    process_id: int,
) -> Path:
    source = _bundle(tmp_path / f"source-{process_id}")
    destination = tmp_path / "backups" / f"autocontribute-state-{timestamp}-{process_id}.bundle.zip"
    destination.parent.mkdir(mode=0o700, exist_ok=True)
    source.replace(destination)
    destination.chmod(0o400)
    return destination


def _receipt_directory(tmp_path: Path) -> Path:
    receipts = tmp_path / "backups" / "receipts"
    receipts.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipts.chmod(0o700)
    return receipts


def _record_path(receipts: Path, bundle: Path) -> Path:
    return receipts / f"{bundle.name}.s3-replication.json"


def test_s3_replication_locks_reads_back_and_receipts_exact_versions(tmp_path: Path) -> None:
    source = _bundle(tmp_path)
    backend = _ObjectLockS3()
    record_path = tmp_path / "records" / "state.replication.json"
    record_path.parent.mkdir(mode=0o700)

    record = _replicate(source, backend, record_destination=record_path)

    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert record.receipt.bundle.sha256 == source_digest
    assert record.receipt.bundle.bucket_owner_account_id == _ACCOUNT_ID
    assert record.receipt.bundle.version_id == "version-1"
    assert record.receipt.bundle.retention_mode == "COMPLIANCE"
    assert record.receipt.bundle.retain_until == _RETAIN_UNTIL
    assert record.receipt.schema_version == 2
    assert record.receipt.retention_requested_at == _NOW
    assert record.receipt.minimum_retain_until == _RETAIN_UNTIL
    assert record.receipt.read_back.complete_bundle_verified
    assert record.receipt_object.version_id == "version-2"
    assert record.receipt_object.retain_until == _RETAIN_UNTIL
    assert record.receipt_read_back.sha256 == record.receipt_sha256
    assert not record.receipt_read_back.complete_bundle_verified

    persisted = BackupReplicationRecord.model_validate_json(record_path.read_bytes())
    assert persisted == record
    assert record_path.stat().st_mode & 0o777 == 0o400
    remote_receipt = backend.objects[record.receipt_object.key][1]
    assert BackupReplicaReceipt.model_validate_json(remote_receipt) == record.receipt
    assert hashlib.sha256(remote_receipt).hexdigest() == record.receipt_sha256
    assert [method for method, _ in backend.calls] == [
        "GET",
        "GET",
        "PUT",
        "HEAD",
        "GET",
        "PUT",
        "HEAD",
        "GET",
    ]


def test_s3_replication_reuses_only_matching_content_addressed_collision(
    tmp_path: Path,
) -> None:
    backend = _ObjectLockS3()
    backend.collide_first_bundle_upload = True

    record = _replicate(_bundle(tmp_path), backend)

    assert record.receipt.bundle.version_id == "version-1"
    bundle_head = backend.calls[3]
    assert bundle_head[0] == "HEAD"
    assert "versionId" not in bundle_head[1]


def test_s3_replication_rounds_fractional_retention_up_without_shortening_it(
    tmp_path: Path,
) -> None:
    backend = _ObjectLockS3()
    backend.retain_until = _RETAIN_UNTIL + timedelta(seconds=1)

    record = _replicate(
        _bundle(tmp_path),
        backend,
        retain_until=_RETAIN_UNTIL + timedelta(microseconds=1),
    )

    assert record.receipt.bundle.retain_until == backend.retain_until
    assert record.receipt_object.retain_until == backend.retain_until


def test_s3_replication_rejects_provider_bytes_that_differ_on_read_back(
    tmp_path: Path,
) -> None:
    backend = _ObjectLockS3()
    backend.tamper_bundle_read_back = True

    with pytest.raises(StateError, match="read-back bytes differ"):
        _replicate(_bundle(tmp_path), backend)

    assert not any("/receipts/" in url for _, url in backend.calls)


def test_s3_replication_requires_provider_compliance_lock_acknowledgement(
    tmp_path: Path,
) -> None:
    backend = _ObjectLockS3()
    backend.omit_compliance_mode = True

    with pytest.raises(StateError, match="object-lock-mode acknowledgement"):
        _replicate(_bundle(tmp_path), backend)

    assert [method for method, _ in backend.calls] == ["GET", "GET", "PUT", "HEAD"]


@pytest.mark.parametrize(
    ("config_response", "message"),
    [
        (b"<VersioningConfiguration/>", "versioning is not enabled"),
        (b"<ObjectLockConfiguration/>", "Object Lock is not enabled"),
    ],
)
def test_s3_replication_fails_closed_on_bucket_configuration(
    tmp_path: Path,
    config_response: bytes,
    message: str,
) -> None:
    normal = _ObjectLockS3()

    def handler(request: httpx.Request) -> httpx.Response:
        if (
            "versioning" in request.url.params and b"VersioningConfiguration" in config_response
        ) or (
            "object-lock" in request.url.params and b"ObjectLockConfiguration" in config_response
        ):
            return httpx.Response(200, content=config_response)
        return normal(request)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(StateError, match=message),
    ):
        replicate_state_bundle_to_s3(
            _bundle(tmp_path),
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            client=client,
            now=_NOW,
        )

    assert not any(method == "PUT" for method, _ in normal.calls)


def test_s3_replication_rejects_entity_declarations_without_expanding_them(
    tmp_path: Path,
) -> None:
    expansion = b"<!DOCTYPE x [<!ENTITY a 'Enabled'>]><Status>&a;</Status>"
    requests = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, content=expansion)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(StateError, match="unsafe bucket configuration declarations"),
    ):
        replicate_state_bundle_to_s3(
            _bundle(tmp_path),
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            client=client,
            now=_NOW,
        )

    assert requests == 1


def test_s3_error_does_not_expand_hostile_entity_content(tmp_path: Path) -> None:
    hostile = (
        b"<!DOCTYPE x [<!ENTITY a 'AccessDenied'><!ENTITY b '&a;&a;&a;&a;'>]>"
        b"<Error><Code>&b;</Code></Error>"
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=hostile)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(StateError) as failure,
    ):
        replicate_state_bundle_to_s3(
            _bundle(tmp_path),
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            client=client,
            now=_NOW,
        )

    assert str(failure.value) == "S3 replication request returned HTTP 403"


def test_s3_replication_bounds_control_response_before_parsing(tmp_path: Path) -> None:
    oversized = b"x" * 1_000_001

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=oversized)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(StateError, match="control response exceeds the safe size limit"),
    ):
        replicate_state_bundle_to_s3(
            _bundle(tmp_path),
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            client=client,
            now=_NOW,
        )


def test_s3_replication_validates_complete_bundle_before_using_network(tmp_path: Path) -> None:
    invalid = tmp_path / "not-a-bundle.zip"
    invalid.write_bytes(b"not a complete state bundle")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(StateError, match="restore complete state bundle"),
    ):
        replicate_state_bundle_to_s3(
            invalid,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            client=client,
            now=_NOW,
        )

    assert calls == []


def test_s3_replication_refuses_existing_record_before_using_network(tmp_path: Path) -> None:
    record = tmp_path / "record.json"
    record.write_text("operator evidence\n", encoding="utf-8")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(500)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(StateError, match="record destination already exists"),
    ):
        replicate_state_bundle_to_s3(
            _bundle(tmp_path),
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            record_destination=record,
            client=client,
            now=_NOW,
        )

    assert calls == []
    assert record.read_text(encoding="utf-8") == "operator evidence\n"


def test_s3_replication_requires_a_preexisting_record_parent_before_network(
    tmp_path: Path,
) -> None:
    backend = _ObjectLockS3()

    with pytest.raises(StateError, match="parent must already exist"):
        _replicate(
            _bundle(tmp_path),
            backend,
            record_destination=tmp_path / "missing" / "record.json",
        )

    assert backend.calls == []


def test_s3_replication_rejects_unsafe_source_filename_before_network(tmp_path: Path) -> None:
    source = _bundle(tmp_path)
    unsafe = source.with_name("unsafe\n.bundle.zip")
    source.rename(unsafe)
    backend = _ObjectLockS3()

    with pytest.raises(StateError, match="source filename is unsafe"):
        _replicate(unsafe, backend)

    assert backend.calls == []


def test_s3_replication_rejects_surrogateescape_inputs_without_encoding_errors(
    tmp_path: Path,
) -> None:
    unsafe = "unsafe-\udcff"

    with pytest.raises(StateError, match="source filename is unsafe"):
        backup_replication_module._validate_source_filename(f"{unsafe}.bundle.zip")
    with pytest.raises(StateError, match="prefix is unsafe"):
        backup_replication_module._validate_prefix(unsafe)
    with pytest.raises(StateError, match="object key is unsafe"):
        backup_replication_module._validate_key(unsafe)
    with pytest.raises(StateError, match="destination filename is unsafe"):
        backup_replication_module._validate_record_destination(tmp_path / f"{unsafe}.json")


@pytest.mark.parametrize("timeout_seconds", [math.nan, math.inf, -math.inf])
def test_s3_replication_rejects_non_finite_timeout_before_network(
    tmp_path: Path,
    timeout_seconds: float,
) -> None:
    source = _bundle(tmp_path)
    backend = _ObjectLockS3()

    with (
        httpx.Client(transport=httpx.MockTransport(backend)) as client,
        pytest.raises(StateError, match="timeout must be between"),
    ):
        replicate_state_bundle_to_s3(
            source,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            timeout_seconds=timeout_seconds,
            client=client,
            now=_NOW,
        )

    assert backend.calls == []


def test_s3_replication_requires_conservative_scratch_capacity_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _bundle(tmp_path)
    backend = _ObjectLockS3()

    class _NoCapacity:
        free = 0

    monkeypatch.setattr(
        backup_replication_module.shutil,
        "disk_usage",
        lambda _: _NoCapacity(),
    )

    with pytest.raises(StateError, match="scratch capacity is insufficient"):
        _replicate(source, backend)

    assert backend.calls == []


def test_s3_replication_rejects_symlinked_scratch_before_network(tmp_path: Path) -> None:
    source = _bundle(tmp_path)
    real_scratch = _scratch(tmp_path)
    linked_scratch = tmp_path / "linked-scratch"
    linked_scratch.symlink_to(real_scratch, target_is_directory=True)
    backend = _ObjectLockS3()

    with pytest.raises(StateError, match="scratch directory cannot be a symbolic link"):
        _replicate(source, backend, scratch_directory=linked_scratch)

    assert backend.calls == []


def test_s3_replication_wraps_scratch_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _bundle(tmp_path)
    backend = _ObjectLockS3()
    real_open = Path.open

    def fail_read_back(path: Path, *args: object, **kwargs: object) -> object:
        if path.name == "bundle.read-back.zip" and args and args[0] == "xb":
            raise OSError("injected scratch exhaustion")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_read_back)

    with pytest.raises(StateError, match="persist S3 read-back in scratch storage"):
        _replicate(source, backend)

    assert not any("/receipts/" in url for _, url in backend.calls)


def test_s3_replication_never_accepts_a_symlinked_source(tmp_path: Path) -> None:
    source = _bundle(tmp_path)
    link = tmp_path / "state-link.zip"
    link.symlink_to(source)

    with pytest.raises(StateError, match="source cannot be a symbolic link"):
        _replicate(link, _ObjectLockS3())


def test_s3_replication_does_not_expose_credentials_in_expected_failures(
    tmp_path: Path,
) -> None:
    source = _bundle(tmp_path)

    def forbidden(_: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=b"<Error><Code>AccessDenied</Code></Error>")

    with (
        httpx.Client(transport=httpx.MockTransport(forbidden)) as client,
        pytest.raises(StateError) as failure,
    ):
        replicate_state_bundle_to_s3(
            source,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            retention_period=timedelta(days=90),
            scratch_directory=_scratch(tmp_path),
            access_key_id=_ACCESS_KEY,
            secret_access_key=_SECRET_KEY,
            session_token="temporary-session-token",
            client=client,
            now=_NOW,
        )

    message = str(failure.value)
    assert "HTTP 403" in message
    assert "AccessDenied" in message
    assert _SECRET_KEY not in message
    assert "temporary-session-token" not in message


def test_replication_receipt_rejects_changed_read_back_evidence(tmp_path: Path) -> None:
    record = _replicate(_bundle(tmp_path), _ObjectLockS3())
    payload = json.loads(record.receipt.model_dump_json())
    payload["read_back"]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="differs from the stored object"):
        BackupReplicaReceipt.model_validate(payload)


def test_replication_record_binds_receipt_to_expected_bucket_owner(tmp_path: Path) -> None:
    record = _replicate(_bundle(tmp_path), _ObjectLockS3())
    payload = json.loads(record.model_dump_json())
    payload["receipt_object"]["bucket_owner_account_id"] = "999999999999"

    with pytest.raises(ValueError, match="different expected bucket owner"):
        BackupReplicationRecord.model_validate(payload)


def test_local_replication_record_fails_closed_when_directory_fsync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _replicate(_bundle(tmp_path), _ObjectLockS3())
    destination = tmp_path / "records" / "record.json"
    destination.parent.mkdir(mode=0o700)
    real_fsync = os.fsync

    def fail_directory(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("injected directory durability failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory)

    with pytest.raises(StateError, match="durably remove"):
        write_backup_replication_record(record, destination)

    assert not destination.exists()


def test_local_replication_record_never_exposes_a_partial_final_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _replicate(_bundle(tmp_path), _ObjectLockS3())
    destination = tmp_path / "records" / "record.json"
    destination.parent.mkdir(mode=0o700)
    real_fdopen = os.fdopen

    class _InterruptedWriter:
        def __init__(self, descriptor: int, mode: str) -> None:
            self._output = real_fdopen(descriptor, mode)

        def __enter__(self) -> "_InterruptedWriter":
            self._output.__enter__()
            return self

        def __exit__(
            self,
            exception_type: type[BaseException] | None,
            exception: BaseException | None,
            traceback: object,
        ) -> bool | None:
            return self._output.__exit__(exception_type, exception, traceback)

        def write(self, _: bytes) -> int:
            raise KeyboardInterrupt("injected interruption before publication")

    with monkeypatch.context() as context:
        context.setattr(
            os,
            "fdopen",
            lambda descriptor, mode: _InterruptedWriter(descriptor, mode),
        )
        with pytest.raises(KeyboardInterrupt, match="before publication"):
            write_backup_replication_record(record, destination)

    assert not destination.exists()
    assert not list(destination.parent.glob(".autocontribute-replication-record-*.tmp"))

    assert write_backup_replication_record(record, destination) == destination
    assert BackupReplicationRecord.model_validate_json(destination.read_bytes()) == record


def test_local_replication_record_rejects_group_writable_parent(tmp_path: Path) -> None:
    record = _replicate(_bundle(tmp_path), _ObjectLockS3())
    parent = tmp_path / "untrusted-records"
    parent.mkdir(mode=0o700)
    parent.chmod(0o770)

    with pytest.raises(StateError, match="cannot be writable by group"):
        write_backup_replication_record(record, parent / "record.json")

    assert not (parent / "record.json").exists()


def test_selector_skips_only_exact_receipts_and_returns_oldest_pending_bundle(
    tmp_path: Path,
) -> None:
    oldest = _production_bundle(tmp_path, "20260721T010203.000000001Z", 11)
    pending = _production_bundle(tmp_path, "20260722T010203.000000002Z", 12)
    newest = _production_bundle(tmp_path, "20260723T010203.000000003Z", 13)
    receipts = _receipt_directory(tmp_path)
    _replicate(
        oldest,
        _ObjectLockS3(),
        record_destination=_record_path(receipts, oldest),
        scratch_directory=_scratch(tmp_path),
    )

    selected = select_next_state_bundle_for_s3(
        bundle_directory=oldest.parent,
        receipt_directory=receipts,
        bucket="backup-vault",
        expected_bucket_owner=_ACCOUNT_ID,
        region="ca-central-1",
        prefix="autocontribute/production",
    )

    assert selected == PendingStateBundleReplication(
        bundle_path=pending,
        record_path=_record_path(receipts, pending),
    )
    assert selected.bundle_path != newest


def test_selector_rejects_receipt_when_the_exact_local_bundle_changed(tmp_path: Path) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 21)
    receipts = _receipt_directory(tmp_path)
    _replicate(
        bundle,
        _ObjectLockS3(),
        record_destination=_record_path(receipts, bundle),
        scratch_directory=_scratch(tmp_path),
    )
    bundle.chmod(0o600)
    with bundle.open("ab") as output:
        output.write(b"changed after replication")
    bundle.chmod(0o400)

    with pytest.raises(StateError, match="does not bind the exact bundle bytes"):
        select_next_state_bundle_for_s3(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
        )


def test_selector_rejects_malformed_expected_receipt_instead_of_skipping(
    tmp_path: Path,
) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 22)
    receipts = _receipt_directory(tmp_path)
    receipt = _record_path(receipts, bundle)
    receipt.write_text("{}\n", encoding="utf-8")
    receipt.chmod(0o400)

    with pytest.raises(StateError, match="receipt is invalid"):
        select_next_state_bundle_for_s3(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
        )


def test_selector_rejects_unsafe_bundle_names_symlinks_and_modes(tmp_path: Path) -> None:
    valid = _production_bundle(tmp_path, "20260723T010203.000000001Z", 23)
    receipts = _receipt_directory(tmp_path)
    unsafe_name = valid.parent / "autocontribute-state-latest.bundle.zip"
    unsafe_name.write_bytes(b"not a bundle")
    unsafe_name.chmod(0o400)

    with pytest.raises(StateError, match="unsafe bundle filename"):
        select_next_state_bundle_for_s3(
            bundle_directory=valid.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
        )

    unsafe_name.unlink()
    valid.chmod(0o600)
    with pytest.raises(StateError, match="exact mode 0400"):
        select_next_state_bundle_for_s3(
            bundle_directory=valid.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
        )

    valid.chmod(0o400)
    link = valid.with_name("autocontribute-state-20260723T010204.000000001Z-24.bundle.zip")
    link.symlink_to(valid)
    with pytest.raises(StateError, match="regular file, not a symbolic link"):
        select_next_state_bundle_for_s3(
            bundle_directory=valid.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
        )


def test_selector_bounds_directory_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 25)
    receipts = _receipt_directory(tmp_path)
    (bundle.parent / "unrelated-entry").write_text("x", encoding="utf-8")
    monkeypatch.setattr(backup_replication_module, "_MAX_LOCAL_DIRECTORY_ENTRIES", 1)

    with pytest.raises(StateError, match="safe entry limit"):
        select_next_state_bundle_for_s3(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
        )


def _prune(bundles: Path, receipts: Path, *, keep: int) -> StateBundlePruneReport:
    return prune_replicated_state_bundles(
        bundle_directory=bundles,
        receipt_directory=receipts,
        bucket="backup-vault",
        expected_bucket_owner=_ACCOUNT_ID,
        region="ca-central-1",
        prefix="autocontribute/production",
        keep=keep,
    )


def test_prune_deletes_older_replicated_bundles_and_receipts_keeping_newest(
    tmp_path: Path,
) -> None:
    oldest = _production_bundle(tmp_path, "20260720T010203.000000001Z", 11)
    older = _production_bundle(tmp_path, "20260721T010203.000000002Z", 12)
    unreplicated = _production_bundle(tmp_path, "20260722T010203.000000003Z", 13)
    newest = _production_bundle(tmp_path, "20260723T010203.000000004Z", 14)
    receipts = _receipt_directory(tmp_path)
    for replicated in (oldest, older, newest):
        _replicate(
            replicated,
            _ObjectLockS3(),
            record_destination=_record_path(receipts, replicated),
            scratch_directory=_scratch(tmp_path),
        )

    report = _prune(oldest.parent, receipts, keep=2)

    assert report.deleted == (oldest, older)
    assert report.kept == (unreplicated, newest)
    assert report.pending_replication == ()
    assert not oldest.exists() and not older.exists()
    assert not _record_path(receipts, oldest).exists()
    assert not _record_path(receipts, older).exists()
    assert unreplicated.exists() and newest.exists()
    assert _record_path(receipts, newest).exists()


def test_prune_preserves_unreplicated_older_bundles_as_pending(tmp_path: Path) -> None:
    oldest = _production_bundle(tmp_path, "20260721T010203.000000001Z", 21)
    older = _production_bundle(tmp_path, "20260722T010203.000000002Z", 22)
    newest = _production_bundle(tmp_path, "20260723T010203.000000003Z", 23)
    receipts = _receipt_directory(tmp_path)

    report = _prune(oldest.parent, receipts, keep=1)

    assert report.deleted == ()
    assert report.pending_replication == (oldest, older)
    assert report.kept == (newest,)
    assert oldest.exists() and older.exists() and newest.exists()


def test_prune_rejects_invalid_receipt_on_prunable_bundle(tmp_path: Path) -> None:
    old = _production_bundle(tmp_path, "20260722T010203.000000001Z", 31)
    _production_bundle(tmp_path, "20260723T010203.000000002Z", 32)
    receipts = _receipt_directory(tmp_path)
    receipt = _record_path(receipts, old)
    receipt.write_text("{}\n", encoding="utf-8")
    receipt.chmod(0o400)

    with pytest.raises(StateError, match="receipt is invalid"):
        _prune(old.parent, receipts, keep=1)

    assert old.exists()
    assert receipt.exists()


def test_prune_rejects_receipt_that_no_longer_binds_the_bundle_bytes(tmp_path: Path) -> None:
    old = _production_bundle(tmp_path, "20260722T010203.000000001Z", 41)
    _production_bundle(tmp_path, "20260723T010203.000000002Z", 42)
    receipts = _receipt_directory(tmp_path)
    _replicate(
        old,
        _ObjectLockS3(),
        record_destination=_record_path(receipts, old),
        scratch_directory=_scratch(tmp_path),
    )
    old.chmod(0o600)
    with old.open("ab") as output:
        output.write(b"changed after replication")
    old.chmod(0o400)

    with pytest.raises(StateError, match="does not bind the exact bundle bytes"):
        _prune(old.parent, receipts, keep=1)

    assert old.exists()
    assert _record_path(receipts, old).exists()


@pytest.mark.parametrize("keep", [0, -1, 1_001])
def test_prune_requires_keep_within_bounds(tmp_path: Path, keep: int) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 51)
    receipts = _receipt_directory(tmp_path)

    with pytest.raises(StateError, match="between 1 and 1,000"):
        _prune(bundle.parent, receipts, keep=keep)

    assert bundle.exists()


def test_prune_keeps_everything_when_bundle_count_is_within_keep(tmp_path: Path) -> None:
    older = _production_bundle(tmp_path, "20260722T010203.000000001Z", 61)
    newest = _production_bundle(tmp_path, "20260723T010203.000000002Z", 62)
    receipts = _receipt_directory(tmp_path)
    _replicate(
        older,
        _ObjectLockS3(),
        record_destination=_record_path(receipts, older),
        scratch_directory=_scratch(tmp_path),
    )

    report = _prune(older.parent, receipts, keep=9)

    assert report.deleted == ()
    assert report.pending_replication == ()
    assert report.kept == (older, newest)
    assert older.exists() and newest.exists()
    assert _record_path(receipts, older).exists()


def test_latest_replication_verification_proves_fresh_bundle_and_receipt_after_marker(
    tmp_path: Path,
) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 26)
    receipts = _receipt_directory(tmp_path)
    receipt = _record_path(receipts, bundle)
    _replicate(
        bundle,
        _ObjectLockS3(),
        record_destination=receipt,
        scratch_directory=_scratch(tmp_path),
    )
    marker = tmp_path / "health" / "worker-attempt"
    marker.parent.mkdir(mode=0o700)
    marker.touch(mode=0o600)
    marker_ns = int(_NOW.timestamp() * 1_000_000_000)
    os.utime(marker, ns=(marker_ns, marker_ns))
    os.utime(bundle, ns=(marker_ns + 1_000_000_000, marker_ns + 1_000_000_000))
    os.utime(receipt, ns=(marker_ns + 2_000_000_000, marker_ns + 2_000_000_000))

    verified = verify_latest_state_bundle_replication(
        bundle_directory=bundle.parent,
        receipt_directory=receipts,
        bucket="backup-vault",
        expected_bucket_owner=_ACCOUNT_ID,
        region="ca-central-1",
        prefix="autocontribute/production",
        maximum_age=timedelta(hours=1),
        minimum_retention=timedelta(days=90),
        required_after=marker,
        now=_NOW + timedelta(seconds=3),
    )

    assert verified.bundle_path == bundle
    assert verified.record_path == receipt


def test_latest_replication_verification_rejects_retention_policy_drift(
    tmp_path: Path,
) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 260)
    receipts = _receipt_directory(tmp_path)
    receipt = _record_path(receipts, bundle)
    backend = _ObjectLockS3()
    backend.retain_until = _NOW + timedelta(days=30)
    _replicate(
        bundle,
        backend,
        record_destination=receipt,
        retain_until=backend.retain_until,
        scratch_directory=_scratch(tmp_path),
    )

    with pytest.raises(StateError, match="shorter retention policy than configured"):
        verify_latest_state_bundle_replication(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
            minimum_retention=timedelta(days=90),
            now=_NOW + timedelta(hours=1),
        )


def test_latest_replication_verification_rejects_expired_compliance_lock(
    tmp_path: Path,
) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 261)
    receipts = _receipt_directory(tmp_path)
    receipt = _record_path(receipts, bundle)
    backend = _ObjectLockS3()
    backend.retain_until = _NOW + timedelta(days=30)
    _replicate(
        bundle,
        backend,
        record_destination=receipt,
        retain_until=backend.retain_until,
        scratch_directory=_scratch(tmp_path),
    )

    with pytest.raises(StateError, match="bundle compliance lock has expired"):
        verify_latest_state_bundle_replication(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
            minimum_retention=timedelta(days=30),
            now=_NOW + timedelta(days=31),
        )


def test_latest_replication_verification_fails_closed_for_legacy_receipt_schema(
    tmp_path: Path,
) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 262)
    receipts = _receipt_directory(tmp_path)
    receipt = _record_path(receipts, bundle)
    record = _replicate(
        bundle,
        _ObjectLockS3(),
        record_destination=receipt,
        scratch_directory=_scratch(tmp_path),
    )
    payload = json.loads(record.model_dump_json())
    payload["schema_version"] = 1
    payload["receipt"]["schema_version"] = 1
    receipt.chmod(0o600)
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    receipt.chmod(0o400)

    with pytest.raises(StateError, match="legacy schema without retention-policy evidence"):
        verify_latest_state_bundle_replication(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
            minimum_retention=timedelta(days=90),
            now=_NOW,
        )


def test_latest_replication_verification_fails_for_unreplicated_newest_bundle(
    tmp_path: Path,
) -> None:
    replicated = _production_bundle(tmp_path, "20260722T010203.000000001Z", 27)
    newest = _production_bundle(tmp_path, "20260723T010203.000000001Z", 28)
    receipts = _receipt_directory(tmp_path)
    _replicate(
        replicated,
        _ObjectLockS3(),
        record_destination=_record_path(receipts, replicated),
        scratch_directory=_scratch(tmp_path),
    )

    with pytest.raises(StateError, match="cannot be opened safely"):
        verify_latest_state_bundle_replication(
            bundle_directory=replicated.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
            now=_NOW,
        )
    assert not _record_path(receipts, newest).exists()


def test_latest_replication_verification_rejects_ambiguous_or_symlinked_marker(
    tmp_path: Path,
) -> None:
    bundle = _production_bundle(tmp_path, "20260723T010203.000000001Z", 29)
    receipts = _receipt_directory(tmp_path)
    receipt = _record_path(receipts, bundle)
    _replicate(
        bundle,
        _ObjectLockS3(),
        record_destination=receipt,
        scratch_directory=_scratch(tmp_path),
    )
    marker = tmp_path / "health" / "worker-attempt"
    marker.parent.mkdir(mode=0o700)
    marker.touch(mode=0o600)
    same_ns = bundle.stat().st_mtime_ns
    os.utime(marker, ns=(same_ns, same_ns))

    with pytest.raises(StateError, match="not unambiguously newer"):
        verify_latest_state_bundle_replication(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
            required_after=marker,
        )

    marker_link = marker.with_name("worker-attempt-link")
    marker_link.symlink_to(marker)
    with pytest.raises(StateError, match="cannot be a symbolic link"):
        verify_latest_state_bundle_replication(
            bundle_directory=bundle.parent,
            receipt_directory=receipts,
            bucket="backup-vault",
            expected_bucket_owner=_ACCOUNT_ID,
            region="ca-central-1",
            prefix="autocontribute/production",
            required_after=marker_link,
        )


def test_s3_replication_cli_uses_environment_credentials_without_printing_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _bundle(tmp_path)
    expected = _replicate(source, _ObjectLockS3())
    captured: dict[str, object] = {}

    def replicate(path: Path, **kwargs: object) -> BackupReplicationRecord:
        captured["path"] = path
        captured.update(kwargs)
        return expected

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", _ACCESS_KEY)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", _SECRET_KEY)
    monkeypatch.setenv("AWS_SESSION_TOKEN", "temporary-session-token")
    monkeypatch.setattr(cli, "replicate_state_bundle_to_s3", replicate)
    record = tmp_path / "operator" / "record.json"

    result = _RUNNER.invoke(
        cli.app,
        [
            "state",
            "replicate-s3",
            "--input",
            str(source),
            "--bucket",
            "backup-vault",
            "--region",
            "ca-central-1",
            "--expected-bucket-owner",
            _ACCOUNT_ID,
            "--scratch-directory",
            str(_scratch(tmp_path)),
            "--prefix",
            "deployment-a",
            "--record-output",
            str(record),
            "--retention-days",
            "120",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Verified immutable S3 backup replica and receipt" in result.output
    assert expected.receipt.bundle.version_id in result.output
    assert expected.receipt_object.version_id in result.output
    assert _SECRET_KEY not in result.output
    assert "temporary-session-token" not in result.output
    assert captured["path"] == source
    assert captured["bucket"] == "backup-vault"
    assert captured["expected_bucket_owner"] == _ACCOUNT_ID
    assert captured["region"] == "ca-central-1"
    assert captured["scratch_directory"] == _scratch(tmp_path)
    assert captured["prefix"] == "deployment-a"
    assert captured["record_destination"] == record
    assert captured["access_key_id"] == _ACCESS_KEY
    assert captured["secret_access_key"] == _SECRET_KEY
    assert captured["session_token"] == "temporary-session-token"
    assert captured["retention_period"] == timedelta(days=120)


def test_s3_replication_cli_requires_credentials_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

    result = _RUNNER.invoke(
        cli.app,
        [
            "state",
            "replicate-s3",
            "--input",
            str(tmp_path / "missing.zip"),
            "--bucket",
            "backup-vault",
            "--region",
            "ca-central-1",
            "--expected-bucket-owner",
            _ACCOUNT_ID,
            "--scratch-directory",
            str(_scratch(tmp_path)),
        ],
    )

    assert result.exit_code == 1
    assert "replication credentials are missing" in result.output
