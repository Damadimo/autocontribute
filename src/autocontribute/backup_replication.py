"""Immutable off-host replication for verified complete state bundles.

The local backup service intentionally has no network or credentials.  This module is the
separate provider boundary: it uploads an already-created complete bundle to AWS S3 Object Lock,
acknowledges the exact immutable version, reads that version back, and stores the resulting receipt
under the same compliance retention policy.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from typing import Final, Literal
from urllib.parse import quote, urlencode

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from autocontribute.backup import restore_state_bundle
from autocontribute.exceptions import StateError

_REPLICATION_SCHEMA_VERSION: Final = 2
_COPY_CHUNK_BYTES: Final = 1024 * 1024
# A complete bundle contains at most 5 GB of uncompressed state.  ZIP framing can add a small
# amount, but a larger local source is never a bundle this implementation could have created.
_MAX_BUNDLE_BYTES: Final = 5_100_000_000
_MAX_RECEIPT_BYTES: Final = 1_000_000
_MAX_CONTROL_RESPONSE_BYTES: Final = 1_000_000
_MAX_RESTORED_BUNDLE_BYTES: Final = 5_000_000_000
_SCRATCH_RESERVE_BYTES: Final = 512 * 1024 * 1024
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_STANDARD_AWS_REGION = re.compile(
    r"^(?:af|ap|ca|eu|il|me|mx|sa|us)-"
    r"(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-"
    r"[1-9][0-9]*$"
)
_AWS_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_ACCESS_KEY = re.compile(r"^[A-Z0-9]{16,128}$")
_LOCAL_BUNDLE = re.compile(
    r"^autocontribute-state-(?P<second>[0-9]{8}T[0-9]{6})\."
    r"(?P<nanosecond>[0-9]{9})Z-(?P<pid>[1-9][0-9]{0,9})\.bundle\.zip$"
)
_LOCAL_BUNDLE_PREFIX: Final = "autocontribute-state-"
_LOCAL_BUNDLE_SUFFIX: Final = ".bundle.zip"
_LOCAL_RECEIPT_SUFFIX: Final = ".s3-replication.json"
_MAX_LOCAL_DIRECTORY_ENTRIES: Final = 10_000
_MARKER_MAX_BYTES: Final = 1_024
_FUTURE_MTIME_TOLERANCE_NS: Final = 5 * 60 * 1_000_000_000


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ImmutableS3Object(_StrictModel):
    """Provider acknowledgement for one exact compliance-locked S3 version."""

    provider: Literal["aws-s3"] = "aws-s3"
    bucket: str
    bucket_owner_account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: str
    key: str
    version_id: str
    retention_mode: Literal["COMPLIANCE"] = "COMPLIANCE"
    retain_until: datetime
    server_side_encryption: Literal["AES256"] = "AES256"
    size: int = Field(ge=0, le=_MAX_BUNDLE_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("retain_until")
    @classmethod
    def retain_until_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("retain_until must include a timezone")
        return value.astimezone(UTC)

    @field_validator("bucket", "region", "key", "version_id")
    @classmethod
    def identity_is_bounded(cls, value: str) -> str:
        if (
            not value
            or value != value.strip()
            or len(value) > 2_048
            or any(not character.isprintable() for character in value)
        ):
            raise ValueError("S3 object identity fields must be bounded printable values")
        return value


class ReplicaReadBack(_StrictModel):
    """Cryptographic evidence computed from provider-returned bytes."""

    verified_at: datetime
    size: int = Field(ge=0, le=_MAX_BUNDLE_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    complete_bundle_verified: bool

    @field_validator("verified_at")
    @classmethod
    def verified_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verified_at must include a timezone")
        return value.astimezone(UTC)


class BackupReplicaReceipt(_StrictModel):
    """Portable receipt persisted in immutable off-host storage."""

    schema_version: Literal[2] = _REPLICATION_SCHEMA_VERSION
    created_at: datetime
    retention_requested_at: datetime
    minimum_retain_until: datetime
    source_filename: str
    bundle: ImmutableS3Object
    read_back: ReplicaReadBack

    @field_validator("created_at", "retention_requested_at", "minimum_retain_until")
    @classmethod
    def receipt_times_are_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("receipt timestamps must include a timezone")
        return value.astimezone(UTC)

    @field_validator("source_filename")
    @classmethod
    def source_filename_is_safe(cls, value: str) -> str:
        if not _is_safe_source_filename(value):
            raise ValueError("source_filename must be one bounded printable filename")
        return value

    @model_validator(mode="after")
    def read_back_matches_object(self) -> BackupReplicaReceipt:
        if self.minimum_retain_until <= self.retention_requested_at:
            raise ValueError("receipt retention interval must be positive")
        if self.created_at < self.retention_requested_at:
            raise ValueError("receipt verification cannot predate its retention request")
        if not self.read_back.complete_bundle_verified:
            raise ValueError("receipt requires complete bundle verification")
        if (self.read_back.size, self.read_back.sha256) != (
            self.bundle.size,
            self.bundle.sha256,
        ):
            raise ValueError("receipt read-back evidence differs from the stored object")
        if self.created_at != self.read_back.verified_at:
            raise ValueError("receipt time must be the completed read-back verification time")
        if self.bundle.retain_until <= self.created_at:
            raise ValueError("receipt cannot acknowledge an already-expired retention lock")
        if self.bundle.retain_until < self.minimum_retain_until:
            raise ValueError("receipt bundle lock is shorter than the requested retention deadline")
        return self


class BackupReplicationRecord(_StrictModel):
    """Local locator for the independently verified off-host receipt version."""

    schema_version: Literal[2] = _REPLICATION_SCHEMA_VERSION
    created_at: datetime
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt: BackupReplicaReceipt
    receipt_object: ImmutableS3Object
    receipt_read_back: ReplicaReadBack

    @field_validator("created_at")
    @classmethod
    def record_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def receipt_storage_is_consistent(self) -> BackupReplicationRecord:
        canonical_receipt = (self.receipt.model_dump_json(indent=2) + "\n").encode()
        if hashlib.sha256(canonical_receipt).hexdigest() != self.receipt_sha256:
            raise ValueError("receipt digest does not bind the embedded receipt evidence")
        if self.receipt_sha256 != self.receipt_object.sha256:
            raise ValueError("receipt digest differs from its stored object")
        if (self.receipt_read_back.size, self.receipt_read_back.sha256) != (
            self.receipt_object.size,
            self.receipt_object.sha256,
        ):
            raise ValueError("receipt read-back differs from its stored object")
        if self.receipt_read_back.complete_bundle_verified:
            raise ValueError("receipt JSON cannot be marked as a complete state bundle")
        if self.created_at != self.receipt_read_back.verified_at:
            raise ValueError("record time must be the completed receipt read-back time")
        if self.receipt_object.retain_until < self.receipt.bundle.retain_until:
            raise ValueError("off-host receipt retention is shorter than bundle retention")
        if (self.receipt_object.bucket, self.receipt_object.region) != (
            self.receipt.bundle.bucket,
            self.receipt.bundle.region,
        ):
            raise ValueError("off-host receipt is outside the acknowledged bundle boundary")
        if (
            self.receipt_object.bucket_owner_account_id
            != self.receipt.bundle.bucket_owner_account_id
        ):
            raise ValueError("off-host receipt has a different expected bucket owner")
        return self


@dataclass(frozen=True, slots=True)
class _Credentials:
    access_key_id: str
    secret_access_key: str = field(repr=False)
    session_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _LocalObject:
    path: Path
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _ValidatedRecordDestination:
    path: Path
    parent_device: int
    parent_inode: int


@dataclass(frozen=True, slots=True)
class PendingStateBundleReplication:
    """The exact oldest local complete bundle that still needs an S3 receipt."""

    bundle_path: Path
    record_path: Path


@dataclass(frozen=True, slots=True)
class VerifiedStateBundleReplication:
    """Read-only proof that one local bundle has exact off-host receipt evidence."""

    bundle_path: Path
    record_path: Path
    record: BackupReplicationRecord


@dataclass(frozen=True, slots=True)
class StateBundlePruneReport:
    """Local complete bundles kept, deleted, or preserved awaiting replication."""

    kept: tuple[Path, ...]
    deleted: tuple[Path, ...]
    pending_replication: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class _DirectorySnapshot:
    path: Path
    device: int
    inode: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _BundleCandidate:
    path: Path
    record_path: Path
    order: tuple[datetime, int, int, str]
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int
    mode: int
    links: int
    owner: int


class _S3ObjectLockClient:
    """Small, auditable AWS Signature V4 client for the required S3 operations only."""

    def __init__(
        self,
        *,
        bucket: str,
        expected_bucket_owner: str,
        region: str,
        credentials: _Credentials,
        client: httpx.Client,
        clock: Callable[[], datetime],
    ) -> None:
        _validate_bucket(bucket)
        _validate_expected_bucket_owner(expected_bucket_owner)
        _validate_region(region)
        if not _ACCESS_KEY.fullmatch(credentials.access_key_id):
            raise StateError("AWS access key ID is malformed")
        if (
            not credentials.secret_access_key
            or len(credentials.secret_access_key) > 256
            or any(character in credentials.secret_access_key for character in "\r\n")
        ):
            raise StateError("AWS secret access key is malformed")
        if credentials.session_token is not None and (
            not credentials.session_token
            or len(credentials.session_token) > 16_384
            or any(character in credentials.session_token for character in "\r\n")
        ):
            raise StateError("AWS session token is malformed")
        self.bucket = bucket
        self.expected_bucket_owner = expected_bucket_owner
        self.region = region
        self._credentials = credentials
        self._client = client
        self._clock = clock
        self._host = f"{bucket}.s3.{region}.amazonaws.com"

    def verify_bucket_boundary(self) -> None:
        versioning = self._request(
            "GET",
            key=None,
            query=(("versioning", ""),),
            now=self._clock(),
        )
        if _xml_value(versioning.content, "Status") != "Enabled":
            raise StateError("S3 backup bucket versioning is not enabled")

        object_lock = self._request(
            "GET",
            key=None,
            query=(("object-lock", ""),),
            now=self._clock(),
        )
        if _xml_value(object_lock.content, "ObjectLockEnabled") != "Enabled":
            raise StateError("S3 backup bucket Object Lock is not enabled")

    def put_immutable(
        self,
        local: _LocalObject,
        *,
        key: str,
        kind: Literal["bundle", "receipt"],
        retain_until: datetime,
    ) -> ImmutableS3Object:
        _validate_key(key)
        checksum = base64.b64encode(bytes.fromhex(local.sha256)).decode("ascii")
        headers = {
            "content-length": str(local.size),
            "content-type": ("application/zip" if kind == "bundle" else "application/json"),
            "if-none-match": "*",
            "x-amz-checksum-sha256": checksum,
            "x-amz-sdk-checksum-algorithm": "SHA256",
            "x-amz-meta-autocontribute-kind": kind,
            "x-amz-meta-autocontribute-sha256": local.sha256,
            "x-amz-object-lock-mode": "COMPLIANCE",
            "x-amz-object-lock-retain-until-date": _iso8601(retain_until),
            "x-amz-server-side-encryption": "AES256",
        }
        with local.path.open("rb") as source:
            response = self._request(
                "PUT",
                key=key,
                headers=headers,
                body=source,
                payload_sha256=local.sha256,
                now=self._clock(),
                accepted_statuses={200, 412},
            )
        if response.status_code == 412:
            # Content-addressed keys make a retry safe.  A pre-existing latest version is adopted
            # only after every byte/retention acknowledgement below matches this exact request.
            return self.acknowledge(
                key=key,
                version_id=None,
                local=local,
                minimum_retain_until=retain_until,
                kind=kind,
            )

        version_id = _required_header(response, "x-amz-version-id")
        return self.acknowledge(
            key=key,
            version_id=version_id,
            local=local,
            minimum_retain_until=retain_until,
            kind=kind,
        )

    def acknowledge(
        self,
        *,
        key: str,
        version_id: str | None,
        local: _LocalObject,
        minimum_retain_until: datetime,
        kind: Literal["bundle", "receipt"],
    ) -> ImmutableS3Object:
        query = () if version_id is None else (("versionId", version_id),)
        response = self._request(
            "HEAD",
            key=key,
            query=query,
            headers={"x-amz-checksum-mode": "ENABLED"},
            now=self._clock(),
        )
        acknowledged_version = _required_header(response, "x-amz-version-id")
        if version_id is not None and acknowledged_version != version_id:
            raise StateError("S3 acknowledged a different immutable object version")
        if _required_int_header(response, "content-length") != local.size:
            raise StateError("S3 acknowledged a different replica byte size")
        expected_checksum = base64.b64encode(bytes.fromhex(local.sha256)).decode("ascii")
        if _required_header(response, "x-amz-checksum-sha256") != expected_checksum:
            raise StateError("S3 acknowledged a different replica SHA-256 checksum")
        if _required_header(response, "x-amz-meta-autocontribute-sha256") != local.sha256:
            raise StateError("S3 replica metadata does not bind the local SHA-256 digest")
        if _required_header(response, "x-amz-meta-autocontribute-kind") != kind:
            raise StateError("S3 replica metadata has the wrong object kind")
        if _required_header(response, "x-amz-object-lock-mode") != "COMPLIANCE":
            raise StateError("S3 replica is not protected by compliance-mode Object Lock")
        if _required_header(response, "x-amz-server-side-encryption") != "AES256":
            raise StateError("S3 replica did not acknowledge required server-side encryption")
        retain_until = _retention_header(response)
        if retain_until < minimum_retain_until:
            raise StateError("S3 replica retention is shorter than requested")
        if retain_until <= self._clock():
            raise StateError("S3 replica retention has already expired")
        return ImmutableS3Object(
            bucket=self.bucket,
            bucket_owner_account_id=self.expected_bucket_owner,
            region=self.region,
            key=key,
            version_id=acknowledged_version,
            retain_until=retain_until,
            size=local.size,
            sha256=local.sha256,
        )

    def read_exact_version(
        self,
        stored: ImmutableS3Object,
        destination: Path,
        *,
        maximum_bytes: int,
    ) -> _LocalObject:
        with self._stream(
            "GET",
            key=stored.key,
            query=(("versionId", stored.version_id),),
            headers={"x-amz-checksum-mode": "ENABLED"},
            now=self._clock(),
        ) as (headers, response):
            if _required_mapping_header(headers, "x-amz-version-id") != stored.version_id:
                raise StateError("S3 read-back returned a different immutable object version")
            if _required_mapping_header(headers, "x-amz-object-lock-mode") != "COMPLIANCE":
                raise StateError("S3 read-back lost compliance-mode retention evidence")
            retain_until = _parse_retention(
                _required_mapping_header(headers, "x-amz-object-lock-retain-until-date")
            )
            if retain_until != stored.retain_until:
                raise StateError("S3 read-back retention differs from its acknowledgement")
            expected_checksum = base64.b64encode(bytes.fromhex(stored.sha256)).decode("ascii")
            if _required_mapping_header(headers, "x-amz-checksum-sha256") != expected_checksum:
                raise StateError("S3 read-back checksum header differs from its acknowledgement")

            digest = hashlib.sha256()
            copied = 0
            try:
                with destination.open("xb") as output:
                    for chunk in response.iter_bytes(_COPY_CHUNK_BYTES):
                        copied += len(chunk)
                        if copied > maximum_bytes:
                            raise StateError("S3 read-back exceeds the safe object size limit")
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except OSError as exc:
                with suppress(OSError):
                    destination.unlink(missing_ok=True)
                raise StateError("Could not persist S3 read-back in scratch storage") from exc
            if copied != stored.size or digest.hexdigest() != stored.sha256:
                raise StateError("S3 read-back bytes differ from the immutable acknowledgement")
            return _LocalObject(path=destination, size=copied, sha256=digest.hexdigest())

    def _request(
        self,
        method: str,
        *,
        key: str | None,
        now: datetime,
        query: tuple[tuple[str, str], ...] = (),
        headers: Mapping[str, str] | None = None,
        body: bytes | Iterable[bytes] = b"",
        payload_sha256: str | None = None,
        accepted_statuses: set[int] | None = None,
    ) -> httpx.Response:
        url, signed_headers = self._signed_request(
            method,
            key=key,
            query=query,
            headers=headers,
            payload_sha256=payload_sha256 or hashlib.sha256(b"").hexdigest(),
            now=now,
        )
        try:
            with self._client.stream(
                method,
                url,
                headers=signed_headers,
                content=body,
            ) as streamed:
                response = httpx.Response(
                    streamed.status_code,
                    headers=streamed.headers,
                    content=_read_bounded_control_response(streamed),
                    request=streamed.request,
                )
        except httpx.HTTPError as exc:
            raise StateError(f"S3 replication request failed: {type(exc).__name__}") from exc
        allowed = accepted_statuses or set(range(200, 300))
        if response.status_code not in allowed:
            error_code = _safe_s3_error_code(response.content)
            suffix = f" ({error_code})" if error_code else ""
            raise StateError(f"S3 replication request returned HTTP {response.status_code}{suffix}")
        return response

    @contextmanager
    def _stream(
        self,
        method: str,
        *,
        key: str,
        now: datetime,
        query: tuple[tuple[str, str], ...],
        headers: Mapping[str, str] | None = None,
    ) -> Iterator[tuple[httpx.Headers, httpx.Response]]:
        url, signed_headers = self._signed_request(
            method,
            key=key,
            query=query,
            headers=headers,
            payload_sha256=hashlib.sha256(b"").hexdigest(),
            now=now,
        )
        try:
            with self._client.stream(method, url, headers=signed_headers) as response:
                if response.status_code < 200 or response.status_code >= 300:
                    error_content = _read_bounded_control_response(response)
                    error_code = _safe_s3_error_code(error_content)
                    suffix = f" ({error_code})" if error_code else ""
                    raise StateError(
                        f"S3 read-back request returned HTTP {response.status_code}{suffix}"
                    )
                yield response.headers, response
        except httpx.HTTPError as exc:
            raise StateError(f"S3 read-back request failed: {type(exc).__name__}") from exc

    def _signed_request(
        self,
        method: str,
        *,
        key: str | None,
        query: tuple[tuple[str, str], ...],
        headers: Mapping[str, str] | None,
        payload_sha256: str,
        now: datetime,
    ) -> tuple[str, dict[str, str]]:
        timestamp = now.astimezone(UTC)
        amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
        date = timestamp.strftime("%Y%m%d")
        canonical_uri = "/" if key is None else f"/{quote(key, safe='/-_.~')}"
        canonical_query = urlencode(
            sorted(query),
            doseq=True,
            safe="-_.~",
            quote_via=quote,
        )
        request_headers = {key.lower(): value for key, value in (headers or {}).items()}
        request_headers.update(
            {
                "host": self._host,
                "x-amz-content-sha256": payload_sha256,
                "x-amz-date": amz_date,
                "x-amz-expected-bucket-owner": self.expected_bucket_owner,
            }
        )
        if self._credentials.session_token is not None:
            request_headers["x-amz-security-token"] = self._credentials.session_token
        canonical_headers = "".join(
            f"{name}:{_normalize_header(value)}\n"
            for name, value in sorted(request_headers.items())
        )
        signed_header_names = ";".join(sorted(request_headers))
        canonical_request = "\n".join(
            (
                method,
                canonical_uri,
                canonical_query,
                canonical_headers,
                signed_header_names,
                payload_sha256,
            )
        )
        scope = f"{date}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            )
        )
        signing_key = _signature_key(self._credentials.secret_access_key, date, self.region)
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        request_headers["authorization"] = (
            "AWS4-HMAC-SHA256 "
            f"Credential={self._credentials.access_key_id}/{scope}, "
            f"SignedHeaders={signed_header_names}, Signature={signature}"
        )
        query_suffix = f"?{canonical_query}" if query else ""
        return f"https://{self._host}{canonical_uri}{query_suffix}", request_headers


def select_next_state_bundle_for_s3(
    *,
    bundle_directory: Path,
    receipt_directory: Path,
    bucket: str,
    expected_bucket_owner: str,
    region: str,
    prefix: str,
) -> PendingStateBundleReplication | None:
    """Return the oldest exact production bundle without valid local S3 evidence.

    Receipt presence alone never makes a bundle eligible to skip.  Every existing expected receipt
    is parsed, checked against the configured S3 boundary, and compared to a SHA-256 digest read
    safely from that exact local bundle.
    """

    _validate_replication_boundary(
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
        region=region,
        prefix=prefix,
    )
    receipt_root = _trusted_local_directory(receipt_directory, label="S3 receipt directory")
    candidates, bundle_snapshot = _local_bundle_inventory(
        bundle_directory,
        receipt_root=receipt_root,
    )
    for candidate in candidates:
        if _path_entry_exists(candidate.record_path):
            _verify_local_replication_record(
                candidate,
                bucket=bucket,
                expected_bucket_owner=expected_bucket_owner,
                region=region,
                prefix=prefix,
            )
            continue
        _assert_directory_unchanged(bundle_snapshot, label="S3 bundle directory")
        return PendingStateBundleReplication(
            bundle_path=candidate.path,
            record_path=candidate.record_path,
        )
    _assert_directory_unchanged(bundle_snapshot, label="S3 bundle directory")
    return None


def verify_latest_state_bundle_replication(
    *,
    bundle_directory: Path,
    receipt_directory: Path,
    bucket: str,
    expected_bucket_owner: str,
    region: str,
    prefix: str,
    maximum_age: timedelta | None = None,
    minimum_retention: timedelta | None = None,
    required_after: Path | None = None,
    now: datetime | None = None,
) -> VerifiedStateBundleReplication:
    """Prove that the newest exact local bundle has matching immutable S3 evidence."""

    _validate_replication_boundary(
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
        region=region,
        prefix=prefix,
    )
    if maximum_age is not None and (
        maximum_age <= timedelta(0) or maximum_age > timedelta(days=365)
    ):
        raise StateError("S3 replication maximum age must be between 1 second and 365 days")
    if minimum_retention is not None and (
        minimum_retention <= timedelta(0) or minimum_retention > timedelta(days=3_650)
    ):
        raise StateError("S3 replication minimum retention must be between 1 second and 3,650 days")
    receipt_root = _trusted_local_directory(receipt_directory, label="S3 receipt directory")
    candidates, bundle_snapshot = _local_bundle_inventory(
        bundle_directory,
        receipt_root=receipt_root,
    )
    if not candidates:
        raise StateError("No exact complete state bundles are available for S3 verification")
    candidate = candidates[-1]
    verified, receipt_metadata = _verify_local_replication_record(
        candidate,
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
        region=region,
        prefix=prefix,
    )
    operation_time = (now or datetime.now(UTC)).astimezone(UTC)
    receipt = verified.record.receipt
    if receipt.bundle.retain_until <= operation_time:
        raise StateError("The latest S3 bundle compliance lock has expired")
    if verified.record.receipt_object.retain_until <= operation_time:
        raise StateError("The latest S3 receipt compliance lock has expired")
    if minimum_retention is not None:
        bound_interval = receipt.minimum_retain_until - receipt.retention_requested_at
        if bound_interval < minimum_retention:
            raise StateError(
                "The latest S3 replication receipt binds a shorter retention policy than configured"
            )
    operation_ns = int(operation_time.timestamp() * 1_000_000_000)
    for label, modified_ns in (
        ("latest complete state bundle", candidate.modified_ns),
        ("latest S3 replication receipt", receipt_metadata.st_mtime_ns),
    ):
        if modified_ns > operation_ns + _FUTURE_MTIME_TOLERANCE_NS:
            raise StateError(f"The {label} has an unsafe future modification time")
        if maximum_age is not None:
            maximum_age_ns = int(maximum_age.total_seconds() * 1_000_000_000)
            if modified_ns < operation_ns - maximum_age_ns:
                raise StateError(f"The {label} is older than the allowed replication age")
    if required_after is not None:
        marker_modified_ns = _trusted_marker_mtime(required_after)
        if candidate.modified_ns <= marker_modified_ns:
            raise StateError(
                "The latest complete state bundle is not unambiguously newer than the "
                "required-after marker"
            )
        if receipt_metadata.st_mtime_ns <= marker_modified_ns:
            raise StateError(
                "The latest S3 replication receipt is not unambiguously newer than the "
                "required-after marker"
            )
    _assert_directory_unchanged(bundle_snapshot, label="S3 bundle directory")
    return verified


def prune_replicated_state_bundles(
    *,
    bundle_directory: Path,
    receipt_directory: Path,
    bucket: str,
    expected_bucket_owner: str,
    region: str,
    prefix: str,
    keep: int,
) -> StateBundlePruneReport:
    """Delete old local bundles only after proving their exact immutable S3 evidence.

    The newest ``keep`` exact complete bundles always survive, replicated or not.  An
    older bundle is deleted together with its local receipt only when that receipt binds
    the bundle's exact bytes to the configured S3 boundary; an older bundle without a
    receipt is preserved for replication and reported as pending instead.
    """

    if not 1 <= keep <= 1_000:
        raise StateError("Local bundle retention must keep between 1 and 1,000 bundles")
    _validate_replication_boundary(
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
        region=region,
        prefix=prefix,
    )
    receipt_root = _trusted_local_directory(receipt_directory, label="S3 receipt directory")
    candidates, _ = _local_bundle_inventory(bundle_directory, receipt_root=receipt_root)
    prunable = candidates[:-keep]
    deleted: list[Path] = []
    pending: list[Path] = []
    for candidate in prunable:
        if not _path_entry_exists(candidate.record_path):
            pending.append(candidate.path)
            continue
        _verify_local_replication_record(
            candidate,
            bucket=bucket,
            expected_bucket_owner=expected_bucket_owner,
            region=region,
            prefix=prefix,
        )
        try:
            current = os.stat(candidate.path, follow_symlinks=False)
        except OSError as exc:
            raise StateError("S3 bundle entry changed after inventory") from exc
        _require_candidate_identity(candidate, current)
        try:
            os.unlink(candidate.path)
            os.unlink(candidate.record_path)
        except OSError as exc:
            raise StateError("A replicated local state bundle could not be deleted") from exc
        deleted.append(candidate.path)
    return StateBundlePruneReport(
        kept=tuple(candidate.path for candidate in candidates[len(prunable) :]),
        deleted=tuple(deleted),
        pending_replication=tuple(pending),
    )


def replicate_state_bundle_to_s3(
    source: Path,
    *,
    bucket: str,
    expected_bucket_owner: str,
    region: str,
    retention_period: timedelta,
    scratch_directory: Path,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None = None,
    prefix: str = "autocontribute",
    record_destination: Path | None = None,
    timeout_seconds: float = 21_600,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> BackupReplicationRecord:
    """Replicate, independently read back, and receipt one complete state bundle.

    Success means the exact bundle version and its receipt are both compliance-locked, were read
    back by immutable version ID, and matched their local SHA-256 digests.  A failed attempt never
    deletes a remote object or a local generation, and an existing local record is never replaced.
    """

    operation_time = (now or datetime.now(UTC)).astimezone(UTC)
    if not isinstance(retention_period, timedelta):
        raise StateError("S3 retention period must be a duration")
    if retention_period <= timedelta(0) or retention_period > timedelta(days=3_650):
        raise StateError("S3 retention period must be between 1 second and 3,650 days")
    requested_retention = _ceil_utc_second(operation_time + retention_period)
    source_filename = _validate_source_filename(source.name)
    _validate_prefix(prefix)
    if record_destination is not None:
        _validate_record_destination(record_destination)
    if not math.isfinite(timeout_seconds) or timeout_seconds < 10 or timeout_seconds > 86_400:
        raise StateError("S3 replication timeout must be between 10 and 86,400 seconds")
    scratch_root, source_size = _validate_scratch_directory(scratch_directory, source)
    _require_scratch_capacity(
        scratch_root,
        required_bytes=(2 * source_size) + _MAX_RESTORED_BUNDLE_BYTES + _SCRATCH_RESERVE_BYTES,
    )

    owned_client = client is None
    transport = client or httpx.Client(
        timeout=httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 30.0)),
        follow_redirects=False,
    )
    credentials = _Credentials(
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
    )
    s3 = _S3ObjectLockClient(
        bucket=bucket,
        expected_bucket_owner=expected_bucket_owner,
        region=region,
        credentials=credentials,
        client=transport,
        clock=(lambda: now.astimezone(UTC)) if now is not None else (lambda: datetime.now(UTC)),
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix="autocontribute-replication-",
            dir=scratch_root,
        ) as temporary_name:
            temporary = Path(temporary_name)
            frozen = _freeze_local_bundle(source, temporary / "source.bundle.zip")
            _require_scratch_capacity(
                scratch_root,
                required_bytes=(frozen.size + _MAX_RESTORED_BUNDLE_BYTES + _SCRATCH_RESERVE_BYTES),
            )
            _verify_complete_bundle(frozen.path, temporary / "source-verification")
            s3.verify_bucket_boundary()

            retention_key = requested_retention.strftime("%Y%m%dT%H%M%SZ")
            bundle_key = (
                f"{prefix}/bundles/sha256/{frozen.sha256}/retain-until-{retention_key}.bundle.zip"
            )
            bundle_object = s3.put_immutable(
                frozen,
                key=bundle_key,
                kind="bundle",
                retain_until=requested_retention,
            )
            bundle_read_back = s3.read_exact_version(
                bundle_object,
                temporary / "bundle.read-back.zip",
                maximum_bytes=_MAX_BUNDLE_BYTES,
            )
            _verify_complete_bundle(
                bundle_read_back.path,
                temporary / "read-back-verification",
            )
            bundle_verified_at = (now or datetime.now(UTC)).astimezone(UTC)
            receipt = BackupReplicaReceipt(
                created_at=bundle_verified_at,
                retention_requested_at=operation_time,
                minimum_retain_until=requested_retention,
                source_filename=source_filename,
                bundle=bundle_object,
                read_back=ReplicaReadBack(
                    verified_at=bundle_verified_at,
                    size=bundle_read_back.size,
                    sha256=bundle_read_back.sha256,
                    complete_bundle_verified=True,
                ),
            )
            receipt_bytes = (receipt.model_dump_json(indent=2) + "\n").encode()
            if len(receipt_bytes) > _MAX_RECEIPT_BYTES:
                raise StateError("Backup replication receipt exceeds the safe size limit")
            receipt_path = temporary / "receipt.json"
            receipt_path.write_bytes(receipt_bytes)
            receipt_digest = hashlib.sha256(receipt_bytes).hexdigest()
            receipt_local = _LocalObject(
                path=receipt_path,
                size=len(receipt_bytes),
                sha256=receipt_digest,
            )
            receipt_key = f"{prefix}/receipts/sha256/{receipt_digest}.json"
            receipt_object = s3.put_immutable(
                receipt_local,
                key=receipt_key,
                kind="receipt",
                retain_until=bundle_object.retain_until,
            )
            receipt_read_back_local = s3.read_exact_version(
                receipt_object,
                temporary / "receipt.read-back.json",
                maximum_bytes=_MAX_RECEIPT_BYTES,
            )
            try:
                parsed_receipt = BackupReplicaReceipt.model_validate_json(
                    receipt_read_back_local.path.read_bytes()
                )
            except (OSError, ValueError) as exc:
                raise StateError("Off-host backup receipt read-back is invalid") from exc
            if parsed_receipt != receipt:
                raise StateError("Off-host backup receipt read-back changed its evidence")
            record_time = (now or datetime.now(UTC)).astimezone(UTC)
            record = BackupReplicationRecord(
                created_at=record_time,
                receipt_sha256=receipt_digest,
                receipt=receipt,
                receipt_object=receipt_object,
                receipt_read_back=ReplicaReadBack(
                    verified_at=record_time,
                    size=receipt_read_back_local.size,
                    sha256=receipt_read_back_local.sha256,
                    complete_bundle_verified=False,
                ),
            )
            if record_destination is not None:
                write_backup_replication_record(record, record_destination)
            return record
    except StateError:
        raise
    except (OSError, ValueError) as exc:
        raise StateError("Could not stage S3 backup replication safely") from exc
    finally:
        if owned_client:
            transport.close()


def write_backup_replication_record(
    record: BackupReplicationRecord,
    destination: Path,
) -> Path:
    """Publish a local receipt locator exactly once; never replace existing evidence."""

    validated = _validate_record_destination(destination)
    target = validated.path
    staging_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    staging_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = -1
    descriptor = -1
    staging_name: str | None = None
    staging_created = False
    published = False
    try:
        parent_descriptor = os.open(target.parent, directory_flags)
        parent_metadata = os.fstat(parent_descriptor)
        if (parent_metadata.st_dev, parent_metadata.st_ino) != (
            validated.parent_device,
            validated.parent_inode,
        ):
            raise StateError("Backup replication record parent changed during creation")
        _validate_trusted_directory_metadata(
            parent_metadata,
            label="Backup replication record parent",
        )
        for _ in range(16):
            candidate = f".autocontribute-replication-record-{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    staging_flags,
                    0o400,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            staging_name = candidate
            staging_created = True
            break
        else:
            raise StateError(
                "Could not allocate an exclusive backup replication record staging file"
            )
        os.fchmod(descriptor, 0o400)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write((record.model_dump_json(indent=2) + "\n").encode())
            output.flush()
            os.fsync(output.fileno())
        assert staging_name is not None
        os.link(
            staging_name,
            target.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published = True
        os.unlink(staging_name, dir_fd=parent_descriptor)
        staging_created = False
        os.fsync(parent_descriptor)
        return target
    except FileExistsError as exc:
        try:
            if staging_created and staging_name is not None:
                os.unlink(staging_name, dir_fd=parent_descriptor)
                staging_created = False
                os.fsync(parent_descriptor)
        except OSError as cleanup_exc:
            raise StateError(
                "Backup replication record destination appeared and staging cleanup failed"
            ) from cleanup_exc
        raise StateError(
            "Backup replication record destination appeared during publication"
        ) from exc
    except OSError as exc:
        removed_entry = False
        try:
            if published:
                os.unlink(target.name, dir_fd=parent_descriptor)
                published = False
                removed_entry = True
            if staging_created and staging_name is not None:
                os.unlink(staging_name, dir_fd=parent_descriptor)
                staging_created = False
                removed_entry = True
            if removed_entry:
                os.fsync(parent_descriptor)
        except OSError as cleanup_exc:
            raise StateError(
                "Could not persist or durably remove the backup replication record"
            ) from cleanup_exc
        raise StateError(f"Could not persist backup replication record: {exc}") from exc
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if staging_created and staging_name is not None and parent_descriptor >= 0:
            with suppress(OSError):
                os.unlink(staging_name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
        if parent_descriptor >= 0:
            with suppress(OSError):
                os.close(parent_descriptor)


def _validate_replication_boundary(
    *,
    bucket: str,
    expected_bucket_owner: str,
    region: str,
    prefix: str,
) -> None:
    _validate_bucket(bucket)
    _validate_expected_bucket_owner(expected_bucket_owner)
    _validate_region(region)
    _validate_prefix(prefix)


def _trusted_local_directory(directory: Path, *, label: str) -> Path:
    requested = directory.expanduser()
    if requested.is_symlink():
        raise StateError(f"{label} cannot be a symbolic link")
    try:
        root = requested.resolve(strict=True)
        metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise StateError(f"{label} is unavailable") from exc
    _validate_trusted_directory_metadata(metadata, label=label)
    return root


def _local_bundle_inventory(
    bundle_directory: Path,
    *,
    receipt_root: Path,
) -> tuple[list[_BundleCandidate], _DirectorySnapshot]:
    root = _trusted_local_directory(bundle_directory, label="S3 bundle directory")
    try:
        root_metadata = root.stat(follow_symlinks=False)
        candidates: list[_BundleCandidate] = []
        entries = 0
        with os.scandir(root) as directory_entries:
            for entry in directory_entries:
                entries += 1
                if entries > _MAX_LOCAL_DIRECTORY_ENTRIES:
                    raise StateError("S3 bundle directory exceeds the safe entry limit")
                name = entry.name
                resembles_bundle = name.startswith(_LOCAL_BUNDLE_PREFIX) or name.endswith(
                    _LOCAL_BUNDLE_SUFFIX
                )
                match = _LOCAL_BUNDLE.fullmatch(name)
                if match is None:
                    if resembles_bundle:
                        raise StateError("S3 bundle directory contains an unsafe bundle filename")
                    continue
                if not _is_safe_source_filename(name):
                    raise StateError("S3 bundle directory contains an unsafe bundle filename")
                try:
                    second = datetime.strptime(match.group("second"), "%Y%m%dT%H%M%S").replace(
                        tzinfo=UTC
                    )
                    nanosecond = int(match.group("nanosecond"))
                    process_id = int(match.group("pid"))
                except (ValueError, OverflowError) as exc:
                    raise StateError(
                        "S3 bundle directory contains an invalid bundle timestamp"
                    ) from exc
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise StateError("S3 bundle entry changed during inventory") from exc
                _validate_local_evidence_file(
                    metadata,
                    label="S3 bundle entry",
                    maximum_bytes=_MAX_BUNDLE_BYTES,
                )
                record_name = f"{name}{_LOCAL_RECEIPT_SUFFIX}"
                if not _is_safe_source_filename(record_name):
                    raise StateError("S3 receipt filename derived from a bundle is unsafe")
                candidates.append(
                    _BundleCandidate(
                        path=root / name,
                        record_path=receipt_root / record_name,
                        order=(second, nanosecond, process_id, name),
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                        size=metadata.st_size,
                        modified_ns=metadata.st_mtime_ns,
                        changed_ns=metadata.st_ctime_ns,
                        mode=metadata.st_mode,
                        links=metadata.st_nlink,
                        owner=metadata.st_uid,
                    )
                )
    except StateError:
        raise
    except OSError as exc:
        raise StateError("Could not inventory the S3 bundle directory safely") from exc
    candidates.sort(key=lambda candidate: candidate.order)
    return candidates, _directory_snapshot(root, root_metadata)


def _directory_snapshot(root: Path, metadata: os.stat_result) -> _DirectorySnapshot:
    return _DirectorySnapshot(
        path=root,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _assert_directory_unchanged(snapshot: _DirectorySnapshot, *, label: str) -> None:
    try:
        metadata = snapshot.path.stat(follow_symlinks=False)
    except OSError as exc:
        raise StateError(f"{label} changed during verification") from exc
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ) != (
        snapshot.device,
        snapshot.inode,
        snapshot.modified_ns,
        snapshot.changed_ns,
    ):
        raise StateError(f"{label} changed during verification")


def _path_entry_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise StateError("S3 replication receipt availability could not be determined") from exc
    return True


def _verify_local_replication_record(
    candidate: _BundleCandidate,
    *,
    bucket: str,
    expected_bucket_owner: str,
    region: str,
    prefix: str,
) -> tuple[VerifiedStateBundleReplication, os.stat_result]:
    receipt_bytes, receipt_metadata = _read_exact_local_file(
        candidate.record_path,
        label="S3 replication receipt",
        maximum_bytes=_MAX_RECEIPT_BYTES,
    )
    try:
        raw_record = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateError("Local S3 replication receipt is invalid") from exc
    if isinstance(raw_record, dict) and raw_record.get("schema_version") == 1:
        raise StateError(
            "Local S3 replication receipt uses a legacy schema without retention-policy evidence"
        )
    try:
        record = BackupReplicationRecord.model_validate(raw_record)
    except ValueError as exc:
        raise StateError("Local S3 replication receipt is invalid") from exc
    bundle_size, bundle_sha256 = _digest_local_bundle(candidate)
    remote_bundle = record.receipt.bundle
    if record.receipt.source_filename != candidate.path.name:
        raise StateError("Local S3 replication receipt names a different source bundle")
    if (remote_bundle.size, remote_bundle.sha256) != (bundle_size, bundle_sha256):
        raise StateError("Local S3 replication receipt does not bind the exact bundle bytes")
    if (
        remote_bundle.bucket,
        remote_bundle.bucket_owner_account_id,
        remote_bundle.region,
    ) != (bucket, expected_bucket_owner, region):
        raise StateError("Local S3 replication receipt is outside the configured bucket boundary")
    retention_key = remote_bundle.retain_until.strftime("%Y%m%dT%H%M%SZ")
    expected_bundle_key = (
        f"{prefix}/bundles/sha256/{bundle_sha256}/retain-until-{retention_key}.bundle.zip"
    )
    expected_receipt_key = f"{prefix}/receipts/sha256/{record.receipt_sha256}.json"
    if remote_bundle.key != expected_bundle_key:
        raise StateError("Local S3 replication receipt names an unexpected bundle object key")
    if record.receipt_object.key != expected_receipt_key:
        raise StateError("Local S3 replication receipt names an unexpected receipt object key")
    verified = VerifiedStateBundleReplication(
        bundle_path=candidate.path,
        record_path=candidate.record_path,
        record=record,
    )
    return verified, receipt_metadata


def _digest_local_bundle(candidate: _BundleCandidate) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate.path, flags)
    except OSError as exc:
        raise StateError("S3 bundle entry cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        _validate_local_evidence_file(
            before,
            label="S3 bundle entry",
            maximum_bytes=_MAX_BUNDLE_BYTES,
        )
        _require_candidate_identity(candidate, before)
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(os.dup(descriptor), "rb") as input_file:
            while chunk := input_file.read(_COPY_CHUNK_BYTES):
                copied += len(chunk)
                if copied > _MAX_BUNDLE_BYTES:
                    raise StateError("S3 bundle entry exceeds the safe bundle size limit")
                digest.update(chunk)
        after = os.fstat(descriptor)
        _require_unchanged_file(before, after, label="S3 bundle entry")
        if copied != before.st_size:
            raise StateError("S3 bundle entry changed while its digest was computed")
        return copied, digest.hexdigest()
    finally:
        os.close(descriptor)


def _require_candidate_identity(candidate: _BundleCandidate, metadata: os.stat_result) -> None:
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
    ) != (
        candidate.device,
        candidate.inode,
        candidate.size,
        candidate.modified_ns,
        candidate.changed_ns,
        candidate.mode,
        candidate.links,
        candidate.owner,
    ):
        raise StateError("S3 bundle entry changed after inventory")


def _read_exact_local_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StateError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        _validate_local_evidence_file(before, label=label, maximum_bytes=maximum_bytes)
        with os.fdopen(os.dup(descriptor), "rb") as input_file:
            content = input_file.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise StateError(f"{label} exceeds the safe size limit")
        after = os.fstat(descriptor)
        _require_unchanged_file(before, after, label=label)
        if len(content) != before.st_size:
            raise StateError(f"{label} changed while it was read")
        return content, before
    finally:
        os.close(descriptor)


def _validate_local_evidence_file(
    metadata: os.stat_result,
    *,
    label: str,
    maximum_bytes: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise StateError(f"{label} must be a regular file, not a symbolic link or special file")
    if metadata.st_uid != os.geteuid():
        raise StateError(f"{label} must be owned by the replication identity")
    if stat.S_IMODE(metadata.st_mode) != 0o400:
        raise StateError(f"{label} must have exact mode 0400")
    if metadata.st_nlink != 1:
        raise StateError(f"{label} cannot have multiple hard links")
    if metadata.st_size < 0 or metadata.st_size > maximum_bytes:
        raise StateError(f"{label} exceeds the safe size limit")


def _require_unchanged_file(
    before: os.stat_result,
    after: os.stat_result,
    *,
    label: str,
) -> None:
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
        before.st_nlink,
        before.st_uid,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
        after.st_nlink,
        after.st_uid,
    ):
        raise StateError(f"{label} changed while it was read")


def _trusted_marker_mtime(path: Path) -> int:
    requested = path.expanduser()
    if (
        not requested.name
        or not _has_bounded_utf8_size(requested.name, maximum_bytes=255)
        or any(not character.isprintable() for character in requested.name)
    ):
        raise StateError("Required-after marker filename is unsafe")
    if requested.is_symlink() or requested.parent.is_symlink():
        raise StateError("Required-after marker cannot be a symbolic link")
    parent = _trusted_local_directory(requested.parent, label="Required-after marker parent")
    marker = parent / requested.name
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker, flags)
    except OSError as exc:
        raise StateError("Required-after marker is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StateError("Required-after marker must be a regular file")
        if before.st_uid != os.geteuid():
            raise StateError("Required-after marker must be owned by the replication identity")
        if stat.S_IMODE(before.st_mode) & 0o022:
            raise StateError("Required-after marker cannot be writable by group or other users")
        if before.st_nlink != 1:
            raise StateError("Required-after marker cannot have multiple hard links")
        if before.st_size > _MARKER_MAX_BYTES:
            raise StateError("Required-after marker exceeds the safe size limit")
        after = os.fstat(descriptor)
        _require_unchanged_file(before, after, label="Required-after marker")
        return before.st_mtime_ns
    finally:
        os.close(descriptor)


def _validate_record_destination(destination: Path) -> _ValidatedRecordDestination:
    requested = destination.expanduser()
    if (
        not requested.name
        or not _has_bounded_utf8_size(requested.name, maximum_bytes=255)
        or any(not character.isprintable() for character in requested.name)
    ):
        raise StateError("Backup replication record destination filename is unsafe")
    if requested.is_symlink() or requested.parent.is_symlink():
        raise StateError("Backup replication record destination cannot be a symbolic link")
    try:
        parent = requested.parent.resolve(strict=True)
        parent_metadata = parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise StateError(
            "Backup replication record parent must already exist and be available"
        ) from exc
    _validate_trusted_directory_metadata(
        parent_metadata,
        label="Backup replication record parent",
    )
    target = parent / requested.name
    if target.exists() or target.is_symlink():
        raise StateError("Backup replication record destination already exists")
    return _ValidatedRecordDestination(
        path=target,
        parent_device=parent_metadata.st_dev,
        parent_inode=parent_metadata.st_ino,
    )


def _freeze_local_bundle(source: Path, destination: Path) -> _LocalObject:
    requested = source.expanduser()
    if requested.is_symlink():
        raise StateError("Backup replication source cannot be a symbolic link")
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise StateError(f"Backup replication source is unavailable: {exc}") from exc
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise StateError(f"Backup replication source cannot be opened safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise StateError("Backup replication source must be a regular file")
        if before.st_size > _MAX_BUNDLE_BYTES:
            raise StateError("Backup replication source exceeds the safe bundle size limit")
        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(os.dup(descriptor), "rb") as input_file, destination.open("xb") as output:
            while chunk := input_file.read(_COPY_CHUNK_BYTES):
                copied += len(chunk)
                if copied > _MAX_BUNDLE_BYTES:
                    raise StateError("Backup replication source exceeds the safe bundle size limit")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(descriptor)
        if copied != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise StateError("Backup replication source changed while it was being frozen")
        os.chmod(destination, 0o400)
        return _LocalObject(path=destination, size=copied, sha256=digest.hexdigest())
    except StateError:
        destination.unlink(missing_ok=True)
        raise
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise StateError(f"Could not freeze backup replication source: {exc}") from exc
    finally:
        os.close(descriptor)


def _verify_complete_bundle(source: Path, target: Path) -> None:
    try:
        restore_state_bundle(target, source)
    finally:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)


def _validate_source_filename(value: str) -> str:
    if not _is_safe_source_filename(value):
        raise StateError("Backup replication source filename is unsafe")
    return value


def _is_safe_source_filename(value: str) -> bool:
    return bool(
        value
        and value == Path(value).name
        and _has_bounded_utf8_size(value, maximum_bytes=255)
        and all(character.isprintable() for character in value)
    )


def _has_bounded_utf8_size(value: str, *, maximum_bytes: int) -> bool:
    try:
        return len(value.encode("utf-8")) <= maximum_bytes
    except UnicodeEncodeError:
        return False


def _validate_scratch_directory(directory: Path, source: Path) -> tuple[Path, int]:
    requested = directory.expanduser()
    if requested.is_symlink():
        raise StateError("S3 replication scratch directory cannot be a symbolic link")
    try:
        root = requested.resolve(strict=True)
        metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise StateError("S3 replication scratch directory is unavailable") from exc
    _validate_trusted_directory_metadata(metadata, label="S3 replication scratch directory")

    requested_source = source.expanduser()
    if requested_source.is_symlink():
        raise StateError("Backup replication source cannot be a symbolic link")
    try:
        resolved_source = requested_source.resolve(strict=True)
        source_metadata = resolved_source.stat(follow_symlinks=False)
    except OSError as exc:
        raise StateError("Backup replication source is unavailable") from exc
    if not stat.S_ISREG(source_metadata.st_mode):
        raise StateError("Backup replication source must be a regular file")
    if source_metadata.st_size > _MAX_BUNDLE_BYTES:
        raise StateError("Backup replication source exceeds the safe bundle size limit")
    return root, source_metadata.st_size


def _validate_trusted_directory_metadata(metadata: os.stat_result, *, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise StateError(f"{label} must be a directory")
    if metadata.st_uid != os.geteuid():
        raise StateError(f"{label} must be owned by the replication identity")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise StateError(f"{label} cannot be writable by group or other users")


def _require_scratch_capacity(root: Path, *, required_bytes: int) -> None:
    try:
        free_bytes = shutil.disk_usage(root).free
    except OSError as exc:
        raise StateError("S3 replication scratch capacity is unavailable") from exc
    if free_bytes < required_bytes:
        raise StateError(
            "S3 replication scratch capacity is insufficient for two bundle copies, "
            "complete restore verification, and the safety reserve"
        )


def _validate_bucket(value: str) -> None:
    if not _BUCKET.fullmatch(value):
        raise StateError("S3 backup bucket must use a DNS-safe lowercase name without dots")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise StateError("S3 backup bucket cannot be formatted as an IP address")


def _validate_region(value: str) -> None:
    if not _STANDARD_AWS_REGION.fullmatch(value):
        raise StateError("AWS region must belong to the standard commercial AWS partition")


def _validate_expected_bucket_owner(value: str) -> None:
    if not _AWS_ACCOUNT_ID.fullmatch(value):
        raise StateError("Expected S3 bucket owner must be a 12-digit AWS account ID")


def _validate_prefix(value: str) -> None:
    if (
        not value
        or value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or not _has_bounded_utf8_size(value, maximum_bytes=700)
        or any(part in {"", ".", ".."} for part in PurePosixPath(value).parts)
        or any(not character.isprintable() or character == "\\" for character in value)
    ):
        raise StateError("S3 backup prefix is unsafe")


def _validate_key(value: str) -> None:
    if (
        not value
        or value.startswith("/")
        or "//" in value
        or not _has_bounded_utf8_size(value, maximum_bytes=1_024)
        or any(part in {"", ".", ".."} for part in PurePosixPath(value).parts)
        or any(not character.isprintable() or character == "\\" for character in value)
    ):
        raise StateError("S3 backup object key is unsafe")


def _signature_key(secret: str, date: str, region: str) -> bytes:
    date_key = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


def _normalize_header(value: str) -> str:
    if "\r" in value or "\n" in value:
        raise StateError("S3 request header contains an unsafe newline")
    return " ".join(value.strip().split())


def _xml_value(content: bytes, local_name: str) -> str | None:
    """Extract one fixed scalar without invoking an entity-capable XML parser."""

    if len(content) > _MAX_CONTROL_RESPONSE_BYTES:
        raise StateError("S3 returned an oversized bucket configuration response")
    folded = content.upper()
    if b"<!DOCTYPE" in folded or b"<!ENTITY" in folded:
        raise StateError("S3 returned unsafe bucket configuration declarations")
    encoded_name = re.escape(local_name.encode("ascii"))
    prefix = rb"(?:[A-Za-z_][A-Za-z0-9_.-]*:)?"
    pattern = re.compile(
        rb"<" + prefix + encoded_name + rb"\s*>([^<]{0,200})</" + prefix + encoded_name + rb"\s*>"
    )
    match = pattern.search(content)
    if match is None:
        return None
    try:
        return match.group(1).decode("ascii")
    except UnicodeDecodeError as exc:
        raise StateError("S3 returned a non-ASCII bucket configuration value") from exc


def _safe_s3_error_code(content: bytes) -> str | None:
    if len(content) > _MAX_RECEIPT_BYTES:
        return None
    folded = content.upper()
    if b"<!DOCTYPE" in folded or b"<!ENTITY" in folded:
        return None
    match = re.search(rb"<(?:[A-Za-z_][A-Za-z0-9_.-]*:)?Code\s*>([^<]{1,100})</", content)
    if match is None:
        return None
    try:
        value = match.group(1).decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if value and len(value) <= 100 and value.replace("-", "").isalnum():
        return value
    return None


def _read_bounded_control_response(response: httpx.Response) -> bytes:
    content = bytearray()
    for chunk in response.iter_bytes(_COPY_CHUNK_BYTES):
        content.extend(chunk)
        if len(content) > _MAX_CONTROL_RESPONSE_BYTES:
            raise StateError("S3 control response exceeds the safe size limit")
    return bytes(content)


def _required_header(response: httpx.Response, name: str) -> str:
    return _required_mapping_header(response.headers, name)


def _required_mapping_header(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    if (
        value is None
        or not value
        or len(value) > 4_096
        or any(character in value for character in "\r\n")
    ):
        raise StateError(f"S3 response is missing required {name} acknowledgement")
    return value


def _required_int_header(response: httpx.Response, name: str) -> int:
    value = _required_header(response, name)
    try:
        parsed = int(value)
    except ValueError as exc:
        raise StateError(f"S3 response has invalid {name} acknowledgement") from exc
    if parsed < 0:
        raise StateError(f"S3 response has invalid {name} acknowledgement")
    return parsed


def _retention_header(response: httpx.Response) -> datetime:
    return _parse_retention(_required_header(response, "x-amz-object-lock-retain-until-date"))


def _parse_retention(value: str) -> datetime:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise StateError("S3 returned an invalid Object Lock retention deadline") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StateError("S3 returned a timezone-free Object Lock retention deadline")
    return parsed.astimezone(UTC)


def _iso8601(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ceil_utc_second(value: datetime) -> datetime:
    normalized = value.astimezone(UTC)
    if normalized.microsecond:
        return normalized.replace(microsecond=0) + timedelta(seconds=1)
    return normalized


__all__ = [
    "BackupReplicaReceipt",
    "BackupReplicationRecord",
    "ImmutableS3Object",
    "PendingStateBundleReplication",
    "ReplicaReadBack",
    "StateBundlePruneReport",
    "VerifiedStateBundleReplication",
    "prune_replicated_state_bundles",
    "replicate_state_bundle_to_s3",
    "select_next_state_bundle_for_s3",
    "verify_latest_state_bundle_replication",
    "write_backup_replication_record",
]
