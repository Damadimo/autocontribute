"""Process coordination helpers built on the durable fenced-lease store."""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta
from types import TracebackType

from autocontribute.exceptions import StateError
from autocontribute.store import Lease, RunStore

PUBLICATION_LEASE_NAME = "autocontribute.publish"
PUBLICATION_LEASE_TTL = timedelta(minutes=15)
PUBLICATION_HEARTBEAT_INTERVAL = timedelta(minutes=1)


class LeaseHeartbeatGuard:
    """Own a fenced lease, renew it in the background, and surface ownership loss."""

    def __init__(
        self,
        store: RunStore,
        name: str,
        *,
        ttl: timedelta,
        heartbeat_interval: timedelta,
        owner: str | None = None,
    ) -> None:
        if not isinstance(ttl, timedelta):
            raise TypeError("lease ttl must be a timedelta")
        if not isinstance(heartbeat_interval, timedelta):
            raise TypeError("heartbeat interval must be a timedelta")
        if ttl <= timedelta(0):
            raise ValueError("lease ttl must be positive")
        if not timedelta(0) < heartbeat_interval < ttl:
            raise ValueError("heartbeat interval must be positive and shorter than the lease ttl")
        self._store = store
        self._name = name
        self._owner = owner or f"worker-{uuid.uuid4().hex}"
        self._ttl = ttl
        self._interval_seconds = heartbeat_interval.total_seconds()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._lease: Lease | None = None
        self._lost_reason: str | None = None

    @property
    def owner(self) -> str:
        return self._owner

    @property
    def lease(self) -> Lease:
        with self._lock:
            if self._lease is None:
                raise StateError(f"Lease {self._name} has not been acquired")
            return self._lease

    @property
    def generation(self) -> int:
        return self.lease.generation

    def __enter__(self) -> LeaseHeartbeatGuard:
        with self._lock:
            if self._lease is not None or self._thread is not None:
                raise StateError(f"Lease guard {self._name} is already active")
            self._lost_reason = None
            self._stop.clear()
        lease = self._store.acquire_lease(self._name, self._owner, ttl=self._ttl)
        if lease is None:
            raise StateError(f"Lease {self._name} is held by another worker")
        with self._lock:
            self._lease = lease
            self._thread = threading.Thread(
                target=self._heartbeat_loop,
                name="autocontribute-lease-heartbeat",
                daemon=True,
            )
            thread = self._thread
        thread.start()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except StateError:
            if exception_type is None:
                raise

    def assert_owned(self) -> Lease:
        """Fail closed at a work boundary if heartbeat or fencing ownership was lost."""

        with self._lock:
            lease = self._lease
            lost_reason = self._lost_reason
        if lease is None:
            raise StateError(f"Lease {self._name} is not active")
        if lost_reason is not None:
            raise StateError(lost_reason)
        try:
            current = self._store.assert_lease(
                self._name,
                self._owner,
                lease.generation,
            )
        except StateError:
            self._mark_lost(f"Lease {self._name} ownership was lost")
            raise
        with self._lock:
            self._lease = current
        return current

    def close(self) -> None:
        """Stop heartbeats and release only the generation this guard acquired."""

        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        with self._lock:
            lease = self._lease
            self._thread = None
            self._lease = None
            lost_reason = self._lost_reason
        if lease is None:
            return
        released = self._store.release_lease(
            self._name,
            self._owner,
            lease.generation,
        )
        if lost_reason is not None or not released:
            raise StateError(lost_reason or f"Lease {self._name} ownership was lost")

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            with self._lock:
                lease = self._lease
            if lease is None:
                return
            try:
                renewed = self._store.heartbeat_lease(
                    self._name,
                    self._owner,
                    lease.generation,
                    ttl=self._ttl,
                )
            except Exception:
                self._mark_lost(f"Lease {self._name} heartbeat failed")
                return
            if renewed is None:
                self._mark_lost(f"Lease {self._name} ownership was lost")
                return
            with self._lock:
                self._lease = renewed

    def _mark_lost(self, reason: str) -> None:
        with self._lock:
            if self._lost_reason is None:
                self._lost_reason = reason
        self._stop.set()


__all__ = [
    "PUBLICATION_HEARTBEAT_INTERVAL",
    "PUBLICATION_LEASE_NAME",
    "PUBLICATION_LEASE_TTL",
    "LeaseHeartbeatGuard",
]
