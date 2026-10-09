"""Additional bounded request holds for the manual HTTP menu experiment.

The original fixture and CLI behavior are unchanged. Construction of state is
pure; serve_http explicitly owns the same loopback-only, bounded HTTP transport.
Holds let the producer verify a live runtime before acquisition or cancel an
actual listing request. A hold is not application acceptance by itself.
"""
from contextlib import contextmanager
import importlib.util
import hashlib
from pathlib import Path
import select
import socket
import threading
import time

_PATH = Path(__file__).resolve().with_name("fixture_http.py")
_SPEC = importlib.util.spec_from_file_location("tui_base_http_fixture", _PATH)
F = importlib.util.module_from_spec(_SPEC)
_BASE_BYTES = _PATH.read_bytes()
exec(compile(_BASE_BYTES, str(_PATH), "exec"), F.__dict__)
F.loaded_source_sha256 = hashlib.sha256(_BASE_BYTES).hexdigest()
del _BASE_BYTES


class TuiHttpState(F.AppHttpState):
    def __init__(self, files, selected_member, *, cancel_download=False, cancel_listing=False):
        if (type(files) is not dict or type(selected_member) is not str or selected_member not in files or
                type(cancel_download) is not bool or type(cancel_listing) is not bool or
                (cancel_download and cancel_listing)):
            raise ValueError("input_invalid")
        super().__init__(files, "cancellation" if cancel_download else "baseline", cancel_member=selected_member)
        self.selected_member = selected_member
        self.cancel_listing = cancel_listing
        self._tui_original = (selected_member, cancel_listing)
        self.download_started = threading.Event()
        self.listing_started = threading.Event()
        self._download_release = threading.Event()
        self._listing_release = threading.Event()
        self.download_released = False
        self.listing_released = False
        self.listing_disconnected = False
        self.root_gets = 0
        self._download_claimed = False
        self._listing_claimed = False

    def source_preserved(self):
        return (super().source_preserved() and
                (self.selected_member, self.cancel_listing) == self._tui_original)

    def release_download(self):
        with self.lock:
            if not self.download_started.is_set() or self.download_released:
                raise ValueError("input_invalid")
            self.download_released = True
            self._download_release.set()

    def release_listing(self):
        with self.lock:
            if not self.listing_started.is_set() or self.listing_released:
                raise ValueError("input_invalid")
            self.listing_released = True
            self._listing_release.set()

    def snapshot(self):
        # The base method deliberately drops state.lock before reading the
        # transport lock. Preserve that order; transport callbacks take both.
        result = super().snapshot()
        with self.lock:
            result.update(download_started=self.download_started.is_set(),
                          download_released=self.download_released,
                          listing_started=self.listing_started.is_set(),
                          listing_released=self.listing_released,
                          listing_disconnected=self.listing_disconnected,
                          root_gets=self.root_gets)
            return result


class _TuiServer(F._Server):
    def _hold(self, sock, kind):
        state = self.state
        release = state._listing_release if kind == "listing" else state._download_release
        with self.lock:
            if sock not in self.sockets:
                raise F.FixtureError("socket_unowned")
            # Same existing suite lifetime cap as the original runtime hold.
            self.sockets[sock] = self.deadline
        while not release.is_set() and not self.stopping.is_set():
            if time.monotonic() >= self.deadline:
                raise F.FixtureError("lifetime_limit")
            ready, _, _ = select.select([sock], [], [], 0.05)
            if time.monotonic() >= self.deadline:
                raise F.FixtureError("lifetime_limit")
            if ready:
                try:
                    incoming = sock.recv(1, socket.MSG_PEEK)
                except ConnectionResetError:
                    incoming = b""
                if self.stopping.is_set():
                    return False
                if time.monotonic() >= self.deadline:
                    raise F.FixtureError("lifetime_limit")
                if incoming:
                    raise F.FixtureError("unexpected_input")
                if kind != "listing":
                    raise F.FixtureError("client_aborted")
                with state.lock:
                    state.listing_disconnected = True
                state._event("listing_disconnected")
                return False
        if self.stopping.is_set():
            return False
        if time.monotonic() >= self.deadline:
            raise F.FixtureError("lifetime_limit")
        with self.lock:
            if sock not in self.sockets:
                raise F.FixtureError("socket_unowned")
            self.sockets[sock] = min(self.deadline, time.monotonic() + F.REQUEST_SECONDS)
        return True

    def _dispatch(self, sock, method, path):
        self._live(sock)
        state = self.state
        kind = None
        with state.lock:
            if not state.source_preserved():
                raise F.FixtureError("source_changed")
            if method == "GET" and path == "":
                # A cancelled held listing must not silently succeed through
                # a retry/parallel request. Recovery uses a fresh owned fixture.
                if state.cancel_listing and state._listing_claimed:
                    raise F.FixtureError("request_invalid")
                state.root_gets += 1
                # Manual connectivity is one shallow root listing. The next
                # root GET is held; the producer must also observe Listing UI.
                if state.cancel_listing and state.root_gets == 2:
                    if not state._observation_release.is_set():
                        raise F.FixtureError("request_invalid")
                    state._listing_claimed = True
                    kind = "listing"
            if method == "GET" and path in state.files:
                if (path != state.selected_member or state._download_claimed or
                        not state._observation_release.is_set() or state.cancel_listing):
                    raise F.FixtureError("request_invalid")
                state._download_claimed = True
                kind = "download"
        if kind is not None:
            state._event(kind + "_observation", path)
            (state.listing_started if kind == "listing" else state.download_started).set()
            if not self._hold(sock, kind):
                return
        super()._dispatch(sock, method, path)

    def close(self):
        # Stop precedes release, so teardown cannot serve a held remainder or
        # pretend that the producer authorized a request to continue.
        self.stopping.set()
        self.state._download_release.set()
        self.state._listing_release.set()
        super().close()


@contextmanager
def serve_http(state):
    if type(state) is not TuiHttpState:
        raise ValueError("input_invalid")
    with state.lock:
        if state._served:
            raise ValueError("state_reused")
        state._served = True
    server = _TuiServer(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
