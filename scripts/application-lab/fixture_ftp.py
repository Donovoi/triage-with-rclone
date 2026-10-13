"""Bounded synthetic plain FTP; transport observations are not app acceptance.

No socket/thread starts on import. Only fixed corpus paths and passive IPv4
loopback channels are supported. The producer must independently bind events to
one app/copy invocation, verify acquired bytes, preserve config, and reap children.

Wire contract: rclone be8d6044/backend/ftp/ftp.go and jlaffaye/ftp 6602e981/ftp.go.
Clean data EOF plus control EOF without 226 permits whole-copy restart; REST
resume after a non-EOF read error is a different, deliberately unsupported case.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import select
import socket
import threading
import time
from types import MappingProxyType

MAX_LIFETIME = 180.0
IO_SECONDS = 15.0
JOIN_SECONDS = 5.0
MAX_SESSIONS = 32
MAX_ACTIVE = 8
MAX_COMMANDS = 512
MAX_LINE = 512
MAX_TRANSFERS = 64
MAX_EVENTS = 2048
MAX_WIRE_BYTES = 32 * 1024 * 1024
DROP_BYTES = 65536
RECONNECT_MEMBER = "large/cancel.bin"
MODIFIED = "20250102030405"
EPOCHS = ("accepted_a", "revoked_a", "replacement_b")
MANIFEST = MappingProxyType({
    "README-synthetic.txt": (30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"),
    RECONNECT_MEMBER: (2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"),
    "nested/binary.bin": (256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
    "nested/spaced name.txt": (20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"),
})
DIRECTORIES = ("", "large", "nested")
MISSING = "missing-synthetic.txt"
EVENT_KINDS = frozenset({"session_open", "session_closed", "user", "login_a", "login_b",
                         "denied_a", "denied_b", "denied_other", "metadata", "missing",
                         "passive", "data_open", "transfer_start", "listing_sent",
                         "content_sent", "drop_prefix_sent", "drop_fin", "restart_served",
                         "epoch", "gate_pre_drop", "gate_restart", "gate_released"})
ERROR_CODES = frozenset({"input_invalid", "state_reused", "deadline", "io_failed",
                         "line_invalid", "command_unsupported", "command_invalid",
                         "path_invalid", "passive_required", "passive_busy", "peer_invalid",
                         "limit_exceeded", "thread_start_failed", "cleanup_failed",
                         "epoch_invalid", "epoch_busy", "epoch_unproved", "source_changed", "gate_invalid"})
GATES = ("pre_prefix_drop", "post_relogin_transfer")


class FixtureError(RuntimeError):
    pass


def corpus():
    """Fresh fixed in-memory bytes; no filesystem paths or caller data."""
    return {"README-synthetic.txt": b"synthetic application fixture\n",
            RECONNECT_MEMBER: bytes(range(256)) * 8192,
            "nested/binary.bin": bytes(range(256)),
            "nested/spaced name.txt": b"spaces remain exact\n"}


def _credential(value):
    return type(value) is str and 1 <= len(value) <= 128 and all(33 <= ord(c) <= 126 for c in value)


class AppFtpState:
    def __init__(self, user, password_a, *, password_b, continuity_gates=False):
        if not all(_credential(x) for x in (user, password_a, password_b)) or password_a == password_b:
            raise FixtureError("input_invalid")
        if type(continuity_gates) is not bool:
            raise FixtureError("input_invalid")
        self.files = MappingProxyType(corpus())
        self._credentials = tuple(x.encode("ascii") for x in (user, password_a, password_b))
        self.lock = threading.RLock()
        self.epoch = 1
        self.events, self.errors = [], []
        self._sessions = self._commands = self._transfers = self._wire_bytes = 0
        self._drop_attempted = False
        self._drop = None
        self._restart = None
        self._served = False
        self._transport = None
        self._transport_attempted = False
        self._gates = ({name: {"entered": None, "released": False, "event": threading.Event()}
                        for name in GATES} if continuity_gates else None)

    def gate_snapshot(self):
        """Closed server observations; no process/TCP birth or acquisition proof."""
        with self.lock:
            return None if self._gates is None else {
                name: {"entered": None if item["entered"] is None else dict(item["entered"]),
                       "released": item["released"]} for name, item in self._gates.items()}

    def release_gate(self, name):
        with self.lock:
            if (type(name) is not str or name not in GATES or self._gates is None or
                    self._transport is None or self.errors):
                raise self.fail("gate_invalid")
            self._transport.live()
            item = self._gates[name]
            if item["entered"] is None or item["released"]:
                raise self.fail("gate_invalid")
            item["released"] = True
            self._event("gate_released", **item["entered"])
            item["event"].set()

    def _hold(self, name, session, transfer, member):
        if self._gates is None:
            return
        with self.lock:
            item = self._gates[name]
            if item["entered"] is not None or self.errors or self.epoch != 1:
                raise self.fail("gate_invalid")
            if name == GATES[1] and not self._gates[GATES[0]]["released"]:
                raise self.fail("gate_invalid")
            item["entered"] = dict(session=session.number, transfer=transfer, member=member)
            self._event("gate_pre_drop" if name == GATES[0] else "gate_restart", **item["entered"])
        # Original absolute deadline applies; shutdown wakes the wait but never
        # marks the gate released or grants continuity credit.
        while not item["event"].wait(min(0.1, max(0.0, self._transport.deadline - time.monotonic()))):
            self._transport.live()
        self._transport.live()
        with self.lock:
            if not item["released"] or self.errors:
                raise self.fail("gate_invalid")

    def fail(self, code):
        code = code if type(code) is str and code in ERROR_CODES else "io_failed"
        with self.lock:
            if code not in self.errors:
                self.errors.append(code)
        return FixtureError(code)

    def _event(self, kind, session=0, transfer=0, member=0, count=0):
        with self.lock:
            if kind not in EVENT_KINDS or len(self.events) >= MAX_EVENTS:
                raise self.fail("limit_exceeded")
            event = {"ordinal": len(self.events) + 1, "kind": kind, "epoch": self.epoch,
                     "session": session, "transfer": transfer, "member": member, "bytes": count}
            self.events.append(event)
            return event["ordinal"]

    def unchanged(self):
        return (set(self.files) == set(MANIFEST) and
                all(type(v) is bytes and (len(v), hashlib.sha256(v).hexdigest()) == MANIFEST[k]
                    for k, v in self.files.items()))

    def snapshot(self):
        with self.lock:
            transport = self._transport.snapshot() if self._transport else None
            return {"schema_version": 1, "scope": "synthetic_ftp_transport",
                    "epoch": EPOCHS[self.epoch - 1], "sessions": self._sessions,
                    "commands": self._commands, "transfers": self._transfers,
                    "wire_bytes": self._wire_bytes, "drop_attempted": self._drop_attempted,
                    "drop_confirmed": self._drop is not None,
                    "reauthenticated_restart_served": self._restart is not None,
                    "events": [dict(e) for e in self.events], "errors": list(self.errors),
                    "transport_attempted": self._transport_attempted, "transport": transport,
                    "source_preserved": self.unchanged(), "can_complete_application": False,
                    "same_invocation_verified": False, "acquired_hash_verified": False}

    def advance_epoch(self, epoch, *, invocation_succeeded, processes_reaped):
        """Caller reap is required but is not independently proved by this fixture."""
        with self.lock:
            if (type(epoch) is not str or self.epoch >= 3 or epoch != EPOCHS[self.epoch] or
                    invocation_succeeded is not True or processes_reaped is not True):
                raise self.fail("epoch_invalid")
            server = self._transport
            if server is None or not server.quiescent() or server.stopping.is_set():
                raise self.fail("epoch_busy")
            server.live()
            required = (self._restart is not None if self.epoch == 1 else
                        any(e["kind"] == "denied_a" and e["epoch"] == 2 for e in self.events))
            if self.errors or not required or not self.unchanged():
                raise self.fail("epoch_unproved")
            self.epoch += 1
            self._event("epoch")


class _Socket:
    """Recorded immediately on allocation; uncertain close is never retried."""
    def __init__(self, server, raw, kind, session):
        self.server, self.raw, self.kind, self.session = server, raw, kind, session
        self.attempted = self.closed = self.uncertain = False
        self.lock = threading.Lock()

    def close(self, *, fin=False):
        with self.lock:
            if self.attempted:
                return self.closed and not self.uncertain
            self.attempted = True
            try:
                try:
                    self.raw.shutdown(socket.SHUT_WR if fin else socket.SHUT_RDWR)
                except OSError:
                    # Unconnected listener shutdown is expected; a requested FIN
                    # is a fault witness only if its shutdown actually succeeded.
                    if fin:
                        self.uncertain = True
                self.raw.close()
                self.closed = True
            except Exception:
                self.uncertain = True
            result = self.closed and not self.uncertain
        # Never acquire state.lock while holding this resource lock: the drop
        # boundary takes state.lock before closing the two resources.
        if not result:
            self.server.state.fail("cleanup_failed")
        return result


class _Session:
    def __init__(self, server, control, number, opened):
        self.server, self.control, self.number, self.opened = server, control, number, opened
        self.epoch = server.state.epoch
        self.user = None
        self.auth = None
        self.auth_event = 0
        self.passive = None
        self.data = None
        self.finished = False

    def reset_auth(self):
        self.user = self.auth = None
        self.auth_event = 0
        if self.passive is not None:
            if not self.passive.close():
                raise self.server.state.fail("cleanup_failed")
            self.passive = None


class _Server:
    def __init__(self, state):
        self.state = state
        self.deadline = time.monotonic() + MAX_LIFETIME
        self.stopping = threading.Event()
        self.resources, self.workers = [], []
        self.listener = self.acceptor = None
        self.endpoint = None
        self.cleanup_complete = False
        self._close_attempted = False
        self._thread_uncertain = False

    def live(self):
        if self.stopping.is_set() or time.monotonic() >= self.deadline:
            raise self.state.fail("deadline")

    def _own(self, raw, kind, session=0):
        resource = _Socket(self, raw, kind, session)
        with self.state.lock:
            self.resources.append(resource)
        return resource

    def _allocate(self, kind, session=0):
        self.live()
        return self._own(socket.socket(socket.AF_INET, socket.SOCK_STREAM), kind, session)

    def _timeout(self, resource):
        self.live()
        resource.raw.settimeout(min(IO_SECONDS, self.deadline - time.monotonic()))

    def _send(self, resource, value):
        self._timeout(resource)
        with self.state.lock:
            if self.state._wire_bytes + len(value) > MAX_WIRE_BYTES:
                raise self.state.fail("limit_exceeded")
            self.state._wire_bytes += len(value)
        resource.raw.sendall(value)
        self.live()

    def _reply(self, session, value):
        self._send(session.control, value)

    def _spawn(self, target, *args):
        thread = threading.Thread(target=target, args=args, daemon=True)
        try:
            thread.start()
        except Exception:
            self._thread_uncertain = True
            self.workers.append(thread)
            raise self.state.fail("thread_start_failed")
        return thread

    def start(self):
        self.listener = self._allocate("control_listener")
        self.listener.raw.bind(("127.0.0.1", 0))
        self.listener.raw.listen(MAX_ACTIVE)
        self.listener.raw.settimeout(0.0)
        address = self.listener.raw.getsockname()
        if (type(address) is not tuple or len(address) != 2 or address[0] != "127.0.0.1" or
                type(address[1]) is not int or not 1 <= address[1] <= 65535):
            raise self.state.fail("peer_invalid")
        self.endpoint = address
        self.acceptor = self._spawn(self._accept)

    def _admit(self, raw, peer):
        control = self._own(raw, "control")
        with self.state.lock:
            self.live()
            if (type(peer) is not tuple or len(peer) != 2 or peer[0] != "127.0.0.1" or
                    type(peer[1]) is not int or not 1 <= peer[1] <= 65535):
                raise self.state.fail("peer_invalid")
            active = sum(r.kind == "control" and not r.closed for r in self.resources)
            if self.state._sessions >= MAX_SESSIONS or active > MAX_ACTIVE:
                raise self.state.fail("limit_exceeded")
            self.state._sessions += 1
            control.session = self.state._sessions
            opened = self.state._event("session_open", control.session)
            return _Session(self, control, control.session, opened)

    def _accept(self):
        try:
            while not self.stopping.is_set():
                self.live()
                # Wait outside the shared state lock so an idle listener cannot
                # repeatedly delay replies, transfers or the committed FIN.
                readable, _, _ = select.select([self.listener.raw], [], [],
                    min(0.1, max(0.0, self.deadline - time.monotonic())))
                if not readable:
                    continue
                try:
                    # The actual nonblocking accept AND registration still share
                    # the committed FIN boundary. Readiness itself grants no
                    # freshness; delayed registration cannot grant it either.
                    with self.state.lock:
                        self.live()
                        raw, peer = self.listener.raw.accept()
                        session = self._admit(raw, peer)
                except BlockingIOError:
                    continue
                thread = self._spawn(self._worker, session)
                with self.state.lock:
                    self.workers.append(thread)
        except Exception as exc:
            if not self.stopping.is_set():
                self.state.fail(str(exc) if type(exc) is FixtureError else "io_failed")
                self.stopping.set()
        finally:
            # No new admissions remain; final close/join is the context owner's duty.
            if self.listener is not None:
                self.listener.close()

    def _line(self, session):
        value = bytearray()
        while len(value) < MAX_LINE:
            self._timeout(session.control)
            piece = session.control.raw.recv(1)
            if not piece:
                if value:
                    raise self.state.fail("line_invalid")
                return None
            value.extend(piece)
            if piece == b"\n":
                if (not value.endswith(b"\r\n") or
                        any(c < 32 or c > 126 for c in value[:-2])):
                    raise self.state.fail("line_invalid")
                body = bytes(value[:-2])
                verb, _, argument = body.partition(b" ")
                if not 1 <= len(verb) <= 8 or not all(65 <= c <= 90 for c in verb):
                    raise self.state.fail("line_invalid")
                with self.state.lock:
                    if self.state._commands >= MAX_COMMANDS:
                        raise self.state.fail("limit_exceeded")
                    self.state._commands += 1
                return verb.decode("ascii"), argument
        raise self.state.fail("line_invalid")

    def _path(self, argument):
        text = argument.decode("ascii")
        if text in ("", ".", "/", "./"):
            return ""
        if text.startswith("/"):
            text = text[1:]
        if text in MANIFEST or text == MISSING:
            return text
        if text in ("large", "large/", "nested", "nested/"):
            return text.rstrip("/")
        raise self.state.fail("path_invalid")

    def _fact(self, path, *, basename=False):
        name = path.rsplit("/", 1)[-1] if basename else (path or "/")
        if path in DIRECTORIES:
            facts = "type=dir;"
        else:
            facts = f"type=file;size={MANIFEST[path][0]};"
        return f"{facts}modify={MODIFIED}; {name}\r\n".encode("ascii")

    def _passive(self, session, verb):
        if session.passive is not None:
            raise self.state.fail("passive_busy")
        passive = self._allocate("data_listener", session.number)
        session.passive = passive
        passive.raw.bind(("127.0.0.1", 0))
        passive.raw.listen(1)
        self._timeout(passive)
        host, port = passive.raw.getsockname()
        if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
            raise self.state.fail("peer_invalid")
        self.state._event("passive", session.number)
        if verb == "EPSV":
            self._reply(session, f"229 Entering Extended Passive Mode (|||{port}|)\r\n".encode("ascii"))
        else:
            self._reply(session, f"227 Entering Passive Mode (127,0,0,1,{port // 256},{port % 256})\r\n".encode("ascii"))

    def _data(self, session):
        if session.passive is None:
            raise self.state.fail("passive_required")
        self._timeout(session.passive)
        raw, peer = session.passive.raw.accept()
        session.data = self._own(raw, "data", session.number)
        if peer[0] != "127.0.0.1" or type(peer[1]) is not int or not 1 <= peer[1] <= 65535:
            raise self.state.fail("peer_invalid")
        if not session.passive.close():
            raise self.state.fail("cleanup_failed")
        session.passive = None
        self.state._event("data_open", session.number)
        return session.data

    def _transfer(self, session, verb, path):
        with self.state.lock:
            if self.state._transfers >= MAX_TRANSFERS:
                raise self.state.fail("limit_exceeded")
            self.state._transfers += 1
            transfer = self.state._transfers
            member = list(MANIFEST).index(path) + 1 if path in MANIFEST else 0
            self.state._event("transfer_start", session.number, transfer, member)
            inject = verb == "RETR" and path == RECONNECT_MEMBER and not self.state._drop_attempted
            if inject:
                self.state._drop_attempted = True
        data = self._data(session)
        self._reply(session, b"150 Opening data connection\r\n")
        if verb == "MLSD":
            prefix = path + "/" if path else ""
            paths = sorted(p for p in (*DIRECTORIES[1:], *MANIFEST) if p.startswith(prefix)
                           and "/" not in p[len(prefix):])
            body = b"".join(self._fact(p, basename=True) for p in paths)
        else:
            body = self.state.files[path]
        if inject:
            self.state._hold(GATES[0], session, transfer, member)
        else:
            with self.state.lock:
                drop = self.state._drop
                restarting = (verb == "RETR" and path == RECONNECT_MEMBER and drop is not None and
                              session.epoch == drop[0] and session.number != drop[1] and
                              session.opened > drop[2] and session.auth_event > drop[2] and session.auth == drop[3])
            if restarting:
                self.state._hold(GATES[1], session, transfer, member)
        self._send(data, body[:DROP_BYTES] if inject else body)
        if inject:
            self.state._event("drop_prefix_sent", session.number, transfer, member, DROP_BYTES)
            # Both writes use orderly FIN; no 226 is emitted. This records server
            # actions, not client EOF, consumed prefix, retry or app outcome.
            with self.state.lock:
                # Admission also takes this lock: a newly accepted session cannot
                # be recorded between the close and its committed drop event.
                data_closed = data.close(fin=True)
                control_closed = session.control.close(fin=True)
                session.finished = True
                if not data_closed or not control_closed:
                    raise self.state.fail("cleanup_failed")
                ordinal = self.state._event("drop_fin", session.number, transfer, member, DROP_BYTES)
                self.state._drop = (session.epoch, session.number, ordinal, session.auth)
            return
        if not data.close(fin=True):
            raise self.state.fail("cleanup_failed")
        self._reply(session, b"226 Transfer complete\r\n")
        kind = "listing_sent" if verb == "MLSD" else "content_sent"
        with self.state.lock:
            self.state._event(kind, session.number, transfer, member, len(body))
            drop = self.state._drop
            if (verb == "RETR" and path == RECONNECT_MEMBER and drop is not None and
                    session.epoch == drop[0] and session.number != drop[1] and
                    session.opened > drop[2] and session.auth_event > drop[2] and session.auth == drop[3]):
                self.state._restart = (session.number, transfer)
                self.state._event("restart_served", session.number, transfer, member, len(body))

    def _dispatch(self, session, verb, argument):
        self.live()
        if session.epoch != self.state.epoch:
            raise self.state.fail("epoch_invalid")
        if verb == "USER":
            session.reset_auth()
            if not _credential(argument.decode("ascii")):
                raise self.state.fail("command_invalid")
            session.user = argument
            self.state._event("user", session.number)
            self._reply(session, b"331 Password required\r\n")
            return
        if verb == "PASS":
            user, a, b = self.state._credentials
            user_matches = session.user is not None and hmac.compare_digest(session.user, user)
            role = ("a" if user_matches and hmac.compare_digest(argument, a) else
                    "b" if user_matches and hmac.compare_digest(argument, b) else "other")
            valid = ((self.state.epoch == 1 and role == "a") or (self.state.epoch == 3 and role == "b"))
            session.reset_auth()
            if valid:
                session.auth = role
                session.auth_event = self.state._event("login_" + role, session.number)
                self._reply(session, b"230 Logged in\r\n")
            else:
                self.state._event("denied_" + role, session.number)
                self._reply(session, b"530 Login incorrect\r\n")
            return
        if verb == "QUIT" and not argument:
            self._reply(session, b"221 Goodbye\r\n")
            session.finished = True
            return
        if session.auth is None:
            self._reply(session, b"530 Login required\r\n")
            return
        if verb == "FEAT" and not argument:
            self._reply(session, b"211-Features\r\n MLST type*;size*;modify*;\r\n UTF8\r\n EPSV\r\n211 End\r\n")
        elif (verb, argument) in (("TYPE", b"I"), ("OPTS", b"UTF8 ON"), ("NOOP", b"")):
            self._reply(session, b"200 Command okay\r\n")
        elif verb == "PWD" and not argument:
            self._reply(session, b'257 "/"\r\n')
        elif verb == "CWD" and self._path(argument) in DIRECTORIES:
            # Only root is supported as working directory; paths remain absolute
            # or root-relative, as generated by the pinned backend.
            if self._path(argument) != "":
                raise self.state.fail("command_unsupported")
            self._reply(session, b"250 Directory okay\r\n")
        elif verb in ("EPSV", "PASV") and not argument:
            self._passive(session, verb)
        elif verb in ("MLST", "MLSD", "RETR"):
            path = self._path(argument)
            if (path == MISSING or (verb == "RETR" and path not in MANIFEST) or
                    (verb == "MLSD" and path not in DIRECTORIES)):
                self.state._event("missing", session.number)
                if session.passive is not None:
                    if not session.passive.close():
                        raise self.state.fail("cleanup_failed")
                    session.passive = None
                self._reply(session, b"550 Not found\r\n")
            elif verb == "MLST":
                self.state._event("metadata", session.number)
                self._reply(session, b"250-Entry\r\n " + self._fact(path) + b"250 End\r\n")
            else:
                self._transfer(session, verb, path)
        else:
            # No active mode, TLS, mutation, LIST fallback or REST-resume credit.
            raise self.state.fail("command_unsupported")

    def _worker(self, session):
        try:
            self._reply(session, b"220 Synthetic FTP fixture\r\n")
            while not session.finished:
                command = self._line(session)
                if command is None:
                    break
                self._dispatch(session, *command)
        except Exception as exc:
            if not self.stopping.is_set():
                self.state.fail(str(exc) if type(exc) is FixtureError else "io_failed")
        finally:
            closed = True
            for resource in (session.data, session.passive, session.control):
                if resource is not None:
                    closed = resource.close() and closed
            session.finished = True
            if closed:
                try:
                    self.state._event("session_closed", session.number)
                except FixtureError:
                    pass

    def quiescent(self):
        return (not self._thread_uncertain and not any(t.is_alive() for t in self.workers) and
                all(r.closed and not r.uncertain for r in self.resources if r.kind != "control_listener"))

    def snapshot(self):
        with self.state.lock:
            counts = {kind: sum(r.kind == kind and not (r.closed and not r.uncertain)
                                for r in self.resources)
                      for kind in ("control_listener", "control", "data_listener", "data")}
            return {**counts, "workers_alive": sum(t.is_alive() for t in self.workers),
                    "acceptor_alive": bool(self.acceptor and self.acceptor.is_alive()),
                    "cleanup_complete": self.cleanup_complete}

    def close(self):
        if self._close_attempted:
            if not self.cleanup_complete:
                raise self.state.fail("cleanup_failed")
            return
        self._close_attempted = True
        self.stopping.set()
        if self.state._gates is not None:
            for item in self.state._gates.values():
                item["event"].set()
        with self.state.lock:
            resources = list(self.resources)
        for resource in resources:
            resource.close()
        deadline = time.monotonic() + JOIN_SECONDS
        if self.acceptor is not None and self.acceptor.ident is not None:
            self.acceptor.join(max(0.0, deadline - time.monotonic()))
        # Worker registration may finish while the acceptor is winding down.
        # Take its list only after joining the acceptor, never before that join.
        with self.state.lock:
            threads = ([self.acceptor] if self.acceptor is not None else []) + list(self.workers)
            resources = list(self.resources)
        for resource in resources:
            if not resource.attempted:
                resource.close()
        for thread in threads:
            if thread is self.acceptor:
                continue
            if thread.ident is not None and thread is not threading.current_thread():
                thread.join(max(0.0, deadline - time.monotonic()))
        # A passive accept may return while its worker is winding down. Inspect
        # the final ownership list after all joins, not the earlier snapshot.
        with self.state.lock:
            resources = list(self.resources)
        for resource in resources:
            if not resource.attempted:
                resource.close()
        self.cleanup_complete = (not self._thread_uncertain and
                                 not any(t.is_alive() for t in threads) and
                                 all(r.closed and not r.uncertain for r in resources))
        if not self.state.unchanged():
            self.state.fail("source_changed")
            self.cleanup_complete = False
        if not self.cleanup_complete:
            raise self.state.fail("cleanup_failed")


@contextmanager
def serve_ftp(state):
    if type(state) is not AppFtpState:
        raise FixtureError("input_invalid")
    with state.lock:
        if state._served:
            raise state.fail("state_reused")
        state._served = state._transport_attempted = True
        server = state._transport = _Server(state)
    try:
        try:
            server.start()
        except Exception as exc:
            raise state.fail(str(exc) if type(exc) is FixtureError else "io_failed") from None
        yield server
    finally:
        server.close()
