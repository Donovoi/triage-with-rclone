"""Pure state and mocked transport checks; no sockets or processes are created."""
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab/fixture_tui_http.py"
SPEC = importlib.util.spec_from_file_location("test_tui_fixture", PATH)
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


class TuiFixtureTests(unittest.TestCase):
    def setUp(self):
        self.socket_guard = patch.object(T.F.socket, "socket", side_effect=AssertionError("no_native"))
        self.socket_guard.start()
        self.addCleanup(self.socket_guard.stop)
        self.state = T.TuiHttpState({"chosen.txt": b"chosen", "other.txt": b"other"}, "chosen.txt")
        self.sock = Mock()
        # Bypass the constructor: these are tests of bounded dispatch decisions.
        self.server = object.__new__(T._TuiServer)
        self.server.state = self.state
        self.server.lock = threading.RLock()
        self.server.stopping = threading.Event()
        self.server.deadline = 100.0
        self.server.sockets = {self.sock: 10.0}
        self.server._live = Mock()

    def dispatch(self, method, path, hold=True):
        with patch.object(T.F._Server, "_dispatch") as parent, patch.object(self.server, "_hold", return_value=hold) as held:
            self.server._dispatch(self.sock, method, path)
            return parent.call_count, held.call_args_list

    def test_state_is_copied_and_modes_are_fixed(self):
        self.assertEqual(self.state.mode, "baseline")
        self.assertTrue(self.state.source_preserved())
        self.state.selected_member = "other.txt"
        self.assertFalse(self.state.source_preserved())
        with self.assertRaises(T.F.FixtureError):
            self.dispatch("HEAD", "")

    def test_invalid_options_refused(self):
        for files, member, options in ((None, "x", {}), ({"x": b"x"}, None, {}),
                ({"x": b"x"}, "missing", {}), ({"x": b"x"}, "x", {"cancel_listing": 1}),
                ({"x": b"xx"}, "x", {"cancel_listing": True, "cancel_download": True})):
            with self.assertRaises(ValueError):
                T.TuiHttpState(files, member, **options)

    def test_release_requires_an_observed_hold_and_cannot_repeat(self):
        for kind in ("download", "listing"):
            release = getattr(self.state, "release_" + kind)
            with self.assertRaises(ValueError):
                release()
            getattr(self.state, kind + "_started").set()
            release()
            with self.assertRaises(ValueError):
                release()
            self.assertTrue(self.state.snapshot()[kind + "_released"])

    def test_metadata_requests_do_not_trigger_download_hold(self):
        for method, path in (("HEAD", "chosen.txt"), ("GET", ""), ("GET", "nested/")):
            count, held = self.dispatch(method, path)
            self.assertEqual((count, held), (1, []))
        self.assertFalse(self.state.download_started.is_set())

    def test_download_requires_connectivity_observation_release(self):
        with self.assertRaises(T.F.FixtureError):
            self.dispatch("GET", "chosen.txt")
        self.assertFalse(self.state.download_started.is_set())

    def test_exact_selected_download_is_held_before_base_dispatch(self):
        self.state.release_observation()
        observed = []
        def held(sock, kind):
            observed.append((kind, self.state.download_started.is_set(), self.state.snapshot()["events"]))
            return True
        with patch.object(T.F._Server, "_dispatch") as parent, patch.object(self.server, "_hold", side_effect=held):
            self.server._dispatch(self.sock, "GET", "chosen.txt")
            parent.assert_called_once_with(self.sock, "GET", "chosen.txt")
        self.assertEqual(observed, [("download", True, [["download_observation", "chosen.txt"]])])

    def test_unselected_content_and_replayed_download_are_refused(self):
        self.state.release_observation()
        with self.assertRaises(T.F.FixtureError):
            self.dispatch("GET", "other.txt")
        self.dispatch("GET", "chosen.txt")
        with self.assertRaises(T.F.FixtureError):
            self.dispatch("GET", "chosen.txt")

    def test_cancelled_hold_never_dispatches_payload(self):
        self.state.release_observation()
        count, _ = self.dispatch("GET", "chosen.txt", hold=False)
        self.assertEqual(count, 0)

    def test_only_second_root_get_is_listing_hold(self):
        self.state = T.TuiHttpState({"chosen.txt": b"chosen"}, "chosen.txt", cancel_listing=True)
        self.server.state = self.state
        self.assertEqual(self.dispatch("HEAD", ""), (1, []))
        self.assertEqual(self.dispatch("GET", ""), (1, []))
        self.state.release_observation()
        count, held = self.dispatch("GET", "", hold=False)
        self.assertEqual(count, 0)
        self.assertEqual(held[0].args, (self.sock, "listing"))
        self.assertTrue(self.state.listing_started.is_set())
        with patch.object(T.F._Server, "_dispatch") as parent:
            with self.assertRaises(T.F.FixtureError):
                self.server._dispatch(self.sock, "GET", "")
            parent.assert_not_called()
        with self.assertRaises(T.F.FixtureError):
            self.dispatch("GET", "chosen.txt")

    def test_unreleased_connectivity_cannot_be_claimed_as_listing_phase(self):
        self.state = T.TuiHttpState({"chosen.txt": b"chosen"}, "chosen.txt", cancel_listing=True)
        self.server.state = self.state
        self.dispatch("GET", "")
        with self.assertRaises(T.F.FixtureError):
            self.dispatch("GET", "")
        self.assertFalse(self.state.listing_started.is_set())

    def test_hold_refuses_unowned_socket_and_expired_lifetime(self):
        with self.assertRaises(T.F.FixtureError):
            self.server._hold(Mock(), "download")
        with patch.object(T.time, "monotonic", return_value=100):
            with self.assertRaises(T.F.FixtureError):
                self.server._hold(self.sock, "download")

    def test_listing_disconnect_is_distinct_from_download_abort(self):
        self.sock.recv.return_value = b""
        with patch.object(T.time, "monotonic", return_value=1), patch.object(T.select, "select", return_value=([self.sock], [], [])):
            self.assertFalse(self.server._hold(self.sock, "listing"))
            self.assertTrue(self.state.listing_disconnected)
            with self.assertRaises(T.F.FixtureError):
                self.server._hold(self.sock, "download")

    def test_extra_client_input_during_hold_is_refused(self):
        self.sock.recv.return_value = b"x"
        with patch.object(T.time, "monotonic", return_value=1), patch.object(T.select, "select", return_value=([self.sock], [], [])):
            with self.assertRaises(T.F.FixtureError):
                self.server._hold(self.sock, "listing")
        self.assertFalse(self.state.listing_disconnected)

    def test_disconnect_after_select_or_recv_overruns_is_not_evidence(self):
        for overrun in ("select", "recv"):
            clock = [1]
            self.state.listing_disconnected = False
            def ready(*_):
                if overrun == "select":
                    clock[0] = 101
                return [self.sock], [], []
            def disconnected(*_):
                if overrun == "recv":
                    clock[0] = 101
                return b""
            self.sock.recv.side_effect = disconnected
            with patch.object(T.time, "monotonic", side_effect=lambda: clock[0]), patch.object(T.select, "select", side_effect=ready):
                with self.assertRaises(T.F.FixtureError):
                    self.server._hold(self.sock, "listing")
            self.assertFalse(self.state.listing_disconnected)

    def test_release_after_deadline_cannot_resume_a_request(self):
        self.state.download_started.set()
        self.state.release_download()
        with patch.object(T.time, "monotonic", return_value=100):
            with self.assertRaises(T.F.FixtureError):
                self.server._hold(self.sock, "download")

    def test_authorized_release_restores_original_request_deadline(self):
        self.state.download_started.set()
        self.state.release_download()
        with patch.object(T.time, "monotonic", return_value=1):
            self.assertTrue(self.server._hold(self.sock, "download"))
        self.assertEqual(self.server.sockets[self.sock], 1 + T.F.REQUEST_SECONDS)

    def test_teardown_sets_stop_before_releases_without_claiming_authorization(self):
        observations = []
        with patch.object(T.F._Server, "close", side_effect=lambda: observations.append((self.server.stopping.is_set(), self.state._download_release.is_set(), self.state._listing_release.is_set()))):
            self.server.close()
        self.assertEqual(observations, [(True, True, True)])
        self.assertFalse(self.state.download_released)
        self.assertFalse(self.state.listing_released)
        self.assertFalse(self.server._hold(self.sock, "download"))

    def test_context_closes_on_start_failure_and_refuses_state_reuse(self):
        server = Mock()
        server.start.side_effect = RuntimeError("synthetic")
        with patch.object(T, "_TuiServer", return_value=server):
            with self.assertRaises(RuntimeError):
                with T.serve_http(self.state):
                    self.fail("unreachable")
        server.close.assert_called_once_with()
        with patch.object(T, "_TuiServer", side_effect=AssertionError("cannot_construct")):
            with self.assertRaises(ValueError):
                with T.serve_http(self.state):
                    self.fail("unreachable")


if __name__ == "__main__":
    unittest.main()
