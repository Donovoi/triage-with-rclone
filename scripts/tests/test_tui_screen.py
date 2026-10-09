"""Pure byte/grid contracts; no terminal, native process, socket or host mutation."""
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
import io
import random
from types import ModuleType
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "application-lab" / "tui_screen.py"
T = ModuleType("tui_screen_under_test")
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), T.__dict__)
ESC = b"\x1b"


class ScreenTests(unittest.TestCase):
    def assert_code(self, code, action):
        with self.assertRaises(T.ScreenError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        self.assertIn(code, T.CODES)

    def frame(self):
        # Literal expected coordinates and text, independent of parser internals.
        return (ESC + b"[?1049h" + ESC + b"[?2004h" + ESC + b"[2J" + ESC + b"[H"
                + ESC + b"[?25l" + ESC + b"[38;2;12;34;56m" + "┌ Review ┐".encode()
                + ESC + b"[0m" + ESC + b"[3;4H" + "▸ café.txt".encode()
                + ESC + b"[5;2H3 files, 1 selected" + ESC + b"[34;1HPress Esc to return")

    def assert_frame(self, screen):
        lines = screen.lines()
        self.assertEqual(len(lines), 34)
        self.assertTrue(all(len(line) == 120 for line in lines))
        self.assertEqual(lines[0], "┌ Review ┐".ljust(120))
        self.assertEqual(lines[2], "   ▸ café.txt".ljust(120))
        self.assertEqual(lines[4], " 3 files, 1 selected".ljust(120))
        self.assertEqual(lines[33], "Press Esc to return".ljust(120))
        self.assertTrue(all(not line.strip() for i, line in enumerate(lines) if i not in (0, 2, 4, 33)))
        self.assertFalse(screen.cursor_visible)
        self.assertTrue(screen.alternate)

    def test_literal_ui_frame_at_every_two_chunk_split(self):
        data = self.frame()
        for split in range(len(data) + 1):
            with self.subTest(split=split):
                screen = T.Screen()
                screen.feed(data[:split])
                screen.feed(data[split:])
                screen.finish()
                self.assert_frame(screen)
                self.assertEqual(screen.total_bytes, len(data))

    def test_one_byte_and_seeded_chunks_match_literal_grid(self):
        data = self.frame()
        for seed in range(12):
            screen, offset, rng = T.Screen(), 0, random.Random(seed)
            while offset < len(data):
                length = 1 if seed == 0 else rng.randint(1, 23)
                screen.feed(data[offset:offset + length])
                offset += length
            self.assert_frame(screen)

    def test_cursor_position_zero_defaults_clipping_and_motion(self):
        screen = T.Screen(80, 24)
        screen.feed(ESC + b"[0;0HA" + ESC + b"[999;999HZ")
        self.assertEqual(screen.cursor, (79, 23))
        self.assertEqual(screen.lines()[0][0], "A")
        self.assertEqual(screen.lines()[23][79], "Z")
        screen.feed(ESC + b"[2A" + ESC + b"[3D" + b"B" + ESC + b"[2F" + b"C")
        self.assertEqual(screen.lines()[21][76], "B")
        self.assertEqual(screen.lines()[19][0], "C")
        screen.feed(ESC + b"[2E" + ESC + b"[6G" + ESC + b"[4dD")
        self.assertEqual(screen.lines()[3][5], "D")

    def test_cr_lf_backspace_tabs_do_not_invent_newline_return(self):
        screen = T.Screen(80, 24)
        screen.feed(b"abc\bX\tY\nZ\rQ\x07")
        self.assertEqual(screen.lines()[0][:10], "abX     Y ")
        self.assertEqual(screen.lines()[1][:11], "Q        Z ")

    def test_delayed_wrap_bottom_scroll_and_disabled_wrap(self):
        screen = T.Screen(80, 24)
        screen.feed(b"x" * 80)
        self.assertEqual(screen.cursor, (79, 0))
        screen.feed(b"y")
        self.assertEqual(screen.lines()[1][0], "y")
        screen.feed(ESC + b"[24;80HQ")
        self.assertEqual(screen.lines()[23][-1], "Q")
        screen.feed(b"R")
        self.assertEqual(screen.lines()[22][-1], "Q")
        self.assertEqual(screen.lines()[23][0], "R")
        screen.feed(ESC + b"[?7l" + ESC + b"[1;80HAB")
        self.assertEqual(screen.lines()[0][-1], "B")
        self.assertEqual(screen.cursor, (79, 0))

    def test_wrap_survives_style_and_is_cancelled_by_cr(self):
        screen = T.Screen(80, 24)
        screen.feed(b"A" * 80 + ESC + b"[31mB")
        self.assertEqual(screen.lines()[1][0], "B")
        screen.feed(ESC + b"[3;80HC\rD")
        self.assertEqual(screen.lines()[2][0], "D")
        self.assertEqual(screen.lines()[2][-1], "C")

    def test_cursor_save_restore_including_style_and_invalid_restore(self):
        screen = T.Screen()
        screen.feed(ESC + b"[3;4H" + ESC + b"[31m" + ESC + b"7"
                    + ESC + b"[9;9HX" + ESC + b"[32m" + ESC + b"8Y")
        self.assertEqual(screen.lines()[2][3], "Y")
        self.assertEqual(screen.cells()[2][3].style.foreground, ("index", 1))
        screen.feed(ESC + b"[s" + ESC + b"[H" + ESC + b"[uZ")
        self.assertEqual(screen.lines()[2][4], "Z")
        self.assert_code("sequence_invalid", lambda: T.Screen().feed(ESC + b"8"))

    def test_erase_ranges_include_cursor_and_preserve_other_cells(self):
        for sequence, expected in ((b"K", "abc   "), (b"1K", "    ef"), (b"2K", "      ")):
            screen = T.Screen()
            screen.feed(b"abcdef" + ESC + b"[1;4H" + ESC + b"[" + sequence)
            self.assertEqual(screen.lines()[0][:6], expected)
        screen = T.Screen()
        screen.feed(b"TOP" + ESC + b"[2;1HMIDDLE" + ESC + b"[3;1HBOTTOM" + ESC + b"[2;4H" + ESC + b"[J")
        self.assertEqual(screen.lines()[0][:3], "TOP")
        self.assertEqual(screen.lines()[1][:6], "MID   ")
        self.assertFalse(screen.lines()[2].strip())
        screen.feed(ESC + b"[1J")
        self.assertFalse(screen.text().strip())
        screen.feed(b"X" + ESC + b"[3J")
        self.assertIn("X", screen.text())
        screen.feed(ESC + b"[2J")
        self.assertFalse(screen.text().strip())

    def test_insert_delete_erase_characters(self):
        screen = T.Screen()
        screen.feed(b"abcdef" + ESC + b"[1;3H" + ESC + b"[2@")
        self.assertEqual(screen.lines()[0][:8], "ab  cdef")
        screen.feed(ESC + b"[3P")
        self.assertEqual(screen.lines()[0][:6], "abdef ")
        screen.feed(ESC + b"[2X")
        self.assertEqual(screen.lines()[0][:6], "ab  f ")

    def test_margin_scrolling_index_reverse_index_and_line_operations(self):
        screen = T.Screen()
        for row, label in enumerate(("TOP", "A", "B", "C", "BOTTOM"), 1):
            screen.feed(ESC + f"[{row};1H{label}".encode())
        screen.feed(ESC + b"[2;4r" + ESC + b"[4;1H\n")
        self.assertEqual([line.rstrip() for line in screen.lines()[:5]], ["TOP", "B", "C", "", "BOTTOM"])
        screen.feed(ESC + b"[2;1H" + ESC + b"M")
        self.assertEqual([line.rstrip() for line in screen.lines()[:5]], ["TOP", "", "B", "C", "BOTTOM"])
        screen.feed(ESC + b"[3;1H" + ESC + b"[L")
        self.assertEqual([line.rstrip() for line in screen.lines()[:5]], ["TOP", "", "", "B", "BOTTOM"])
        screen.feed(ESC + b"[M" + ESC + b"[S")
        self.assertEqual([line.rstrip() for line in screen.lines()[:5]], ["TOP", "B", "", "", "BOTTOM"])
        screen.feed(ESC + b"[T")
        self.assertEqual([line.rstrip() for line in screen.lines()[:5]], ["TOP", "", "B", "", "BOTTOM"])

    def test_sgr_attributes_extended_colors_and_conceal(self):
        screen = T.Screen()
        screen.feed(ESC + b"[1;3;4;7;38;2;1;2;3;48;5;200;58;2;4;5;6mA"
                    + ESC + b"[8mSECRET" + ESC + b"[28;22;23;24;27;39;49;59mB")
        self.assertEqual(screen.lines()[0][:8], "A      B")
        style = screen.cells()[0][0].style
        self.assertEqual(style.flags, frozenset({1, 3, 4, 7}))
        self.assertEqual(style.foreground, ("rgb", 1, 2, 3))
        self.assertEqual(style.background, ("index", 200))
        self.assertEqual(style.underline, ("rgb", 4, 5, 6))
        self.assertEqual(screen.cells()[0][7].style, T.Style())

    def test_alternate_screen_cannot_expose_stale_main_or_unpositioned_grid(self):
        screen = T.Screen()
        screen.feed(b"MAIN" + ESC + b"[?1049h")
        self.assertFalse(screen.ready)
        self.assert_code("screen_not_ready", screen.text)
        screen.feed(ESC + b"[2J" + ESC + b"[HUI")
        self.assertTrue(screen.alternate)
        self.assertEqual(screen.lines()[0][:4], "UI  ")
        screen.feed(ESC + b"[?1049lX")
        self.assertFalse(screen.alternate)
        self.assertEqual(screen.lines()[0][:5], "MAINX")

    def test_resize_requires_full_erase_and_absolute_position_for_each_buffer(self):
        screen = T.Screen()
        screen.feed(self.frame())
        screen.resize(80, 24)
        self.assert_code("screen_not_ready", screen.lines)
        screen.feed(ESC + b"[Hpartial")
        self.assertFalse(screen.ready)
        screen.feed(ESC + b"[2J" + ESC + b"[HNEW")
        self.assertEqual(screen.lines()[0], "NEW".ljust(80))
        self.assertEqual(len(screen.lines()), 24)
        screen.feed(ESC + b"[?1049l")
        self.assertFalse(screen.ready)
        screen.feed(ESC + b"[2J" + ESC + b"[HMAIN")
        self.assertEqual(screen.lines()[0][:4], "MAIN")
        screen.resize(80, 24)
        self.assertTrue(screen.ready)

    def test_pending_sequences_utf8_sync_and_eof_refuse_snapshots(self):
        for prefix, suffix in ((ESC + b"[", b"H"), (b"\xc3", b"\xa9"),
                               (ESC + b"]2;title" + ESC, b"\\"),
                               (ESC + b"[?2026hX", ESC + b"[?2026l")):
            with self.subTest(prefix=prefix):
                screen = T.Screen()
                screen.feed(prefix)
                self.assertTrue(screen.pending)
                self.assert_code("incomplete", screen.lines)
                screen.feed(suffix)
                self.assertTrue(screen.ready)
                screen.finish()
                self.assert_code("stream_finished", lambda: screen.feed(b"X"))
        for data, code in ((ESC, "incomplete"), (ESC + b"]2;x", "incomplete"),
                           (b"\xc3", "utf8_invalid"), (ESC + b"[?2026h", "incomplete")):
            screen = T.Screen()
            screen.feed(data)
            self.assert_code(code, screen.finish)
            self.assert_code(code, screen.text)

    def test_osc_titles_are_bounded_and_never_visible(self):
        screen = T.Screen()
        screen.feed(b"BEFORE" + ESC + b"]0;PRIVATE_CANARY\x07" + b"AFTER"
                    + ESC + b"]2;OTHER_PRIVATE_CANARY" + ESC + b"\\")
        self.assertEqual(screen.lines()[0][:11], "BEFOREAFTER")
        self.assertNotIn("CANARY", screen.text())
        self.assert_code("sequence_invalid", lambda: T.Screen().feed(ESC + b"]2;" + b"a" * 255 + b"\x07"))
        self.assert_code("sequence_limit", lambda: T.Screen().feed(ESC + b"]2;" + b"a" * 1025))

    def test_unknown_controls_and_malformed_escapes_are_sticky_and_static(self):
        samples = (ESC + b"]52;PRIVATE_CANARY\x07", ESC + b"]8;;https://example.invalid\x07",
                   ESC + b"PPRIVATE_CANARY", ESC + b"[?999h", ESC + b"[8;24;80t",
                   ESC + b"[1:2m", ESC + b"[2;3;4H", ESC + b"[4J", ESC + b"[3;2r",
                   ESC + b"(0", ESC + b"[38;2;1;2m", ESC + b"[48;5;256m", ESC + b"[999m",
                   ESC + b"[2\x00J", b"\x00", b"\x7f", b"\x80", b"\xc0\xaf")
        for data in samples:
            with self.subTest(data=data):
                screen = T.Screen()
                screen.feed(b"PREVIOUS UI")
                with self.assertRaises(T.ScreenError) as caught:
                    screen.feed(data)
                code = caught.exception.code
                self.assertEqual(str(caught.exception), code)
                self.assertNotIn("CANARY", str(caught.exception))
                self.assert_code(code, screen.text)
                self.assert_code(code, lambda: screen.feed(ESC + b"[2JRECOVER"))
                self.assert_code(code, lambda: screen.resize(80, 24))

    def test_unicode_width_and_format_uncertainty_fail_closed(self):
        for text in ("界", "Ａ", "🙂", "e\u0301", "\u200d", "\u202e", "\u2028", "\u000b"):
            self.assert_code("unicode_unsupported", lambda t=text: T.Screen().feed(t.encode()))
        screen = T.Screen()
        screen.feed("é—┌─┐▸»·".encode())
        self.assertEqual(screen.cursor, (8, 0))

    def test_size_input_and_sequence_numeric_bounds(self):
        for size in ((79, 24), (121, 24), (80, 23), (120, 35), (True, 24), (80.0, 24)):
            self.assert_code("size_invalid", lambda s=size: T.Screen(*s))
        for value in ("text", bytearray(b"X"), None):
            self.assert_code("input_invalid", lambda v=value: T.Screen().feed(v))
        for body in (b"9" * 129, b"32768H", b"000000H", b"1;" * 33 + b"m"):
            self.assert_code("sequence_limit", lambda b=body: T.Screen().feed(ESC + b"[" + b))

    def test_total_output_cell_work_and_scroll_bounds_are_cumulative(self):
        screen = T.Screen()
        with patch.object(T, "MAX_BYTES", 6):
            screen.feed(b"123")
            screen.feed(b"456")
            self.assert_code("byte_limit", lambda: screen.feed(b"7"))
        screen = T.Screen(80, 24)
        with patch.object(T, "MAX_CELL_UPDATES", 80 * 24):
            screen.feed(ESC + b"[2J")
            self.assert_code("operation_limit", lambda: screen.feed(ESC + b"[2J"))
        screen = T.Screen()
        with patch.object(T, "MAX_SCROLL_ROWS", 3):
            screen.feed(ESC + b"[2S")
            screen.feed(ESC + b"[T")
            self.assert_code("scroll_limit", lambda: screen.feed(ESC + b"[S"))

    def test_snapshots_are_immutable_detached_and_do_not_strip_spaces(self):
        screen = T.Screen()
        screen.feed(b"A ")
        before, cells = screen.lines(), screen.cells()
        screen.feed(b"B")
        self.assertEqual(before[0][:3], "A  ")
        self.assertEqual(cells[0][2].character, " ")
        self.assertEqual(screen.lines()[0][:3], "A B")
        self.assertEqual(len(screen.text()), 120 * 34 + 33)
        with self.assertRaises(TypeError):
            cells[0][0] = T.Cell("X", T.Style())

    def test_resize_with_partial_input_is_sticky_failure(self):
        screen = T.Screen()
        screen.feed(ESC + b"[")
        self.assert_code("incomplete", lambda: screen.resize(80, 24))
        self.assert_code("incomplete", lambda: screen.feed(b"H"))

    def test_non_screen_modes_and_cursor_shape_are_closed(self):
        screen = T.Screen()
        screen.feed(ESC + b"[?1;12;2004h" + ESC + b"=" + ESC + b"(B"
                    + ESC + b"[2 q" + ESC + b"[?25lX" + ESC + b"[?25h")
        self.assertEqual(screen.lines()[0][0], "X")
        self.assertTrue(screen.cursor_visible)
        self.assert_code("sequence_invalid", lambda: T.Screen().feed(ESC + b"[7 q"))

    def test_conpty_startup_vectors_at_every_split_emit_no_response(self):
        # Source-derived compatibility vectors, not a captured hosted transcript.
        # VtIo StartIfNeeded currently emits DA1, focus mode, then Win32 input.
        vectors = (b"\x1b[c\x1b[?1004h\x1b[?9001h",
                   b"\x1b[0c\x1b[?9001h\x1b[?1004h")
        for vector in vectors:
            data = vector + self.frame() + b"\x1b[?1004l\x1b[?9001l"
            for split in range(len(data) + 1):
                with self.subTest(vector=vector, split=split):
                    screen = T.Screen()
                    with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                        self.assertIsNone(screen.feed(data[:split]))
                        self.assertIsNone(screen.feed(data[split:]))
                    self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
                    self.assert_frame(screen)
                    self.assertEqual(screen.total_bytes, len(data))
            screen = T.Screen()
            for byte in data:
                screen.feed(bytes([byte]))
            screen.finish()
            self.assert_frame(screen)

    def test_input_modes_and_da1_preserve_primary_style_cursor_and_pending_wrap(self):
        controls = (b"\x1b[?1004h", b"\x1b[?1004l", b"\x1b[?9001h", b"\x1b[?9001l",
                    b"\x1b[c", b"\x1b[0c")
        for control in controls:
            with self.subTest(control=control):
                screen = T.Screen(80, 24)
                screen.feed(b"\x1b[1;38;2;1;2;3;48;5;200m\x1b[?25l\x1b[1;80HX")
                before = screen.cells(), screen.cursor, screen.cursor_visible, screen.alternate, screen.ready
                count = screen.total_bytes
                screen.feed(control)
                self.assertEqual((screen.cells(), screen.cursor, screen.cursor_visible, screen.alternate,
                                  screen.ready), before)
                self.assertEqual(screen.total_bytes, count + len(control))
                screen.feed(b"Y")
                self.assertEqual(screen.cursor, (1, 1))
                self.assertEqual(screen.lines()[0], " " * 79 + "X")
                self.assertEqual(screen.lines()[1], "Y" + " " * 79)
                self.assertEqual(screen.cells()[1][0].style.flags, frozenset({1}))
                self.assertEqual(screen.cells()[1][0].style.foreground, ("rgb", 1, 2, 3))
                self.assertEqual(screen.cells()[1][0].style.background, ("index", 200))

    def test_input_controls_preserve_scroll_region_and_saved_cursor(self):
        screen = T.Screen(80, 24)
        screen.feed(b"TOP\x1b[2;4r\x1b[2;1HA\x1b[3;1HB\x1b[4;1HC\x1b[4;1H\x1b7")
        screen.feed(b"\x1b[?1004;9001h\x1b[0c\x1b[?9001;1004l")
        screen.feed(b"\n\x1b8D")
        self.assertEqual(screen.lines()[:4], tuple(text.ljust(80) for text in ("TOP", "B", "C", "D")))
        self.assertEqual(screen.cursor, (1, 3))
        self.assertTrue(all(not line.strip() for line in screen.lines()[4:]))

    def test_input_controls_do_not_make_alternate_or_resized_buffers_ready(self):
        control = b"\x1b[?1004h\x1b[?9001h\x1b[c\x1b[?1004l\x1b[?9001l\x1b[0c"
        screen = T.Screen()
        screen.feed(b"MAIN\x1b[?1049h" + control)
        self.assertFalse(screen.ready)
        self.assert_code("screen_not_ready", screen.lines)
        screen.feed(b"\x1b[2J" + control)
        self.assertFalse(screen.ready)  # Absolute position is still missing.
        screen.feed(b"\x1b[HUI")
        before = screen.cells(), screen.cursor, screen.alternate
        screen.feed(control)
        self.assertEqual((screen.cells(), screen.cursor, screen.alternate), before)
        screen.resize(80, 24)
        screen.feed(control)
        self.assertFalse(screen.ready)
        self.assert_code("screen_not_ready", screen.lines)
        screen.feed(b"\x1b[2J\x1b[HNEW\x1b[?1049l" + control)
        self.assertFalse(screen.ready)  # Resized primary buffer is also invalid.
        self.assert_code("screen_not_ready", screen.lines)
        screen.feed(b"\x1b[2J\x1b[HMAIN")
        self.assertEqual(screen.lines()[0], "MAIN".ljust(80))

    def test_input_controls_cannot_end_synchronized_output_or_disable_wrap_mode(self):
        control = b"\x1b[?1004;9001h\x1b[c\x1b[?9001;1004l"
        screen = T.Screen(80, 24)
        screen.feed(b"\x1b[?7l\x1b[1;80HX\x1b[?2026h" + control)
        self.assertTrue(screen.pending)
        self.assertFalse(screen.ready)
        self.assert_code("incomplete", screen.lines)
        screen.feed(b"Y\x1b[?2026l")
        self.assertEqual(screen.lines()[0], " " * 79 + "Y")
        self.assertEqual(screen.lines()[1], " " * 80)
        self.assertEqual(screen.cursor, (79, 0))

    def test_nearby_queries_replies_modes_and_malformed_controls_stay_sticky(self):
        refusals = {
            "sequence_unsupported": (b"\x1b[1c", b"\x1b[00c",
                b"\x1b[?c", b"\x1b[?0c", b"\x1b[?1;0c", b"\x1bZ",
                b"\x1b[?3h", b"\x1b[?1000h", b"\x1b[?9002h", b"\x1b[?1004;9001;3h",
                b"\x1b[?9001;9002l", b"\x1b[?1004p", b"\x1b[I", b"\x1b[O"),
            "sequence_invalid": (b"\x1b[>c", b"\x1b[>0c", b"\x1b[=c", b"\x1b[0:c",
                b"\x1b[0;0c", b"\x1b[;c", b"\x1b[?1004$p"),
            "sequence_limit": (b"\x1b[?090001h", b"\x1b[?32768h"),
        }
        for code, vectors in refusals.items():
            for vector in vectors:
                with self.subTest(vector=vector):
                    screen = T.Screen()
                    screen.feed(b"PRIVATE_CANARY")
                    self.assert_code(code, lambda: screen.feed(vector))
                    self.assert_code(code, lambda: screen.feed(b"\x1b[c\x1b[2J\x1b[H"))
                    self.assert_code(code, screen.lines)

    def test_ignored_controls_still_consume_byte_budget_and_truncated_eof_fails(self):
        screen = T.Screen()
        with patch.object(T, "MAX_BYTES", 8):
            screen.feed(b"\x1b[?1004h")
            self.assertEqual(screen.total_bytes, 8)
            self.assert_code("byte_limit", lambda: screen.feed(b"\x1b[c"))
            self.assert_code("byte_limit", screen.lines)
        for prefix in (b"\x1b[?1004", b"\x1b[?9001", b"\x1b[0"):
            screen = T.Screen()
            screen.feed(prefix)
            self.assertTrue(screen.pending)
            self.assert_code("incomplete", screen.finish)
            self.assert_code("incomplete", screen.lines)


if __name__ == "__main__":
    unittest.main()
