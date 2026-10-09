"""Bounded, fail-closed VT text grid for private hosted ConPTY transcripts.

No I/O, terminal replies, acceptance decision, transcript logging or dependencies.
feed() accepts UTF-8 bytes across arbitrary chunk boundaries. lines()/text()/cells()
return immutable snapshots only at a complete, unsynchronized parser boundary.
finish() additionally rejects a truncated EOF. Any parse/limit error is sticky.

This is a deliberately closed subset, not a general terminal emulator. Printable
single-column Unicode is supported; combining, wide/fullwidth and format/control
characters are refused rather than assigned an invented cell width. OSC 0/2 titles
are bounded and discarded; hyperlinks, clipboard operations and unknown VT fail.
SGR attributes are retained, but this module does not claim pixel/color fidelity.

resize() discards both grids and invalidates them until each active buffer receives
ED2 plus an absolute CUP/HVP. Drain old-size transcript bytes before acknowledging
resize; this parser cannot establish the ordering of ConPTY output and resize.
Snapshot availability is not proof that an application redraw has finished.

References: Microsoft Console Virtual Terminal Sequences (cursor, erase, margins,
SGR, OSC and alternate buffer); xterm ctlseqs (synchronized output); pinned
crossterm 0.28.1 and ratatui-crossterm sources. No incoming escape is executed.
"""
import codecs
from typing import NamedTuple
import unicodedata


MAX_BYTES = 8 * 1024 * 1024
MAX_SEQUENCE = 128
MAX_OSC_BYTES = 1024
MAX_CELL_UPDATES = 32 * 1024 * 1024
MAX_SCROLL_ROWS = 32768
CODES = frozenset({
    "input_invalid", "size_invalid", "byte_limit", "sequence_limit",
    "control_invalid", "sequence_invalid", "sequence_unsupported",
    "utf8_invalid", "unicode_unsupported", "operation_limit", "scroll_limit",
    "incomplete", "screen_not_ready", "stream_finished",
})


class ScreenError(ValueError):
    """Static code only; never retains or renders source transcript bytes."""

    def __init__(self, code):
        self.code = code if code in CODES else "input_invalid"
        super().__init__(self.code)


class Style(NamedTuple):
    flags: frozenset = frozenset()
    foreground: tuple = ()
    background: tuple = ()
    underline: tuple = ()


class Cell(NamedTuple):
    character: str
    style: Style


class _Buffer:
    def __init__(self, columns, rows, ready=True):
        self.grid = [[Cell(" ", Style()) for _ in range(columns)] for _ in range(rows)]
        self.x = self.y = self.top = 0
        self.bottom = rows - 1
        self.saved = None
        self.wrap_pending = False
        self.erased = self.positioned = ready


class Screen:
    def __init__(self, columns=120, rows=34):
        self._error = None
        self._check_size(columns, rows)
        self.columns, self.rows = columns, rows
        self._primary = _Buffer(columns, rows)
        self._alternate = None
        self._buffer = self._primary
        self._style = Style()
        self._decoder = codecs.getincrementaldecoder("utf-8")("strict")
        self._state, self._sequence = "ground", ""
        self._osc_bytes = 0
        self._bytes = self._updates = self._scroll_rows = 0
        self._finished = self._sync = False
        self._wrap = True
        self.cursor_visible = True

    def _fail(self, code):
        self._error = self._error or code
        raise ScreenError(self._error) from None

    def _check(self):
        if self._error:
            raise ScreenError(self._error)

    def _check_size(self, columns, rows):
        if (type(columns) is not int or type(rows) is not int
                or not 80 <= columns <= 120 or not 24 <= rows <= 34):
            self._fail("size_invalid")

    @property
    def pending(self):
        return bool(self._state != "ground" or self._decoder.getstate()[0] or self._sync)

    @property
    def ready(self):
        return (not self._error and not self.pending
                and self._buffer.erased and self._buffer.positioned)

    @property
    def alternate(self):
        return self._alternate is not None

    @property
    def total_bytes(self):
        return self._bytes

    @property
    def cursor(self):
        self._snapshot_guard()
        return self._buffer.x, self._buffer.y

    def _snapshot_guard(self):
        self._check()
        if self.pending:
            raise ScreenError("incomplete")
        if not self.ready:
            raise ScreenError("screen_not_ready")

    def cells(self):
        self._snapshot_guard()
        return tuple(tuple(row) for row in self._buffer.grid)

    def lines(self):
        """Exactly rows fixed-width strings; concealed SGR cells appear blank."""
        return tuple("".join(" " if 8 in c.style.flags else c.character for c in row)
                     for row in self.cells())

    def text(self):
        return "\n".join(self.lines())

    def resize(self, columns, rows):
        self._check()
        self._check_size(columns, rows)
        if self._finished:
            self._fail("stream_finished")
        if self.pending:
            self._fail("incomplete")
        if (columns, rows) == (self.columns, self.rows):
            return
        self._charge(columns * rows * (2 if self.alternate else 1))
        self.columns, self.rows = columns, rows
        self._primary = _Buffer(columns, rows, ready=False)
        if self.alternate:
            # The old main-buffer cursor cannot survive a resize as a known
            # position. Leaving the alternate buffer still requires a redraw.
            self._primary.saved = (0, 0, False, self._style, False)
            self._alternate = _Buffer(columns, rows, ready=False)
        self._buffer = self._alternate or self._primary

    def feed(self, data):
        self._check()
        if self._finished:
            self._fail("stream_finished")
        if type(data) is not bytes:
            self._fail("input_invalid")
        if len(data) > MAX_BYTES - self._bytes:
            self._fail("byte_limit")
        self._bytes += len(data)
        try:
            decoded = self._decoder.decode(data, final=False)
        except UnicodeError:
            self._fail("utf8_invalid")
        for char in decoded:
            self._consume(char)

    def finish(self):
        self._check()
        if self._finished:
            return
        try:
            self._decoder.decode(b"", final=True)
        except UnicodeError:
            self._fail("utf8_invalid")
        if self.pending:
            self._fail("incomplete")
        self._finished = True
        self._snapshot_guard()

    def _charge(self, count):
        self._updates += count
        if self._updates > MAX_CELL_UPDATES:
            self._fail("operation_limit")

    def _consume(self, char):
        if self._state == "osc_escape":
            if char != "\\":
                self._fail("sequence_invalid")
            self._finish_osc()
        elif self._state == "osc":
            if char == "\x07":
                self._finish_osc()
            elif char == "\x1b":
                self._state = "osc_escape"
            else:
                if unicodedata.category(char).startswith("C") or char in "\u2028\u2029":
                    self._fail("control_invalid")
                self._osc_bytes += len(char.encode("utf-8"))
                if self._osc_bytes > MAX_OSC_BYTES:
                    self._fail("sequence_limit")
                self._sequence += char
        elif self._state == "csi":
            if "@" <= char <= "~":
                body = self._sequence
                self._state, self._sequence = "ground", ""
                self._csi(body, char)
            elif " " <= char <= "?":
                if len(self._sequence) >= MAX_SEQUENCE:
                    self._fail("sequence_limit")
                self._sequence += char
            else:
                self._fail("sequence_invalid")
        elif self._state == "charset":
            if char != "B":
                self._fail("sequence_unsupported")
            self._state = "ground"
        elif self._state == "escape":
            self._state = "ground"
            if char == "[":
                self._state, self._sequence = "csi", ""
            elif char == "]":
                self._state, self._sequence, self._osc_bytes = "osc", "", 0
            elif char == "(":
                self._state = "charset"
            elif char in "78":
                self._save_restore(char == "7")
            elif char in "DEM":
                if char == "E":
                    self._buffer.x = 0
                self._index(-1 if char == "M" else 1)
            elif char not in "=>":  # Input keypad mode only; no screen effect.
                self._fail("sequence_unsupported")
        elif char == "\x1b":
            self._state = "escape"
        elif char in "\r\n\b\t\x07":
            b = self._buffer
            if char == "\r":
                b.x, b.wrap_pending = 0, False
            elif char == "\n":
                self._index(1)
            elif char == "\b":
                b.x, b.wrap_pending = max(0, b.x - 1), False
            elif char == "\t":
                b.x, b.wrap_pending = min(self.columns - 1, (b.x // 8 + 1) * 8), False
        else:
            if (not char.isprintable() or unicodedata.category(char).startswith(("C", "M"))
                    or unicodedata.east_asian_width(char) in ("W", "F")):
                self._fail("unicode_unsupported")
            self._put(char)

    def _finish_osc(self):
        kind, separator, title = self._sequence.partition(";")
        if kind not in ("0", "2"):
            self._fail("sequence_unsupported")
        if not separator or len(title) >= 255:
            self._fail("sequence_invalid")
        self._state, self._sequence = "ground", ""

    def _put(self, char):
        b = self._buffer
        if b.wrap_pending:
            b.x = 0
            self._index(1)
        self._charge(1)
        b.grid[b.y][b.x] = Cell(char, self._style)
        if b.x == self.columns - 1:
            b.wrap_pending = self._wrap
        else:
            b.x += 1

    def _scroll(self, top, bottom, count):
        self._scroll_rows += abs(count)
        if self._scroll_rows > MAX_SCROLL_ROWS:
            self._fail("scroll_limit")
        height = bottom - top + 1
        n = min(abs(count), height)
        self._charge(height * self.columns)
        blank = [[Cell(" ", self._style) for _ in range(self.columns)] for _ in range(n)]
        old = self._buffer.grid[top:bottom + 1]
        self._buffer.grid[top:bottom + 1] = old[n:] + blank if count > 0 else blank + old[:height - n]

    def _index(self, direction):
        b = self._buffer
        b.wrap_pending = False
        if direction > 0 and b.y == b.bottom:
            self._scroll(b.top, b.bottom, 1)
        elif direction < 0 and b.y == b.top:
            self._scroll(b.top, b.bottom, -1)
        else:
            b.y = max(0, min(self.rows - 1, b.y + direction))

    def _save_restore(self, save):
        b = self._buffer
        if save:
            b.saved = (b.x, b.y, b.wrap_pending, self._style, b.positioned)
        elif b.saved is None:
            self._fail("sequence_invalid")
        else:
            b.x, b.y, b.wrap_pending, self._style, b.positioned = b.saved

    def _parameters(self, body):
        if any(c not in "0123456789;" for c in body):
            self._fail("sequence_invalid")
        parts = body.split(";") if body else []
        if len(parts) > 32 or any(len(p) > 5 for p in parts):
            self._fail("sequence_limit")
        values = [int(p) if p else 0 for p in parts]
        if any(v > 32767 for v in values):
            self._fail("sequence_limit")
        return values

    def _csi(self, body, final):
        if body.startswith("?"):
            values = self._parameters(body[1:])
            if final not in "hl" or not values:
                self._fail("sequence_unsupported")
            for value in values:
                self._mode(value, final == "h")
            return
        if final == "q" and body.endswith(" "):
            values = self._parameters(body[:-1])
            if len(values) > 1 or (values and values[0] > 6):
                self._fail("sequence_invalid")
            return  # Cursor shape only; cursor visibility is separately retained.
        values = self._parameters(body)
        b = self._buffer
        if final == "m":
            self._sgr(values or [0])
            return
        if final in "su":
            if values:
                self._fail("sequence_invalid")
            self._save_restore(final == "s")
            return
        if final in "Hfr":
            if len(values) > 2:
                self._fail("sequence_invalid")
            first = (values[0] if values else 0) or 1
            second = (values[1] if len(values) > 1 else 0) or (self.rows if final == "r" else 1)
            if final == "r":
                if not 1 <= first < second <= self.rows:
                    self._fail("sequence_invalid")
                b.top, b.bottom, b.x, b.y = first - 1, second - 1, 0, 0
            else:
                b.y, b.x = min(self.rows, first) - 1, min(self.columns, second) - 1
            b.positioned, b.wrap_pending = True, False
            return
        if len(values) > 1:
            self._fail("sequence_invalid")
        value = values[0] if values else 0
        n = value or 1
        if final in "ABCDEFGd":
            if final in "ABEF":
                b.y = max(0, min(self.rows - 1, b.y + (n if final in "BE" else -n)))
                if final in "EF":
                    b.x = 0
            elif final in "CD":
                b.x = max(0, min(self.columns - 1, b.x + (n if final == "C" else -n)))
            elif final == "G":
                b.x = min(self.columns, n) - 1
            else:
                b.y = min(self.rows, n) - 1
        elif final in "JK":
            if value not in (0, 1, 2) and not (final == "J" and value == 3):
                self._fail("sequence_invalid")
            if value == 3:
                return  # No scrollback is retained.
            if final == "J":
                pos = b.y * self.columns + b.x
                start, stop = (pos, self.rows * self.columns) if value == 0 else (0, pos + 1)
                if value == 2:
                    start, stop, b.erased = 0, self.rows * self.columns, True
            else:
                start = b.y * self.columns + (b.x if value == 0 else 0)
                stop = b.y * self.columns + (b.x + 1 if value == 1 else self.columns)
            self._charge(stop - start)
            for offset in range(start, stop):
                b.grid[offset // self.columns][offset % self.columns] = Cell(" ", self._style)
        elif final in "ST":
            self._scroll(b.top, b.bottom, n if final == "S" else -n)
        elif final in "LM":
            if b.top <= b.y <= b.bottom:
                self._scroll(b.y, b.bottom, -n if final == "L" else n)
        elif final in "@PX":
            n = min(n, self.columns - b.x)
            self._charge(self.columns - b.x)
            row = b.grid[b.y]
            blank = [Cell(" ", self._style)] * n
            if final == "@":
                row[b.x:] = blank + row[b.x:self.columns - n]
            elif final == "P":
                row[b.x:] = row[b.x + n:] + blank
            else:
                row[b.x:b.x + n] = blank
        else:
            self._fail("sequence_unsupported")
        b.wrap_pending = False

    def _mode(self, value, enabled):
        if value == 1049:
            if enabled and not self.alternate:
                self._charge(self.columns * self.rows)
                self._save_restore(True)
                self._alternate = _Buffer(self.columns, self.rows, ready=False)
                self._buffer = self._alternate
            elif not enabled and self.alternate:
                self._buffer, self._alternate = self._primary, None
                self._save_restore(False)
        elif value == 7:
            self._wrap = enabled
            self._buffer.wrap_pending = False
        elif value == 25:
            self.cursor_visible = enabled
        elif value == 2026:
            self._sync = enabled
        elif value not in (1, 12, 2004):  # Input cursor mode, cursor blink, bracketed paste.
            self._fail("sequence_unsupported")

    def _sgr(self, values):
        flags = set(self._style.flags)
        colors = [self._style.foreground, self._style.background, self._style.underline]
        i = 0
        while i < len(values):
            v = values[i]
            if v == 0:
                flags, colors = set(), [(), (), ()]
            elif v in range(1, 10) or v == 21:
                flags.add(v)
            elif v in (22, 23, 24, 25, 27, 28, 29):
                flags.difference_update({22: {1, 2}, 23: {3}, 24: {4, 21}, 25: {5, 6},
                                         27: {7}, 28: {8}, 29: {9}}[v])
            elif v in (39, 49, 59):
                colors[{39: 0, 49: 1, 59: 2}[v]] = ()
            elif 30 <= v <= 37 or 90 <= v <= 97:
                colors[0] = ("index", v - 30 if v < 90 else v - 90 + 8)
            elif 40 <= v <= 47 or 100 <= v <= 107:
                colors[1] = ("index", v - 40 if v < 100 else v - 100 + 8)
            elif v in (38, 48, 58):
                if i + 1 >= len(values) or values[i + 1] not in (2, 5):
                    self._fail("sequence_invalid")
                count = 3 if values[i + 1] == 2 else 1
                components = values[i + 2:i + 2 + count]
                if len(components) != count or any(c > 255 for c in components):
                    self._fail("sequence_invalid")
                colors[{38: 0, 48: 1, 58: 2}[v]] = ("rgb" if count == 3 else "index", *components)
                i += count + 1
            else:
                self._fail("sequence_unsupported")
            i += 1
        self._style = Style(frozenset(flags), *colors)
