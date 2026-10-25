// A finite content witness only. The caller owns runtime observation and cancellation.
// Every pin is read-only with read/write sharing but no delete sharing. Release all
// pins before a fresh owned-runtime observation and any cancellation signal.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace ApplicationLab {
    public sealed class ContentProgressSample {
        public int Sequence { get; internal set; }
        public string State { get; internal set; }
        public long BeforeLength { get; internal set; }
        public long AfterLength { get; internal set; }
        public int ReadBytes { get; internal set; }
        public int VerifiedBytes { get; internal set; }
    }

    // Pure classification is shared by the real reader and synthetic controls.
    public static class ContentProgressPolicy {
        public const int BlockBytes = 65536;
        public const int MaximumVerifiedBytes = 1048576;
        public const int ReadLimit = MaximumVerifiedBytes + BlockBytes;
        public static void Validate(long totalBytes, string[] blocks) {
            Need(totalBytes > ReadLimit && totalBytes <= 67108864 && blocks != null && blocks.Length == 17);
            foreach (string hash in blocks) Need(hash != null && Regex.IsMatch(hash, @"\A[0-9a-f]{64}\z"));
        }
        static void Need(bool value) { if (!value) throw new InvalidOperationException("content_witness_rejected"); }
        public static ContentProgressSample Classify(byte[] data, long before, long after, long totalBytes, string[] blocks) {
            Validate(totalBytes, blocks);
            Need(data != null && before >= 0 && after >= before && after <= totalBytes && data.Length <= ReadLimit && data.Length <= after);
            var value = new ContentProgressSample { State = "pending", BeforeLength = before, AfterLength = after, ReadBytes = data.Length };
            // A short read is not EOF, and file length alone proves no content.
            if (data.Length < Math.Min(after, ReadLimit)) return value;
            if (after == totalBytes || after >= ReadLimit) { value.State = "window_missed"; return value; }
            using (var hash = SHA256.Create()) {
                while (value.VerifiedBytes + BlockBytes <= data.Length) {
                    string actual = BitConverter.ToString(hash.ComputeHash(data, value.VerifiedBytes, BlockBytes)).Replace("-", "").ToLowerInvariant();
                    if (!String.Equals(actual, blocks[value.VerifiedBytes / BlockBytes], StringComparison.Ordinal)) break;
                    value.VerifiedBytes += BlockBytes;
                }
            }
            if (value.VerifiedBytes > MaximumVerifiedBytes) value.State = "window_missed";
            else if (value.VerifiedBytes > 0) value.State = "incomplete_extent";
            return value;
        }
    }

    public sealed class ContentProgressWitness : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low, High; }
        [StructLayout(LayoutKind.Sequential)] struct Info {
            public uint Attributes; public FileTime Created, Accessed, Written;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        sealed class Pin { internal IntPtr Handle; internal string Path; internal Info Identity; internal bool Directory; }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr handle, out Info info);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint length, uint flags);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint GetFileType(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFilePointerEx(IntPtr handle, long distance, out long position, uint method);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr handle, [Out] byte[] bytes, uint count, out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        readonly List<Pin> parents = new List<Pin>();
        readonly Stopwatch clock;
        readonly int deadline;
        readonly long totalBytes;
        readonly string[] blocks;
        readonly Func<bool> additionalBudgetAdmission;
        readonly Func<int, bool> additionalCloseConfirmation;
        int closeAttempts;
        Pin leaf;
        int sequence;
        long firstObservedLength = -1;
        long lastObservedLength;
        bool progressed, missed, failed, closeAttempted;
        public bool Closed { get; private set; }
        public bool CleanupFailed { get; private set; }
        public bool Failed { get { return failed; } }
        public bool ProgressObserved { get { return progressed; } }
        public bool ProofAvailable { get { return progressed && Closed && !CleanupFailed && !failed && !missed; } }

        static void Need(bool value) { if (!value) throw new InvalidOperationException("content_witness_rejected"); }
        static bool Valid(IntPtr handle) { return handle != IntPtr.Zero && handle != new IntPtr(-1); }
        static string Full(string value) {
            Need(value != null && value.Length >= 3 && value.Length < 1024 && value[0] >= 'A' && value[0] <= 'Z' && value[1] == ':' && value[2] == '\\');
            if (value.Length > 3) foreach (string part in value.Substring(3).Split('\\')) {
                Need(part.Length > 0 && part != "." && part != ".." && !part.EndsWith(".", StringComparison.Ordinal) && !part.EndsWith(" ", StringComparison.Ordinal));
                foreach (char c in part) Need(c >= 32 && c <= 126 && "<>:\"/|?*~".IndexOf(c) < 0);
            }
            Need(String.Equals(Path.GetFullPath(value), value, StringComparison.Ordinal));
            return value;
        }
        static string Io(string value) { return @"\\?\" + value; }
        static bool Inside(string root, string value) { return value.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
        static long Size(Info value) { return ((long)value.SizeHigh << 32) | value.SizeLow; }
        static bool Same(Info a, Info b) { return a.Volume == b.Volume && a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow; }
        static Info Information(IntPtr handle) { Info value; Need(GetFileInformationByHandle(handle, out value)); return value; }
        static string FinalPath(IntPtr handle) {
            var text = new StringBuilder(4096);
            uint count = GetFinalPathNameByHandleW(handle, text, 4096, 0);
            Need(count > 0 && count < 4096);
            string value = text.ToString();
            Need(value.StartsWith(@"\\?\", StringComparison.Ordinal));
            return Full(value.Substring(4));
        }
        static void Plain(string value, bool directory) {
            FileAttributes attributes = File.GetAttributes(Io(value));
            Need((attributes & FileAttributes.ReparsePoint) == 0 && ((attributes & FileAttributes.Directory) != 0) == directory);
        }
        bool WithinBudget() {
            return clock != null && clock.IsRunning && clock.ElapsedMilliseconds < deadline &&
                (additionalBudgetAdmission == null || additionalBudgetAdmission());
        }
        void Active() { Need(!closeAttempted && !failed && !missed && WithinBudget()); }
        void Verify(Pin pin) {
            Need(pin != null && Valid(pin.Handle));
            Plain(pin.Path, pin.Directory);
            Info value = Information(pin.Handle);
            Need(GetFileType(pin.Handle) == 1 && Same(value, pin.Identity) && (value.Attributes & 0x400) == 0 && ((value.Attributes & 0x10) != 0) == pin.Directory);
            Need(String.Equals(FinalPath(pin.Handle), pin.Path, StringComparison.OrdinalIgnoreCase));
            if (!pin.Directory) Need(value.Links == 1 && Size(value) >= 0 && Size(value) <= totalBytes);
        }
        Pin Open(string value, bool directory) {
            Active(); Plain(value, directory);
            var pin = new Pin { Path = value, Directory = directory };
            // Track the slot before opening; every acquired handle has a cleanup owner.
            if (directory) parents.Add(pin); else leaf = pin;
            pin.Handle = CreateFileW(Io(value), directory ? 0x81u : 0x80000000u, 3, IntPtr.Zero, 3, directory ? 0x02200000u : 0x00200000u, IntPtr.Zero);
            Need(Valid(pin.Handle));
            pin.Identity = Information(pin.Handle); Verify(pin); return pin;
        }
        long VerifyContent() {
            Active(); foreach (Pin parent in parents) Verify(parent);
            Verify(leaf); return Size(Information(leaf.Handle));
        }
        public ContentProgressWitness(string root, string relativePartial, Stopwatch originalClock, int deadlineMilliseconds, long expectedTotalBytes, string[] expectedBlocks)
            : this(root, relativePartial, originalClock, deadlineMilliseconds, expectedTotalBytes, expectedBlocks, null, null) { }

        // Same-assembly synthetic controls may only deny admission/confirmation, never bypass native checks.
        // Neither seam exposes a handle; public construction always leaves both unset.
        internal ContentProgressWitness(string root, string relativePartial, Stopwatch originalClock, int deadlineMilliseconds, long expectedTotalBytes, string[] expectedBlocks, Func<bool> budgetAdmission, Func<int, bool> closeConfirmation) {
            clock = originalClock; deadline = deadlineMilliseconds; totalBytes = expectedTotalBytes;
            additionalBudgetAdmission = budgetAdmission; additionalCloseConfirmation = closeConfirmation;
            try {
                ContentProgressPolicy.Validate(totalBytes, expectedBlocks);
                blocks = (string[])expectedBlocks.Clone();
                Need(deadline >= 1000 && deadline <= 180000); Active();
                root = Full(root);
                Need(relativePartial != null && relativePartial.Length > 0 && !Path.IsPathRooted(relativePartial));
                string selected = Full(root.TrimEnd('\\') + "\\" + relativePartial);
                Need(Inside(root, selected));
                var chain = new List<string>(); string parent = Path.GetDirectoryName(selected);
                while (!String.IsNullOrEmpty(parent)) { chain.Add(Full(parent)); parent = Path.GetDirectoryName(parent); }
                chain.Reverse(); Need(chain.Count <= 32);
                foreach (string directory in chain) Open(directory, true);
                Open(selected, false); lastObservedLength = VerifyContent();
            } catch {
                failed = true;
                try { Dispose(); } catch { }
                throw new InvalidOperationException("content_witness_rejected");
            }
        }
        public ContentProgressSample Observe() {
            try {
                Active(); Need(!progressed && sequence < 4096);
                long before = VerifyContent(); Need(before >= lastObservedLength);
                long position; Need(SetFilePointerEx(leaf.Handle, 0, out position, 0) && position == 0);
                byte[] data = new byte[ContentProgressPolicy.ReadLimit]; uint count;
                Need(ReadFile(leaf.Handle, data, (uint)data.Length, out count, IntPtr.Zero) && count <= data.Length);
                long after = VerifyContent(); Need(after >= before); lastObservedLength = after;
                if (count != data.Length) Array.Resize(ref data, (int)count);
                ContentProgressSample value = ContentProgressPolicy.Classify(data, before, after, totalBytes, blocks);
                value.Sequence = ++sequence;
                if (value.State == "window_missed") missed = true;
                else if (value.State == "incomplete_extent") {
                    if (firstObservedLength < 0) {
                        // A pre-existing second prefix cannot be split into fake progress.
                        if (after >= 2 * ContentProgressPolicy.BlockBytes) { missed = true; value.State = "window_missed"; }
                        else { firstObservedLength = after; value.State = "first_extent"; }
                    } else if (value.VerifiedBytes > firstObservedLength) {
                        progressed = true; value.State = "progress";
                    } else value.State = "pending";
                }
                return value;
            } catch {
                failed = true;
                throw new InvalidOperationException("content_witness_rejected");
            }
        }
        void Close(Pin pin) {
            if (pin == null || !Valid(pin.Handle)) return;
            int attempt = ++closeAttempts;
            try {
                bool closed = CloseHandle(pin.Handle);
                // A test may turn a real successful close into uncertain evidence, never the reverse.
                if (closed && additionalCloseConfirmation != null) closed = additionalCloseConfirmation(attempt);
                if (closed) pin.Handle = IntPtr.Zero;
                else CleanupFailed = true;
            } catch { CleanupFailed = true; }
            // An uncertain handle value is retained; this instance never attempts a second close.
        }
        public void Dispose() {
            if (closeAttempted) {
                if (!Closed || CleanupFailed) throw new InvalidOperationException("content_witness_cleanup_failed");
                return;
            }
            // Failed admission cannot suppress mandatory cleanup or earn content proof.
            try {
                if (!WithinBudget()) failed = true;
                foreach (Pin parent in parents) Verify(parent);
                if (leaf != null && Valid(leaf.Handle)) {
                    Verify(leaf);
                    long finalLength = Size(Information(leaf.Handle));
                    if (finalLength < lastObservedLength) failed = true;
                    if (finalLength >= totalBytes || finalLength >= ContentProgressPolicy.ReadLimit) missed = true;
                }
            } catch { failed = true; }
            closeAttempted = true;
            Close(leaf);
            for (int i = parents.Count - 1; i >= 0; i--) Close(parents[i]);
            Closed = !CleanupFailed;
            try { if (!WithinBudget()) failed = true; } catch { failed = true; }
            if (!Closed) throw new InvalidOperationException("content_witness_cleanup_failed");
        }
    }
}
