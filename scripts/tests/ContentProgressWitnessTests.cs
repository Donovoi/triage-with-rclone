using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using ApplicationLab;

public static class ContentProgressWitnessTests {
    static readonly List<string> started = new List<string>();
    static readonly List<string> passed = new List<string>();
    static bool runStarted;
    public static string[] StartedCases { get { return started.ToArray(); } }
    public static string[] CompletedCases { get { return passed.ToArray(); } }
    static void Begin(string name) { started.Add(name); }
    const int Block = 65536;
    const long Total = 16777216;
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateHardLinkW(string link, string existing, IntPtr security);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DeviceIoControl(IntPtr handle, uint code, byte[] input, int inputLength, IntPtr output, int outputLength, out int returned, IntPtr overlap);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    static void Check(bool value) { if (!value) throw new InvalidOperationException("synthetic_control_failed"); }
    static void Rejected(Action action) {
        bool rejected = false;
        try { action(); } catch (InvalidOperationException error) {
            if (error.Message != "content_witness_rejected" && error.Message != "content_witness_cleanup_failed") throw;
            rejected = true;
        }
        Check(rejected);
    }
    static void Blocked(Action action) {
        bool blocked = false;
        try { action(); } catch (IOException) { blocked = true; }
        Check(blocked);
    }
    static byte[] Fixture(int count) {
        var bytes = new byte[count];
        for (int i = 0; i < count; i++) bytes[i] = (byte)((i % Block + (i / Block) * 17) % 251);
        return bytes;
    }
    // Independent fixed oracle: SHA-256 of block j bytes (offset + 17*j) modulo 251.
    // Calculated as inert source data separately from the C# producer/reader.
    static string[] Hashes() {
        return new string[] {
            "4b640d85ab3ba30fd02c9fc9db4a8928f416322ad27022ea58a65aaee68a4df2",
            "e05a19880e522ec8b96bf1098d4660e3d467fd307333541f39f21463f7a34312",
            "38d9be03ab889d1ee341e65b8cb5491172d17de45c728b84c571c024713390f7",
            "776cd7af10b70566e7fab9ad3f3592a2178a1127902af181c3024f191a772327",
            "38780e0e8b1cfbea2c2e4a78a520b7f5a8b948106cb2c8400f2285475c82a01d",
            "067a75762a939676fab6dc7725500d610def31d4fc2f2abdec9a7db4ccce3635",
            "cec41101b9bacfc95afbe8ceeb47b01acc402203627cf8be12be995ba5f65b22",
            "807782141c6d708971dae6a7a357f89de8988863319166ca1035abb76761ab54",
            "b28c42987b2e0f553bb970078803ddb94bf78bb87a2dd1283e00f40758c767ba",
            "79852f8934a3c41a7c53b618d7a8936943275fbbcafda933ea9f3438d07d5a26",
            "d0279d356a8b59526391b655df607b7268038da0d69735563aae15f44769ce12",
            "aaadd4d2f6591502d83e14340ed97813fe4c1ebc3abe9d28b6ba37f30fc22f23",
            "526f2424e6330b2d608df921e74b08a3bef55337bdad71a45143f1d0d7ff1324",
            "13cf6d4d5e87b3da8fb8ab06b9993c72dca09868996d2ffcddc7083960798d70",
            "533d8ad99923996dca855c923e23902080aae9ade834cb9943837f0fa48db4e4",
            "3a0799e508a24b476a7ab3d73b78ff1889d432ec397eea527d95250fe4d23cce",
            "2bd385f883af6508ba9ab6ff714737a4ef89ee3040090edfd66fa1983c75f11d"
        };
    }
    static void WriteNew(string file, byte[] bytes) {
        using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite)) { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
    }
    static string Case(string root, string name) {
        string value = Path.Combine(root, name);
        Check(!Directory.Exists(value) && !File.Exists(value)); Directory.CreateDirectory(value); return value;
    }
    static ContentProgressWitness Open(string root, string leaf, Stopwatch clock) {
        return new ContentProgressWitness(root, leaf, clock, 120000, Total, Hashes());
    }
    static void RemoveCase(string directory) {
        foreach (string item in Directory.GetFiles(directory)) File.Delete(item);
        Check(Directory.GetDirectories(directory).Length == 0);
        Directory.Delete(directory); Check(!Directory.Exists(directory));
    }
    static void Junction(string link, string target) {
        Directory.CreateDirectory(link);
        string substitute = @"\??\" + target;
        byte[] sub = Encoding.Unicode.GetBytes(substitute), print = Encoding.Unicode.GetBytes(target);
        var buffer = new byte[16 + sub.Length + 2 + print.Length + 2];
        Action<int, ushort> put = delegate(int offset, ushort value) { Array.Copy(BitConverter.GetBytes(value), 0, buffer, offset, 2); };
        Array.Copy(BitConverter.GetBytes(0xA0000003u), 0, buffer, 0, 4);
        put(4, (ushort)(buffer.Length - 8)); put(8, 0); put(10, (ushort)sub.Length);
        put(12, (ushort)(sub.Length + 2)); put(14, (ushort)print.Length);
        Array.Copy(sub, 0, buffer, 16, sub.Length); Array.Copy(print, 0, buffer, 18 + sub.Length, print.Length);
        IntPtr handle = CreateFileW(link, 0x40000000, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        Check(handle != IntPtr.Zero && handle != new IntPtr(-1));
        try { int returned; Check(DeviceIoControl(handle, 0x000900A4, buffer, buffer.Length, IntPtr.Zero, 0, out returned, IntPtr.Zero)); }
        finally { Check(CloseHandle(handle)); }
    }
    static void Growing(string root) {
        string directory = Case(root, "growing"), file = Path.Combine(directory, "partial.bin");
        var first = new ManualResetEventSlim(false); var grow = new ManualResetEventSlim(false);
        var second = new ManualResetEventSlim(false); var closeWriter = new ManualResetEventSlim(false);
        Exception writerError = null; bool writerClosed = false;
        var writer = new Thread(delegate() {
            try {
                using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite)) {
                    byte[] content = Fixture(2 * Block); stream.Write(content, 0, Block); stream.Flush(true); first.Set();
                    Check(grow.Wait(5000)); stream.Write(content, Block, Block); stream.Flush(true); second.Set();
                    Check(closeWriter.Wait(5000));
                }
                writerClosed = true;
            } catch (Exception error) { writerError = error; first.Set(); second.Set(); }
        });
        writer.IsBackground = true; ContentProgressWitness witness = null;
        try {
            writer.Start(); Check(first.Wait(5000) && writerError == null);
            witness = Open(directory, "partial.bin", Stopwatch.StartNew());
            var a = witness.Observe(); Check(a.State == "first_extent" && a.VerifiedBytes == Block && a.AfterLength == Block);
            var same = witness.Observe(); Check(same.State == "pending" && !witness.ProgressObserved && !witness.ProofAvailable);
            grow.Set(); Check(second.Wait(5000) && writerError == null);
            var b = witness.Observe(); Check(b.State == "progress" && b.VerifiedBytes == 2 * Block && b.Sequence > a.Sequence && b.VerifiedBytes > a.AfterLength);
            Check(witness.ProgressObserved && !witness.ProofAvailable);
            closeWriter.Set(); Check(writer.Join(5000) && writerClosed && writerError == null);
            Blocked(delegate { File.Move(file, file + ".moved"); });
            Blocked(delegate { Directory.Move(directory, directory + "-moved"); });
            witness.Dispose(); Check(witness.Closed && !witness.CleanupFailed && witness.ProofAvailable);
            witness.Dispose(); Check(witness.ProofAvailable);
            File.Move(file, file + ".moved"); File.Delete(file + ".moved"); Directory.Delete(directory);
        } finally {
            grow.Set(); closeWriter.Set();
            if (writer.IsAlive) Check(writer.Join(5000));
            if (witness != null) witness.Dispose();
            first.Dispose(); grow.Dispose(); second.Dispose(); closeWriter.Dispose();
        }
    }
    static int ParentCount(string file) {
        int count = 0; string parent = Path.GetDirectoryName(file);
        while (!String.IsNullOrEmpty(parent)) { count++; parent = Path.GetDirectoryName(parent); }
        return count;
    }
    static void Advance(ContentProgressWitness witness, string file) {
        Check(witness.Observe().State == "first_extent");
        using (var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) {
            byte[] bytes = Fixture(2 * Block); stream.Position = Block;
            stream.Write(bytes, Block, Block); stream.Flush(true);
        }
        Check(witness.Observe().State == "progress" && !witness.ProofAvailable);
    }
    static void FinalGrowth(string root, string name, long finalLength) {
        string directory = Case(root, name), file = Path.Combine(directory, "partial.bin");
        WriteNew(file, Fixture(Block)); var witness = Open(directory, "partial.bin", Stopwatch.StartNew());
        try {
            Advance(witness, file);
            using (var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) {
                stream.SetLength(finalLength); stream.Flush(true);
            }
        } finally { witness.Dispose(); }
        Check(witness.ProgressObserved && witness.Closed && !witness.CleanupFailed && !witness.ProofAvailable);
        RemoveCase(directory);
    }
    public static string[] Run(string root) {
        Check(!runStarted); runStarted = true; string[] hashes = Hashes();
        Check(Directory.Exists(root) && Directory.GetFileSystemEntries(root).Length == 0);
        Begin("short_read_is_pending");
        var shortRead = ContentProgressPolicy.Classify(Fixture(Block - 1), Block, Block, Total, hashes);
        Check(shortRead.State == "pending" && shortRead.VerifiedBytes == 0); passed.Add("short_read_is_pending");
        Begin("wrong_content_is_not_progress");
        var wrong = ContentProgressPolicy.Classify(new byte[Block], Block, Block, Total, hashes);
        Check(wrong.State == "pending" && wrong.VerifiedBytes == 0); passed.Add("wrong_content_is_not_progress");
        Begin("complete_length_is_missed");
        var complete = ContentProgressPolicy.Classify(Fixture(ContentProgressPolicy.ReadLimit), Total, Total, Total, hashes);
        Check(complete.State == "window_missed"); passed.Add("complete_length_is_missed");
        Begin("read_cap_is_missed");
        var overshot = ContentProgressPolicy.Classify(Fixture(ContentProgressPolicy.ReadLimit), ContentProgressPolicy.ReadLimit, ContentProgressPolicy.ReadLimit, Total, hashes);
        Check(overshot.State == "window_missed"); passed.Add("read_cap_is_missed");
        Begin("invalid_read_bounds_rejected");
        Rejected(delegate { ContentProgressPolicy.Classify(Fixture(Block), Block + 1, Block, Total, hashes); });
        Rejected(delegate { ContentProgressPolicy.Classify(Fixture(Block), 0, Block - 1, Total, hashes); });
        Rejected(delegate { ContentProgressPolicy.Classify(new byte[ContentProgressPolicy.ReadLimit + 1], 0, ContentProgressPolicy.ReadLimit + 1, Total, hashes); });
        passed.Add("invalid_read_bounds_rejected");
        Begin("independent_hash_contract_rejected");
        var badHashes = (string[])hashes.Clone(); badHashes[0] = "BAD";
        Rejected(delegate { ContentProgressPolicy.Validate(Total, badHashes); });
        Rejected(delegate { ContentProgressPolicy.Validate(Total, new string[16]); }); passed.Add("independent_hash_contract_rejected");
        Begin("barrier_growth_and_real_release");
        Growing(root); passed.Add("barrier_growth_and_real_release");
        Begin("already_present_second_extent_is_missed");
        string directory = Case(root, "already_two"), file = Path.Combine(directory, "partial.bin");
        WriteNew(file, Fixture(2 * Block));
        using (var witness = Open(directory, "partial.bin", Stopwatch.StartNew())) {
            Check(witness.Observe().State == "window_missed" && !witness.ProgressObserved);
        }
        RemoveCase(directory); passed.Add("already_present_second_extent_is_missed");
        Begin("preallocation_is_not_progress");
        directory = Case(root, "preallocated"); file = Path.Combine(directory, "partial.bin");
        using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.ReadWrite)) stream.SetLength(Total);
        using (var witness = Open(directory, "partial.bin", Stopwatch.StartNew())) Check(witness.Observe().State == "window_missed" && !witness.ProgressObserved);
        RemoveCase(directory); passed.Add("preallocation_is_not_progress");
        Begin("length_regression_poisoned");
        directory = Case(root, "regression"); file = Path.Combine(directory, "partial.bin"); WriteNew(file, Fixture(Block));
        var regressed = Open(directory, "partial.bin", Stopwatch.StartNew());
        try {
            Check(regressed.Observe().State == "first_extent");
            using (var stream = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite)) stream.SetLength(1);
            Rejected(delegate { regressed.Observe(); }); Check(regressed.Failed);
        } finally { regressed.Dispose(); }
        Check(!regressed.ProofAvailable && regressed.Closed); RemoveCase(directory); passed.Add("length_regression_poisoned");
        Begin("path_and_original_clock_rejected");
        directory = Case(root, "wrong_leaf"); file = Path.Combine(directory, "partial.bin"); WriteNew(file, Fixture(Block));
        Rejected(delegate { using (var witness = Open(directory, "..\\wrong_leaf\\partial.bin", Stopwatch.StartNew())) { } });
        Rejected(delegate { using (var witness = Open(directory, "partial.bin:stream", Stopwatch.StartNew())) { } });
        Rejected(delegate { using (var witness = Open(directory, "partial.bin", new Stopwatch())) { } });
        RemoveCase(directory); passed.Add("path_and_original_clock_rejected");
        Begin("real_multilink_rejected_and_released");
        directory = Case(root, "hardlink"); file = Path.Combine(directory, "partial.bin"); WriteNew(file, Fixture(Block));
        string link = Path.Combine(directory, "alias.bin"); Check(CreateHardLinkW(link, file, IntPtr.Zero));
        Rejected(delegate { using (var witness = Open(directory, "partial.bin", Stopwatch.StartNew())) { } });
        RemoveCase(directory); passed.Add("real_multilink_rejected_and_released");
        Begin("real_reparse_parent_rejected_and_released");
        directory = Case(root, "reparse"); string target = Path.Combine(directory, "target"), junction = Path.Combine(directory, "link");
        Directory.CreateDirectory(target); file = Path.Combine(target, "partial.bin"); WriteNew(file, Fixture(Block)); Junction(junction, target);
        Rejected(delegate { using (var witness = Open(directory, "link\\partial.bin", Stopwatch.StartNew())) { } });
        Directory.Delete(junction); File.Delete(file); Directory.Delete(target); Directory.Delete(directory); passed.Add("real_reparse_parent_rejected_and_released");
        Begin("clock_failure_cannot_skip_release");
        directory = Case(root, "stopped_clock"); file = Path.Combine(directory, "partial.bin"); WriteNew(file, Fixture(Block));
        var clock = Stopwatch.StartNew(); var expired = Open(directory, "partial.bin", clock); Check(expired.Observe().State == "first_extent");
        clock.Stop(); Rejected(delegate { expired.Observe(); }); expired.Dispose(); Check(!expired.ProofAvailable && expired.Closed);
        RemoveCase(directory); passed.Add("clock_failure_cannot_skip_release");
        Begin("final_completed_length_removes_proof");
        FinalGrowth(root, "completed_before_close", Total); passed.Add("final_completed_length_removes_proof");
        Begin("final_read_cap_removes_proof");
        FinalGrowth(root, "read_cap_before_close", ContentProgressPolicy.ReadLimit); passed.Add("final_read_cap_removes_proof");
        Begin("injected_post_close_budget_denial");
        directory = Case(root, "post_close_budget"); file = Path.Combine(directory, "partial.bin"); WriteNew(file, Fixture(Block));
        ContentProgressWitness budget = null; int budgetDenials = 0;
        budget = new ContentProgressWitness(directory, "partial.bin", Stopwatch.StartNew(), 120000, Total, Hashes(),
            delegate { if (budget != null && budget.Closed) { budgetDenials++; return false; } return true; }, null);
        try { Advance(budget, file); } finally { budget.Dispose(); }
        Check(budgetDenials == 1 && budget.Closed && budget.Failed && !budget.ProofAvailable);
        budget.Dispose(); Check(budgetDenials == 1); RemoveCase(directory); passed.Add("injected_post_close_budget_denial");
        Begin("injected_close_failure_sticky_and_remaining_pins");
        directory = Case(root, "uncertain_close"); file = Path.Combine(directory, "partial.bin"); WriteNew(file, Fixture(Block));
        int closeCalls = 0, expectedCloses = ParentCount(file) + 1;
        var uncertain = new ContentProgressWitness(directory, "partial.bin", Stopwatch.StartNew(), 120000, Total, Hashes(), null,
            delegate(int attempt) { Check(attempt == ++closeCalls); return attempt != 1; });
        try { Advance(uncertain, file); } finally { Rejected(delegate { uncertain.Dispose(); }); }
        Check(closeCalls == expectedCloses && uncertain.CleanupFailed && !uncertain.Closed && !uncertain.ProofAvailable);
        Rejected(delegate { uncertain.Dispose(); }); Rejected(delegate { uncertain.Observe(); }); Check(closeCalls == expectedCloses);
        // The injected uncertainty follows a real successful close; deletion proves all real pins released.
        RemoveCase(directory); passed.Add("injected_close_failure_sticky_and_remaining_pins");
        Begin("partial_construction_close_failure_attempts_all_pins");
        directory = Case(root, "partial_construction"); file = Path.Combine(directory, "absent.bin");
        int partialCloses = 0, expectedPartialCloses = ParentCount(file);
        Rejected(delegate {
            using (var unused = new ContentProgressWitness(directory, "absent.bin", Stopwatch.StartNew(), 120000, Total, Hashes(), null,
                delegate(int attempt) { Check(attempt == ++partialCloses); return attempt != 1; })) { }
        });
        Check(partialCloses == expectedPartialCloses && partialCloses > 0);
        RemoveCase(directory); passed.Add("partial_construction_close_failure_attempts_all_pins");
        Check(Directory.GetFileSystemEntries(root).Length == 0);
        return passed.ToArray();
    }
}
