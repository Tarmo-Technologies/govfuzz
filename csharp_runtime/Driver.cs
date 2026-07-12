// SPDX-License-Identifier: Apache-2.0
//
// govfuzz C# / .NET fork-server driver — the managed analog of
// python_runtime/govfuzz_driver.py and java_runtime Driver.java. Speaks the SAME
// GOVFUZZ_FRAMED protocol so the builtin engine drives a warm, long-lived CLR one
// input at a time (amortizing JIT + assembly-load startup), exactly like a
// C/Rust fork-server binary — no AFL fork-server, no libFuzzer.
//
// Coverage bridge: SharpFuzz instruments the target IL to increment
// SharpFuzz.Common.Trace.SharedMem[prev ^ cur]. AFL's own map is 1<<16 bytes,
// which is exactly govfuzz's GOVFUZZ_COV_BITS. We mmap the engine's file-backed
// GOVFUZZ_COV_SHM (MAP_SHARED, 65536 bytes) and point Trace.SharedMem at it, so
// the instrumented target writes coverage straight into the engine's cumulative
// AFL-style edge bitmap — no shmat, no AFL runtime.
//
// Protocol (must match the C driver):
//   1. Save the engine's control pipe (fd 1) to a private fd, then redirect fd 1
//      to /dev/null so the target's stdout can't corrupt the sync stream (#427).
//   2. Write one ready byte to the control fd.
//   3. Loop: read {u32 little-endian length, bytes} from fd 0, run the harness,
//      write one sync byte to the control fd.
// An uncaught FINDING exception halts the process (exit 86) with no sync byte, so
// the engine sees the death and re-isolates the input. An expected rejection
// (input validation / our-fault type mismatch) is swallowed — the input is just
// rejected.
//
// Without GOVFUZZ_FRAMED, argv[0] is a single input file to replay once (the
// engine's per-spawn crash-isolation path), else stdin is read.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

internal static unsafe class Driver
{
    private const int FindingHaltCode = 86;
    private const int CovBits = 1 << 16; // matches GOVFUZZ_COV_BITS and the AFL map

    // ---- libc P/Invoke (Linux) for the framed control fd + coverage mmap -------
    [DllImport("libc", SetLastError = true)]
    private static extern int open(string path, int flags, int mode);

    [DllImport("libc", SetLastError = true)]
    private static extern int ftruncate(int fd, long length);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr mmap(IntPtr addr, IntPtr length, int prot, int flags, int fd, IntPtr offset);

    [DllImport("libc", SetLastError = true)]
    private static extern int dup(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int dup2(int oldfd, int newfd);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr read(int fd, byte[] buf, IntPtr count);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr write(int fd, byte[] buf, IntPtr count);

    private const int O_RDWR = 0x0002;
    private const int O_CREAT = 0x0040; // Linux
    private const int O_WRONLY = 0x0001;
    private const int PROT_READ = 0x1;
    private const int PROT_WRITE = 0x2;
    private const int MAP_SHARED = 0x1;
    private const int MAP_PRIVATE = 0x2;
    private const int MAP_ANONYMOUS = 0x20; // Linux

    // Exception TYPES (by base) that are input *rejection* or a harness artifact,
    // never a target bug — mirrors the Python driver's REJECTION_EXC. govfuzz
    // synthesizes the argument, so a whole class of exceptions come from us
    // handing the wrong VALUE/SHAPE, not from a target defect. Suppressing them is
    // the key to avoiding a false-positive storm:
    //   - ArgumentException (+ ArgumentNull/ArgumentOutOfRange): the canonical
    //     "you called me with a bad argument" — library input validation.
    //   - FormatException / DecoderFallbackException: bad input format/encoding.
    //   - NotSupportedException / NotImplementedException: this input drove the
    //     API down an unsupported/unimplemented path — not a memory-safety bug.
    //   - IOException (+ EndOfStream/FileNotFound): environmental / stream end.
    //   - KeyNotFoundException: a synthesized container missing a key the target
    //     pre-seeds — our wrong shape (mirrors Python KeyError).
    //   - TimeoutException: environmental.
    // Genuine bugs still surface: IndexOutOfRangeException (real OOB on the bytes
    // we feed → GF-201), NullReferenceException (GF-206), DivideByZero/Overflow
    // (GF-205), OutOfMemory (GF-209), and any other/custom throwable (GF-210).
    private static bool IsRejection(Exception exc) =>
        exc is ArgumentException          // + ArgumentNull, ArgumentOutOfRange, DecoderFallback
        || exc is FormatException
        || exc is NotSupportedException
        || exc is NotImplementedException
        || exc is IOException             // + EndOfStream, FileNotFound, DirectoryNotFound
        || exc is System.Collections.Generic.KeyNotFoundException
        || exc is TimeoutException
        || exc is OperationCanceledException;

    // Never a finding: control-flow / interpreter signals.
    private static bool IsControl(Exception exc) =>
        exc is OperationCanceledException;

    private static string[] _expected = Array.Empty<string>();
    private static string _targetNamespace = "";

    // An exception whose type lives IN the target's own root namespace is that
    // library's declared way of rejecting input (mirrors Ada "declared exception =
    // intended rejection" and Python's _TARGET_PKG). Framework exceptions
    // (namespace "System...") never match, so real faults still surface.
    private static bool IsLibraryException(Exception exc)
    {
        if (_targetNamespace.Length == 0)
        {
            return false;
        }
        var ns = exc.GetType().Namespace ?? "";
        return ns == _targetNamespace
            || ns.StartsWith(_targetNamespace + ".", StringComparison.Ordinal);
    }

    private static bool IsFinding(Exception exc)
    {
        if (IsControl(exc))
        {
            return false;
        }
        var name = exc.GetType().Name;
        foreach (var e in _expected)
        {
            if (e == name)
            {
                return false;
            }
        }
        if (IsRejection(exc))
        {
            return false;
        }
        if (IsLibraryException(exc))
        {
            return false;
        }
        return true;
    }

    private static void ReportFinding(Exception exc)
    {
        // Marker mirrors the JVM driver's `== govfuzz JVM finding:`; the engine's
        // `parse_csharp_finding` maps the exception type -> GF rule -> CWE.
        var msg = (exc.Message ?? "").Replace('\n', ' ').Replace('\r', ' ');
        Console.Error.WriteLine($"== govfuzz csharp finding: {exc.GetType().FullName}: {msg}");
        Console.Error.WriteLine(exc.StackTrace);
        Console.Error.Flush();
    }

    private static void RunInput(byte[] data)
    {
        SharpFuzz.Common.Trace.PrevLocation = 0;
        try
        {
            Govfuzzgen.GovfuzzEntry.Run(data);
        }
        catch (Exception exc) when (!IsFinding(exc))
        {
            // Expected rejection / library validation / our-fault — swallow.
        }
        catch (Exception exc)
        {
            ReportFinding(exc);
            FlushAndExit(FindingHaltCode);
        }
    }

    private static void FlushAndExit(int code)
    {
        Console.Out.Flush();
        Console.Error.Flush();
        Environment.Exit(code);
    }

    // Map GOVFUZZ_COV_SHM into Trace.SharedMem. On any failure fall back to a
    // private anonymous page so the instrumented target's writes never null-deref.
    private static void SetupCoverage()
    {
        var path = Environment.GetEnvironmentVariable("GOVFUZZ_COV_SHM");
        if (!string.IsNullOrEmpty(path))
        {
            int fd = open(path, O_RDWR | O_CREAT, 0x180 /* 0600 */);
            if (fd >= 0)
            {
                ftruncate(fd, CovBits);
                IntPtr p = mmap(IntPtr.Zero, (IntPtr)CovBits, PROT_READ | PROT_WRITE, MAP_SHARED, fd, IntPtr.Zero);
                close(fd);
                if (p != (IntPtr)(-1) && p != IntPtr.Zero)
                {
                    SharpFuzz.Common.Trace.SharedMem = (byte*)p;
                    return;
                }
            }
        }
        // Fallback: private, discarded map (crash-isolation replay or unset env).
        IntPtr anon = mmap(IntPtr.Zero, (IntPtr)CovBits, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, IntPtr.Zero);
        SharpFuzz.Common.Trace.SharedMem = anon == (IntPtr)(-1)
            ? (byte*)Marshal.AllocHGlobal(CovBits)
            : (byte*)anon;
    }

    private static bool ReadExact(int fd, byte[] buf, int n)
    {
        int got = 0;
        while (got < n)
        {
            // read into a slice via a temporary (P/Invoke read fills from offset 0)
            byte[] tmp = got == 0 && n == buf.Length ? buf : new byte[n - got];
            IntPtr r = read(fd, tmp, (IntPtr)(n - got));
            int rr = (int)r;
            if (rr <= 0)
            {
                return false;
            }
            if (!ReferenceEquals(tmp, buf))
            {
                Array.Copy(tmp, 0, buf, got, rr);
            }
            got += rr;
        }
        return true;
    }

    private static int ReadU32(int fd)
    {
        var b = new byte[4];
        if (!ReadExact(fd, b, 4))
        {
            return -1;
        }
        return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
    }

    private static void FramedLoop()
    {
        // Save control pipe (fd 1) then redirect stdout to /dev/null so target
        // prints can't corrupt the sync stream (#427).
        int controlFd = dup(1);
        int devnull = open("/dev/null", O_WRONLY, 0);
        if (devnull >= 0)
        {
            dup2(devnull, 1);
            close(devnull);
        }
        var one = new byte[] { 1 };
        write(controlFd, one, (IntPtr)1); // ready byte
        while (true)
        {
            int n = ReadU32(0);
            if (n < 0)
            {
                break;
            }
            var data = new byte[n];
            if (n > 0 && !ReadExact(0, data, n))
            {
                break;
            }
            RunInput(data);
            write(controlFd, one, (IntPtr)1); // sync byte
        }
    }

    public static int Main(string[] args)
    {
        _expected = (Environment.GetEnvironmentVariable("GOVFUZZ_EXPECTED_EXCEPTIONS") ?? "")
            .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < _expected.Length; i++)
        {
            _expected[i] = _expected[i].Trim();
        }
        _targetNamespace = (Environment.GetEnvironmentVariable("GOVFUZZ_CS_NAMESPACE") ?? "").Trim();

        SetupCoverage();

        if (Environment.GetEnvironmentVariable("GOVFUZZ_FRAMED") != null)
        {
            FramedLoop();
            return 0;
        }

        // Per-spawn single-input replay: argv[0] is an input file, else read stdin.
        byte[] input;
        if (args.Length > 0 && File.Exists(args[0]))
        {
            input = File.ReadAllBytes(args[0]);
        }
        else
        {
            using var stdin = Console.OpenStandardInput();
            using var ms = new MemoryStream();
            stdin.CopyTo(ms);
            input = ms.ToArray();
        }
        RunInput(input);
        return 0;
    }
}
