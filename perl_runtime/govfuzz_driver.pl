# SPDX-License-Identifier: Apache-2.0
# govfuzz Perl fork-server driver. Run under `perl -d:GovfuzzCov` so DB::DB records
# edge coverage into the shared GOVFUZZ_COV_SHM map. Speaks the GOVFUZZ_FRAMED
# protocol (matches c_runtime/govfuzz_driver.c): fd 1 control pipe, fd 0 input pipe
# ({u32 LE len, bytes}). A finding die()s -> stderr marker + exit 86 (no sync byte);
# an expected rejection (input validation / a library's own exception object) is
# swallowed. No third-party fuzzer.
use strict;
use warnings;
require Devel::GovfuzzCov;

my $FINDING_HALT = 86;
# Top package of the target (set by the launcher): a blessed exception object whose
# class is in the target's own namespace is that library's declared rejection, not
# a govfuzz finding (the Ada/Java "declared exception" principle).
# M22: `defined(..) ? .. : ..` not the `//` defined-or operator, so this driver
# runs on Perl 5.6-5.9 (legacy gov/mil) where `//` is a syntax error (5.10+).
my $TARGET_PKG = defined($ENV{GOVFUZZ_TARGET_PACKAGE}) ? $ENV{GOVFUZZ_TARGET_PACKAGE} : '';
my @EXPECTED = grep { length } split /,/,
    (defined($ENV{GOVFUZZ_EXPECTED_EXCEPTIONS}) ? $ENV{GOVFUZZ_EXPECTED_EXCEPTIONS} : '');

my $harness = $ENV{GOVFUZZ_HARNESS} or die "GOVFUZZ_HARNESS unset\n";
require $harness;

# A die message that reads like input validation, not a bug. Mirrors the Python
# lane's ValueError/declared-exception suppression. Perl's croak-on-bad-input
# convention produces these.
# Perl uses `die` as ordinary error handling — a plain string die is almost always
# the program REJECTING bad input (the croak-on-bad-args convention), not a bug. So
# (FP-avoidant, like the Python untyped policy) we report ONLY high-confidence
# bug-class dies and suppress everything else. The behavioral/taint oracles (the
# shim) catch the security classes regardless. Returns the CWE, or '' for a generic
# die (= not a finding). A user can force-report a message via GOVFUZZ_EXPECTED... no
# — @EXPECTED here SUPPRESSES named messages (a target's known internal die text).
sub bug_cwe {
    my ($msg) = @_;
    for my $e (@EXPECTED) { return '' if length($e) && index($msg, $e) >= 0; }
    return 'CWE-674' if $msg =~ /deep recursion/i;
    return 'CWE-789' if $msg =~ /out of memory|can't allocate/i;
    return 'CWE-369' if $msg =~ /division by zero|illegal division|illegal modulus/i;
    return 'CWE-617'
        if $msg
        =~ /\b(panic|assert(ion)?|invariant|unreachable|internal error|should (never|not) (happen|be reached|occur)|impossible|corrupt)\b/i;
    return '';    # generic die = normal Perl error handling, suppressed
}

sub run_input {
    my ($data) = @_;
    Devel::GovfuzzCov::reset_prev();
    my $ok = eval {
        govfuzzgen::govfuzz_run_one($data);
        1;
    };
    return if $ok;
    my $err = $@;
    # A blessed exception object from the target's own package is a declared
    # rejection (e.g. My::Parser::Error), not a finding.
    if (ref $err) {
        my $class = ref $err;
        return if length($TARGET_PKG) && index($class, $TARGET_PKG) == 0;
        my $cwe = bug_cwe("$err");
        report_finding($cwe, "$class: $err") if $cwe;
        return;
    }
    my $cwe = bug_cwe("$err");
    report_finding($cwe, "$err") if $cwe;
}

sub report_finding {
    my ($cwe, $msg) = @_;
    $msg =~ s/\s+at .* line \d+\.?$//;    # trim the "at FILE line N" suffix
    # Marker mirrors the JVM/Python drivers; the engine's parse_perl_finding maps
    # the CWE token to a GF rule.
    print STDERR "== govfuzz perl finding: $cwe: $msg\n";
    exit($FINDING_HALT);
}

sub read_exact {
    my ($n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $r = sysread(STDIN, my $chunk, $n - length($buf));
        return undef if !defined($r) || $r == 0;
        $buf .= $chunk;
    }
    return $buf;
}

binmode STDIN;
if (defined $ENV{GOVFUZZ_FRAMED}) {
    # Save the control pipe (fd 1) then redirect STDOUT to /dev/null so the target's
    # prints can't corrupt the sync stream (#427).
    open(my $CTL, '>&', \*STDOUT) or die "dup control: $!\n";
    binmode $CTL;
    $CTL->autoflush(1);
    open(STDOUT, '>', '/dev/null') or die "redirect stdout: $!\n";
    syswrite($CTL, "\x01");    # ready byte
    my $count = 0;
    while (1) {
        my $hdr = read_exact(4);
        last if !defined $hdr;
        my $n = unpack('V', $hdr);
        my $data = $n > 0 ? read_exact($n) : '';
        last if !defined $data;
        run_input($data);
        Devel::GovfuzzCov::flush();
        syswrite($CTL, "\x01");    # sync byte
        # Periodically persist covered lines for negative fuzz-confirmation (no-op
        # unless the set grew / GOVFUZZ_COVERED_LINES is set; coverage plateaus).
        ++$count;
        # Exponentially spaced early checkpoints keep short campaigns from
        # losing all line evidence before the old 512-input checkpoint.
        Devel::GovfuzzCov::dump_covered_lines()
            if (($count & ($count - 1)) == 0 || ($count & 0x1FF) == 0);
    }
} else {
    my $data;
    if (@ARGV && -f $ARGV[0]) {
        local $/;
        open(my $f, '<', $ARGV[0]) or die "open $ARGV[0]: $!\n";
        binmode $f;
        $data = <$f>;
    } else {
        local $/;
        $data = <STDIN>;
    }
    run_input(defined($data) ? $data : '');
    Devel::GovfuzzCov::flush();
}
Devel::GovfuzzCov::dump_covered_lines();
