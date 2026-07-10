# SPDX-License-Identifier: Apache-2.0
package Devel::GovfuzzCov;
use strict; use warnings;
our $COV_BITS = 1 << 16;
our $MASK = $COV_BITS - 1;
my $map = "\0" x $COV_BITS;
my $prev = 0;
my $prefix = $ENV{GOVFUZZ_TRACE_PREFIX} // '';
# Covered "file:line" set for negative fuzz-confirmation (see govfuzz_cov.py).
my %covered;
my $covered_dumped = 0;
sub _fnv {
    my ($s, $line) = @_;
    my $h = 0x811c9dc5;
    for my $c (unpack 'C*', $s) { $h = (($h ^ $c) * 0x01000193) & 0xFFFFFFFF; }
    $h = (($h ^ ($line & 0xFF)) * 0x01000193) & 0xFFFFFFFF;
    $h = (($h ^ (($line >> 8) & 0xFF)) * 0x01000193) & 0xFFFFFFFF;
    return $h & $MASK;
}
sub record {
    my ($file, $line) = @_;
    return if length($prefix) && index($file, $prefix) != 0;
    $covered{"$file:$line"} = 1;
    my $block = _fnv($file, $line);
    my $idx = ($prev ^ $block) & $MASK;
    my $v = ord(substr($map, $idx, 1));
    $v++ if $v != 0xFF;
    substr($map, $idx, 1) = chr($v);
    $prev = ($block >> 1) & $MASK;
}
sub reset_prev { $prev = 0; }
sub dump_covered_lines {
    my $path = $ENV{GOVFUZZ_COVERED_LINES} or return;
    my $n = scalar keys %covered;
    return if $n == $covered_dumped;
    my $fh;
    open($fh, '>', "$path.tmp") or return;
    print $fh join("\n", sort keys %covered);
    close($fh);
    rename("$path.tmp", $path);
    $covered_dumped = $n;
}
sub flush {
    my $path = $ENV{GOVFUZZ_COV_SHM} or return;
    my $fh;
    open($fh, '+<', $path) or open($fh, '>', $path) or return;
    binmode $fh; sysseek($fh, 0, 0); syswrite($fh, $map); close($fh);
}
package DB;
sub DB {
    my ($pkg, $file, $line) = caller;
    Devel::GovfuzzCov::record($file, $line);
}
sub sub { no strict 'refs'; &$DB::sub }
1;
