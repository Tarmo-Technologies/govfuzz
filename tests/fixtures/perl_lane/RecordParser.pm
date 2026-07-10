# SPDX-License-Identifier: Apache-2.0
# A tiny untrusted-input parser fixture for the govfuzz Perl lane. `parse_record`
# is the fuzzable entry point; a crafted first byte drives a divide-by-zero
# (CWE-369), a real arithmetic fault reachable purely from the input bytes.
package RecordParser;
use strict;
use warnings;

sub parse_record {
    my ($data) = @_;
    die "empty record\n" unless length $data;        # normal rejection (suppressed)
    my $tag = substr($data, 0, 1);
    if ($tag eq 'A') {                               # planted defect: divide by zero
        my $n = length($data) - length($data);
        return 100 / $n;
    }
    if ($tag eq 'B') { return { len => length($data) }; }
    die "unknown tag\n";                             # normal rejection (suppressed)
}

1;
