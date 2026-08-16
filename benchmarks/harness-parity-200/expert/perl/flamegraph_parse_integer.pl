# SPDX-License-Identifier: Apache-2.0

use strict;
use warnings;

require "./stackcollapse-vsprof.pl";
while (read(STDIN, my $length, 4) == 4) {
    my $size = unpack("V", $length);
    last if $size > 1_048_576;
    read(STDIN, my $data, $size) == $size or last;
    main::parse_integer($data);
}
