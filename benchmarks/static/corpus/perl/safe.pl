sub h {
    my $ok = eval { risky() };   # block eval: exception handling
    my @a = split /,/, $csv;     # no shell
}
