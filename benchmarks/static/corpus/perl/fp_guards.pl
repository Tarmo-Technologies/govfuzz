#!/usr/bin/perl
# SPDX-License-Identifier: Apache-2.0
# Campaign 2026-07-03 Perl guards: POD prose, heredoc/comment prose mentioning a
# "system call", and a backtick inside a string are NOT shell execution.
use strict;
use warnings;

=head1 DESCRIPTION

This module could run system("rm -rf /") or `dangerous` backticks or
eval "$code" in its examples — but this is POD documentation, not code.

=cut

sub note {
    my $msg = "the loader uses a system call to fork";  # prose, not a call
    warn "bad hook name `$name' given";                  # backtick inside a string
    $msg =~ s/`[^`]+`//g;                                # backticks in regex, not a command
    return $msg;
}

sub run_cmd {
    my ($cmd) = @_;
    system "$cmd";                                        # EXPECT GF-404
}

sub capture {
    my ($dir) = @_;
    return `ls $dir`;                                     # EXPECT GF-404
}

sub list_form_open {
    my (@filemasks) = @_;
    open(my $git_ls_files, '-|', 'git', 'ls-files', '--', @filemasks) or die;
    return <$git_ls_files>;
}

sub list_form_system {
    system('diff', ('-u', '/tmp/autotools', '/tmp/cmake'));
    system($^X, ('-c', __FILE__));
}

sub evaluate {
    my ($code) = @_;
    return eval "$code";                                  # EXPECT GF-420
}

1;
