sub h {
    my $o = `ls $d`;      # EXPECT GF-404
    system("rm " . $a);   # EXPECT GF-404
    my $r = eval "$code"; # EXPECT GF-420
    my $x = md5_hex($d);  # EXPECT GF-422
    my $api_key = "AKIAsecretvalue1234"; # EXPECT GF-429
}
