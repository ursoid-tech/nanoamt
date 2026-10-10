use strict;
use warnings;
use Test::More;
use t::Util;

for my $case (
    ['dual', 'IPv4/IPv6 outer and inner families, SSM and ASM'],
    ['teardown', 'NAT rebinding, limit flag, teardown credentials and direct relay'],
    ['fragments', 'IPv4/IPv6 reassembly, overlaps, expiry and atomic fragments'],
    ['mld', 'MLDv2 truncation, checksums, router alert and query validation'],
    ['ecn', 'RFC 6040/9601 ECN matrix, checksum preservation and fragment marks'],
    ['raw', 'complete non-UDP multicast IP delivery'],
) {
    subtest $case->[1] => sub {
        my ($err, $out) = run_prog({}, test_binary('test-rfc'), $case->[0]);
        is($out, "===AMT RFC $case->[0] OK===\n", $case->[1]) or diag($err);
    };
}
done_testing;
