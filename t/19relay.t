use strict;
use warnings;
use Test::More;
use t::Util;

for my $case (qw(exchange linux-gateway fanout authentication mtu native-fragments policy expiry interface-refresh indexed-scale indexed-churn)) {
    my ($err, $out) = run_prog({}, test_binary('test-relay'), $case);
    is($out, "===AMT relay $case OK===\n", $case) or diag($err);
}
done_testing;
