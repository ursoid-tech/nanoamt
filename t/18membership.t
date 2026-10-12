use strict;
use warnings;
use Test::More;
use t::Util;

for my $case (qw(endpoint router algebra validation legacy capacity)) {
    my ($err, $out) = run_prog({}, test_binary('test-membership'), $case);
    is($out, "===AMT membership $case OK===\n", $case) or diag($err);
}
done_testing;
