use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'AMTQ disabled' if defined($ENV{NANOAMT_TEST_AMTQ}) && !$ENV{NANOAMT_TEST_AMTQ};
for my $case (qw(exchange fragments native-fragments authorization control report-errors contexts bounds full-state timeout)) {
    my ($err, $out) = run_prog({}, test_binary('test-amtq-relay'), $case);
    is($out, "===AMTQ relay $case OK===\n", $case) or diag($err);
}
done_testing;
