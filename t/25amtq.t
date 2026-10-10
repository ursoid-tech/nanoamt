use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'AMTQ disabled' if defined $ENV{NANOAMT_TEST_AMTQ} && !$ENV{NANOAMT_TEST_AMTQ};
for my $case (qw(wire lifecycle membership ipv6 packets control fragments limits)) {
    subtest "AMTQ $case" => sub {
        my ($stderr, $stdout) = run_prog({}, test_binary('test-amtq'), $case);
        is($stdout, "===AMTQ $case OK===\n", $case) or diag($stderr);
    };
}
done_testing;
