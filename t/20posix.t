use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'POSIX adapter disabled for this build'
    if defined $ENV{NANOAMT_TEST_POSIX} && !$ENV{NANOAMT_TEST_POSIX};

my ($stderr, $stdout) = run_prog({}, test_binary('test-posix'));
is($stdout, "posix: real UDP discovery, query, report, data and leave passed\n",
   'nonblocking gateway handles UDP exchange, backpressure and cancellation') or diag($stderr);
done_testing;
