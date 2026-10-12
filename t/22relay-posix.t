use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'Linux POSIX relay adapter disabled for this build'
    if $^O ne 'linux' || (defined $ENV{NANOAMT_TEST_POSIX} && !$ENV{NANOAMT_TEST_POSIX});

my ($stderr, $stdout) = run_prog({}, test_binary('test-relay-posix'));
is($stdout, "relay-posix: real UDP, backpressure, withdrawal, expiry and admission passed\n",
   'relay serves both IP families with bounded queues and deferred-send validation') or diag($stderr);
done_testing;
