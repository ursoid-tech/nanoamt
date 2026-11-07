use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'OpenSSL provider disabled for this build' unless $ENV{NANOAMT_TEST_OPENSSL};
my ($err, $out) = run_prog({}, test_binary('test-openssl'));
is($out, "===AMT OpenSSL OK===\n", 'HMAC known vector and secure random provider') or diag($err);
done_testing;
