use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'native provider disabled' unless $ENV{NANOAMT_TEST_NATIVE};
my ($err, $out) = run_prog({}, test_binary('test-native'), 'codec');
is($out, "native: offload UDP/TCP checksums and fragment rejection passed\n", 'checksum offload normalization') or diag($err);
done_testing;
