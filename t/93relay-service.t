use strict;
use warnings;
use Test::More;
use File::Spec;
use t::Util;

plan skip_all => 'set NANOAMT_NATIVE_TEST=1 with native, POSIX and OpenSSL enabled for relay service tests'
    unless $ENV{NANOAMT_NATIVE_TEST} && $ENV{NANOAMT_TEST_NATIVE} &&
           $ENV{NANOAMT_TEST_POSIX} && $ENV{NANOAMT_TEST_OPENSSL};
for my $outer (0, 1) {
    for my $inner (0, 1) {
        my ($err, $out) = run_prog({timeout => 15}, 'unshare', '--user', '--map-root-user', '--net',
            'sh', File::Spec->catfile(source_dir(), 't', 'interop', 'relay-service.sh'),
            File::Spec->catfile(build_dir(), 'nanoamt-relay'), test_binary('test-relay-service'), $outer, $inner);
        is($out, 'service: outer IPv' . ($outer ? 6 : 4) . ' inner IPv' . ($inner ? 6 : 4) .
           " native multicast delivery and leave passed\n", "outer IPv" . ($outer ? 6 : 4) . " inner IPv" . ($inner ? 6 : 4)) or diag($err);
    }
}
done_testing;
