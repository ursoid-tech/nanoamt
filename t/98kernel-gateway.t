use strict;
use warnings;
use Test::More;
use File::Spec;
use t::Util;

plan skip_all => 'set NANOAMT_KERNEL_TEST=1 with native, POSIX and OpenSSL enabled for Linux gateway tests'
    unless $ENV{NANOAMT_KERNEL_TEST} && $ENV{NANOAMT_TEST_NATIVE} &&
           $ENV{NANOAMT_TEST_POSIX} && $ENV{NANOAMT_TEST_OPENSSL};
plan skip_all => 'Linux only' unless $^O eq 'linux';
for my $inner (4, 6) {
    my ($err, $out) = run_prog({timeout => 45}, 'unshare', '--user', '--map-root-user', '--net',
        'sh', File::Spec->catfile(source_dir(), 't', 'interop', 'kernel-gateway.sh'),
        File::Spec->catfile(build_dir(), 'nanoamt-relay'), $inner);
    is($out, "kernel-gateway: IPv$inner native multicast hash passed\n", "Linux gateway IPv$inner") or diag($err);
}
done_testing;
