use strict;
use warnings;
use Test::More;
use File::Spec;
use t::Util;

plan skip_all => 'set NANOAMT_KERNEL_TEST=1 to test the Linux relay in network namespaces'
    unless $ENV{NANOAMT_KERNEL_TEST};
plan skip_all => 'Linux only' unless $^O eq 'linux';
plan skip_all => 'POSIX adapter disabled for this build'
    if defined $ENV{NANOAMT_TEST_POSIX} && !$ENV{NANOAMT_TEST_POSIX};

for my $inner (0, 1) {
    SKIP: {
        # Linux P bit erratum
        skip 'set NANOAMT_KERNEL_IPV6=1 for a kernel with the RFC Request P bit fixed', 2
            if $inner && !$ENV{NANOAMT_KERNEL_IPV6};
        for my $asm (0, 1) {
            my $label = 'IPv' . ($inner ? 6 : 4) . ' ' . ($asm ? 'ASM' : 'SSM');
            my ($err, $out) = run_prog({}, 'unshare', '--user', '--map-root-user', '--net',
                'sh', File::Spec->catfile(source_dir(), 't', 'interop', 'kernel.sh'),
                test_binary('test-kernel'), $inner, $asm);
            is($out, "kernel: $label membership and multicast delivery passed\n", $label) or diag($err);
        }
    }
}
done_testing;
