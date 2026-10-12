use strict;
use warnings;
use Test::More;
use File::Spec;
use t::Util;

plan skip_all => 'set NANOAMT_NATIVE_TEST=1 for isolated native provider tests'
    unless $ENV{NANOAMT_NATIVE_TEST} && $ENV{NANOAMT_TEST_NATIVE};
for my $case ([0, 'native0'], [1, 'native0'], [0, 'lo']) {
    my ($v6, $interface) = @$case;
    my ($err, $out) = run_prog({timeout => 30}, 'unshare', '--user', '--map-root-user', '--net',
        'sh', File::Spec->catfile(source_dir(), 't', 'interop', 'native.sh'),
        test_binary('test-native'), $v6, $interface);
    is($out, 'native: IPv' . ($v6 ? 6 : 4) . " $interface capture, transactional filters and ICMP passed\n",
       "IPv" . ($v6 ? 6 : 4) . " $interface") or diag($err);
}
done_testing;
