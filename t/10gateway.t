use strict;
use warnings;
use Test::More;
use t::Util;

my @cases = (
    ['lifecycle', 'join, refresh, data during refresh and leave'],
    ['data', 'checksums, truncation, source filtering and mutable payloads'],
    ['control', 'query validation, peer matching and relay limit handling'],
    ['retry', 'bounded retries, rediscovery, clock and configuration errors'],
    ['random', 'RNG failures during reports, refresh and leave revoke membership'],
    ['defaults', 'default and explicit IPv4 families interoperate without changing caller configuration'],
    ['discovery', 'advertised relay selection and exponential QQIC decoding'],
);
for my $case (@cases) {
    my ($name, $description) = @$case;
    subtest $description => sub {
        my ($stderr, $stdout) = run_prog({}, test_binary('test-nanoamt'), $name);
        is($stdout, "===AMT GATEWAY $name OK===\n", $description) or diag($stderr);
    };
}
done_testing;
