use strict;
use warnings;
use Test::More;
use t::Util;

my ($stderr, $stdout) = run_prog({}, $^X, '-e', 'print join("|", @ARGV)', 'a b', '$(not-a-command)');
is($stdout, 'a b|$(not-a-command)', 'arguments are passed without shell interpretation');

my $ok = eval {
    run_prog({}, $^X, '-e', 'print "SUCCESS\n"; warn "late failure\n"; exit 7');
    1;
};
ok(!$ok, 'a success marker cannot hide a failing process');
like($@, qr/late failure/, 'failure includes stderr');
like($@, qr/SUCCESS/, 'failure includes stdout');

($stderr, $stdout) = run_prog({}, $^X, '-e',
    'for (1..8) { print STDOUT "o" x 65536; print STDERR "e" x 65536; }');
is(length($stdout), 8 * 65536, 'stdout larger than pipe capacity is drained');
is(length($stderr), 8 * 65536, 'stderr is drained concurrently');

$ok = eval { run_prog({timeout => 1}, $^X, '-e', 'sleep 30'); 1; };
ok(!$ok, 'hung test programs are terminated');
like($@, qr/timed out/, 'timeout has a useful diagnostic');
done_testing;
