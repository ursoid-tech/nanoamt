package t::Util;

use strict;
use warnings;
use Exporter 'import';
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use File::Spec;
use IPC::Open3 qw(open3);
use IO::Select;
use Symbol qw(gensym);
use Errno qw(EINTR);

our @EXPORT = qw(run_prog test_binary build_dir source_dir);

sub source_dir { return dirname(dirname(abs_path(__FILE__))); }
sub build_dir { return File::Spec->rel2abs($ENV{NANOAMT_BUILD_DIR} // File::Spec->catdir(source_dir(), 'build')); }
sub test_binary { return File::Spec->catfile(build_dir(), 't', '00util', shift); }
sub run_prog {
    my ($options, @command) = @_;
    die "run_prog needs a command\n" unless @command;
    my $timeout = $options->{timeout} // 15;
    my ($input, $output);
    my $error = gensym;
    my $pid = open3($input, $output, $error, @command);
    close $input;
    binmode $output;
    binmode $error;
    my $stdout_fd = fileno($output);
    my $reader = IO::Select->new($output, $error);
    my ($stdout, $stderr, $status) = ('', '', undef);
    my $ok = eval {
        local $SIG{ALRM} = sub { die "command timed out after ${timeout}s\n"; };
        alarm $timeout;
        while ($reader->count) {
            for my $pipe ($reader->can_read) {
                my $count = sysread($pipe, my $bytes, 65536);
                if (!defined $count) {
                    next if $! == EINTR;
                    die "read from child: $!\n";
                }
                if ($count == 0) {
                    $reader->remove($pipe);
                    close $pipe;
                } elsif (fileno($pipe) == $stdout_fd) {
                    $stdout .= $bytes;
                } else {
                    $stderr .= $bytes;
                }
            }
        }
        my $wait;
        do { $wait = waitpid($pid, 0); } while ($wait < 0 && $! == EINTR);
        die "wait for child: $!\n" unless $wait == $pid;
        $status = $?;
        alarm 0;
        1;
    };
    my $failure = $@;
    alarm 0;
    unless ($ok) {
        kill 'KILL', $pid;
        waitpid($pid, 0);
        die "$failure$stderr$stdout";
    }
    die "command (@command) failed (wait status $status)\n$stderr$stdout"
        if $status != 0;
    return ($stderr, $stdout);
}

1;
