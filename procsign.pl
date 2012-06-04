#!/usr/bin/perl -w
# -*- Mode: cperl; cperl-indent-level: 4 -*-
# This program uses the codesign(1) program to validate the signature
# of all running processes, as well as printing them grouped by certificate
# chain.
#
# on x86_64 systems, run with:
#   VERSIONER_PERL_PREFER_32_BIT=yes ./procsign.pl

# TODO: option to show interpreters such as Perl even with --hide-apple
# because they may run arbitrary unsigned code

use Term::ANSIColor;
use Mac::Processes;

my $color = 1;
$color = 0 if $ENV{'NOCOLOR'};
my @hiddenchains;
my $hideapple = 0;
my $unsigned_in_summary = 1;
my $warnuntrusted = 1;
my $appleanchorcheck = 1;
my $optc = $#ARGV + 1;
my $stage1 = 1;
my $stage2 = 1;
for (@ARGV) {
    if ($_ eq "--hide-apple") {
	push @hiddenchains, "Software Signing/Apple Code Signing Certification Authority/Apple Root CA";
	$optc--;
    }
    if ($_ eq "--dont-check-trust") {
	$warnuntrusted = 0;
	$optc--;
    }
    if ($_ eq "--no-color") {
	$color = 0;
	$optc--;
    }
    if ($_ eq "--no-unsigned-summary") {
	$unsigned_in_summary = 0;
	$optc--;
    }
    if ($_ eq "--no-session") {
	$stage1 = 0;
	$optc--;
    }
    if ($_ eq "--in-session") {
	$stage2 = 0;
	$optc--;
    }
}
if ($optc) {
    print "Usage:\n";
    print "\t$0 [--hide-apple] [--no-color] [no-unsigned-summary] [--in-session]\n";
    print "\n(you may have to set the environment variable
VERSIONER_PERL_PREFER_32_BIT=yes on an x86_64 machine)\n";
    exit 1;
}

my @wheel = ( '|', '/', '-', '\\' );
my @colors = ( 'blue', 'magenta', 'red', 'yellow', 'green', 'white' );
my $wid = 0;
my $cid = 0;
my %process_signed_by;
my %last_validation_failure;
my %ps;
my %pids;

sub executable_from_pid {
    my $pid = shift;
    open LSOF, "lsof -p $pid|";
    while (<LSOF>) {
	my ($cmd, $pid, $user, $fd, $type, $device, $size, $node, $name) = split /[ \t]+/, $_, 9;
	if ($fd eq "txt") {
	    chomp $name;
	    close LSOF;
	    return $name;
	}
    }
    close LSOF;
    return "";
}

sub spin_wheel {
    print chr(8);
    print color $colors[$cid++] if $color;
    print $wheel[$wid++];
    $wid = 0 if ($wid > $#wheel);
    $cid = 0 if ($cid > $#colors);
    print color 'reset' if $color;
}

sub examineprocess {
    my ($psn, $pid, $executable) = @_;
    return if $pids{$pid};

    if ($hideapple && $appleanchorcheck) {
	my $applecsrc = system('codesign -R="anchor apple" -v ' . $pid . ' > /dev/null 2>&1');
	$applecsrc >>= 8;
	if ($applecsrc == 0) {
	    next;
	}
    }
    my @signdata = split /\n/, `codesign -dvvv "$executable" 2>&1`;

    my $csargs = '';
    if ($warnuntrusted) {
	$csargs .= '-R="anchor trusted"';
    }

    my $csrc = system("codesign $csargs -v $pid > /dev/null 2>&1");
    $csrc >>= 8;

    for (@signdata) {
	chomp;
	my ($key, $value) = split /=/, $_, 2;
	$ps{$psn}{'signdata'}{$key} = [ ] unless $ps{$psn}{'signdata'}{$key};
	if ($value && $value ne "") {
	    push @{$ps{$psn}{'signdata'}{$key}}, $value;
	}
    }
    $ps{$psn}{'csrc'} = $csrc;
    $ps{$psn}{'executable'} = $executable;
    $ps{$psn}{'pid'} = $pid;
    $pids{$pid} = $ps{$psn};
    my $path = "";
    $path = join('/', @{$ps{$psn}{'signdata'}{'Authority'}}) if $ps{$psn}{'signdata'}{'Authority'};
    $ps{$psn}{'signpath'} = $path;
    $last_validation_failure{$path} = $csrc;
    $process_signed_by{$path} = [ ] unless $process_signed_by{$path};
    push @{$process_signed_by{$path}}, $ps{$psn};
}

if ($stage1) {
    print 'Examining running processes... (stage 1)  ';
    while ( ($psn, $psi) = each(%Process) ) {
	my $executable = $psi->processAppSpec;
	my $pid = GetProcessPID($psn);
	spin_wheel;
	examineprocess($psn, $pid, $executable);
    }

    print chr(8) x 42;
    print ' ' x 42;
    print chr(8) x 42;
}

if ($stage2) {
    print 'Examining running processes... (stage 2)  ';
    open PS, "ps -ax -o pid,comm|";
    while (<PS>) {
	s/^[ \t]+//;
	next if /^PID/;
	my ($pid, $cmd) = split / +/, $_, 2;
	die "invalid pid for executable $pid" unless $pid;
	my $executable = executable_from_pid($pid);
	print STDERR chr(8)."\nExecutable \"$executable\" for pid $pid not found (process or file may be gone)\n" unless -f $executable;

	my $psn = $pid . "_" . $executable;
	spin_wheel;
	examineprocess($psn, $pid, $executable);
    }
    close PS;

    print chr(8) x 42;
    print ' ' x 42;
    print chr(8) x 42;
}


my $lastapp = "";
my $apprepeatcount = 0;
my $first = 1;
CHAIN: for (sort keys %process_signed_by) {
    my $path = $_;
    my @psis = @{$process_signed_by{$path}};
    my $hidden = 0;
    for (@hiddenchains) {
	next CHAIN if $_ eq $path;
    }
    print "\n" unless $first;
    $first = 0 if $first;
    if ($path) {
	print "Processes signed by ";
	print color 'green' if $color;
	print "$path";
	if ($last_validation_failure{$path} == 3) {
	    print color 'red' if $color;
	    print ' (self-signed or untrusted CA)';
	} else {
	    print color 'green' if $color;
	}
	print color 'reset';
	print ":\n";
    } else {
	if (!$unsigned_in_summary) {
	    next;
	}
	print "Unsigned or self-signed processes:\n";
    }
    for (sort { $a->{'executable'} cmp $b->{'executable'} } @psis) {
	my %p = %{$_};
	if ($lastapp eq $p{'executable'}) {
	    $apprepeatcount++;
	} else {
	    print color 'blue' if $color;
	    if ($apprepeatcount > 0) {
		print "\t (x" . ($apprepeatcount+1) . ")\n";
	    }
	    $apprepeatcount=0;
	    print "\t" . $p{'executable'};
	    if ($p{'csrc'} == 3 && $#{$p{'signdata'}{'Authority'}} == -1) {
		print color 'yellow';
		print (" (self-signed)");
	    }
	    print color 'reset' if $color;
	    print " (pid " .$p{'pid'}. ")\n";

	}
	$lastapp = $p{'executable'};
    }
    if ($apprepeatcount > 0) {
	print "\t (x" . ($apprepeatcount+1) . ")\n";
	$lastapp = ""; $apprepeatcount = 0;
    }
}
