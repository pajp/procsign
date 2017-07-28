#!/usr/bin/perl -w
# -*- Mode: cperl; cperl-indent-level: 4 -*-
# This program uses the codesign(1) program to validate the signature
# of all running processes, as well as printing them grouped by certificate
# chain.

# TODO: option to show interpreters such as Perl even with --hide-apple
# because they may run arbitrary unsigned code

use Term::ANSIColor;

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
    print "\t$0 [--hide-apple] [--no-color] [--no-unsigned-summary] [--in-session]\n";
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

sub examineprocess {
    my ($pid) = @_;
    return if $pids{$pid};

    my $status = "pid: $pid";
    print chr(8) . " [$status]";
    if ($hideapple && $appleanchorcheck) {
	my $applecsrc = system('codesign -R="anchor apple" -v ' . $pid . ' > /dev/null 2>&1');
	$applecsrc >>= 8;
	if ($applecsrc == 0) {
	    next;
	}
    }
    my @signdata = split /\n/, `codesign -dvvv "$pid" 2>&1`;

    my $csargs = '';
    if ($warnuntrusted) {
	$csargs .= '-R="anchor trusted"';
    }

    my %signdata;
    for (@signdata) {
	chomp;
	my ($key, $value) = split /=/, $_, 2;
	$signdata{$key} = [ ] unless $signdata{$key};
	if ($value && $value ne "") {
	    push @{$signdata{$key}}, $value;
	}
    }
    my $executable = ${$signdata{"Executable"}}[0];
    if ($executable) {
	print chr(8) x (length($status)+3);
	$status .= " ($executable)";
	print " [$status]";
    } else {
	#print "\nNo executable information for pid $pid\n";
	$executable = "???";
    }
    my $csrc = system("codesign $csargs -v $pid > /dev/null 2>&1");
    $csrc >>= 8;
    my $psn = $pid . "_" . $executable;
    $ps{$psn}{'csrc'} = $csrc;
    $ps{$psn}{'executable'} = $executable;
    $ps{$psn}{'pid'} = $pid;
    $ps{$psn}{'signdata'} = \%signdata;
    $pids{$pid} = $ps{$psn};
    my $path = "";
    $path = join('/', @{$ps{$psn}{'signdata'}{'Authority'}}) if $ps{$psn}{'signdata'}{'Authority'};
    $ps{$psn}{'signpath'} = $path;
    $last_validation_failure{$path} = $csrc;
    $process_signed_by{$path} = [ ] unless $process_signed_by{$path};
    push @{$process_signed_by{$path}}, $ps{$psn};
    print chr(8) x (length($status) + 2);
    print ' ' x (length($status) + 2);
    print chr(8) x (length($status) + 2);
}

if ($stage1) {
    print 'Examining processes in current session…  ';
    open LAUNCHCTL, "launchctl list|";
    while (<LAUNCHCTL>) {
	next unless /^[0-9]/;
	my ($pid) = split /[ \t]+/;
	examineprocess($pid);
    }
    close LAUNCHCTL;

    print chr(8) x 42;
    print ' ' x 42;
    print chr(8) x 42;
}

if ($stage2) {
    print 'Examining all processes… ';
    open PS, "ps -ax -o pid,comm|";
    while (<PS>) {
	s/^[ \t]+//;
	next if /^PID/;
	my ($pid, $cmd) = split / +/, $_, 2;
	examineprocess($pid);
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
