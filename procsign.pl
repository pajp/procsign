#!/usr/bin/perl -w
# -*- Mode: cperl; cperl-indent-level: 4 -*-
# This program uses the codesign(1) program to validate the signature
# of all running processes, as well as printing them grouped by certificate
# chain.

use Term::ANSIColor;

my $color = 1;
$color = 0 if $ENV{'NOCOLOR'};
my @interpreters = ("ruby", "perl5", "python", "bash", "sh");
my @hiddenchains;
my $unsigned_in_summary = 1;
my $warnuntrusted = 1;
my $appleanchorcheck = 1;
my $optc = $#ARGV + 1;
my $stage1 = 0;
my $stage2 = 1;
my $psargs = "-a";
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
    if ($_ eq "--own") {
	$psargs = "-U " . $ENV{"USER"};
	$optc--;
    }
    if ($_ eq "--no-unsigned-summary") {
	$unsigned_in_summary = 0;
	$optc--;
    }
    if ($_ eq "--in-session") {
	$stage2 = 0;
	$stage1 = 1;
	$optc--;
    }
}
if ($optc) {
    print "Usage:\n";
    print "\t$0 [--hide-apple] [--no-color] [--no-unsigned-summary] [--in-session] [--own]\n";
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

sub isinterpreter {
    my ($signdata) = @_;
    for (@interpreters) {
	my $identifiers = $signdata->{'Identifier'};
	if ($identifiers && ${$identifiers}[0] eq "com.apple.".$_) {
	    return 1;
	}
    }
    return 0;
}

sub decorated_pid {
    my ($pid) = @_;
    my @fds = proc_standard_fds($pid);

    if (my $ttyfd = fds_contain_tty(@fds)) {
        return "$pid (".$ttyfd.")";
    } else {
	return "$pid";
    }
}

sub fds_contain_tty {
    for (@_) {
	next if !$_ || /^$/;
	if (/^\/dev\/tty[0-9a-z]+$/) {
	    s/^\/dev\///;
	    return $_;
	}
    }
    return 0;
}

sub proc_standard_fds {
    my ($pid) = @_;
    open LSOF, "lsof -p $pid -a -d 0,1,2 2>/dev/null |";
    my @fds;
    while (<LSOF>) {
	chomp;
	my ($cmd, $pid, $user, $fd, $type, $device, $ffoset, $node, $name) = split /[ \t]+/;
	next if $cmd eq "COMMAND";
	push @fds, $name;
    }
    return @fds;
}

sub clearline {
    my ($len) = @_;
    print chr(8) x $len;
    print ' ' x $len;
    print chr(8) x $len;
}

sub examineprocess {
    my ($pid, $cmd) = @_;
    return if $pids{$pid};

    my $status = "pid: $pid";
    print chr(8) . " [$status]";

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
	if ($cmd) {
	    $executable = $cmd;
	} else {
	    $executable = "<executable unknown>";
	}
    }
    my $csrc = system("codesign $csargs -v $pid > /dev/null 2>&1");
    $csrc >>= 8;
    my $psn = $pid . "_" . $executable;
    $ps{$psn}{'csrc'} = $csrc;
    $ps{$psn}{'executable'} = $executable;
    $ps{$psn}{'pid'} = $pid;
    $ps{$psn}{'signdata'} = \%signdata;
    my $path = "";
    $path = join('/', @{$ps{$psn}{'signdata'}{'Authority'}}) if $ps{$psn}{'signdata'}{'Authority'};

    for (@hiddenchains) {
	if ($_ eq $path && !isinterpreter(\%signdata)) {
	    clearline(length($status)+2);
	    return;
	}
    }

    # lsof -p 15460 -a -d 0,1,2

    $pids{$pid} = $ps{$psn};
    $ps{$psn}{'signpath'} = $path;
    $last_validation_failure{$path} = $csrc;
    $process_signed_by{$path} = [ ] unless $process_signed_by{$path};
    push @{$process_signed_by{$path}}, $ps{$psn};

    clearline(length($status)+2);
}

if ($stage1) {
    print 'Examining processes in current session…  ';
    open LAUNCHCTL, "launchctl list|";
    while (<LAUNCHCTL>) {
	next unless /^[0-9]/;
	my ($pid, undef, $cmd) = split /[ \t]+/;
	examineprocess($pid, $cmd);
    }
    close LAUNCHCTL;

    clearline(42);
}

if ($stage2) {
    print 'Examining all processes… ';
    open PS, "ps -x -o pid,comm $psargs|";
    while (<PS>) {
	chomp;
	s/^[ \t]+//;
	next if /^PID/;
	my ($pid, $cmd) = split / +/, $_, 2;
	examineprocess($pid, $cmd);
    }
    close PS;

    clearline(42);
}


my $lastapp = "";
my $apprepeatcount = 0;
my $first = 1;
CHAIN: for (sort keys %process_signed_by) {
    my $path = $_;
    my @psis = @{$process_signed_by{$path}};
    my $hidden = 0;
    print "\n" unless $first;
    $first = 0 if $first;
    if ($path) {
	print "Processes signed by ";
	print color 'green' if $color;
	print "$path";
	if ($last_validation_failure{$path} == 3) {
	    print color 'yellow' if $color;
	    print " (one or more invalid signatures)";
	} else {
	    print color 'green' if $color;
	}
	print color 'reset';
	print ":\n";
    } else {
	if (!$unsigned_in_summary) {
	    next;
	}
	print "Unsigned or self-signed processes, or processes that died during execution:\n";
    }
    my @repeatedpids;
    for (sort { $a->{'executable'} cmp $b->{'executable'} } @psis) {
	my %p = %{$_};
	if ($lastapp eq $p{'executable'}) {
	    $apprepeatcount++;
	    push @repeatedpids, $p{'pid'};
	} else {
	    print color 'blue' if $color;
	    if ($apprepeatcount > 0) {
		print "\t (x" . ($apprepeatcount+1) . "): ";
		$_ = decorated_pid($_) for (@repeatedpids);
		print join (', ', @repeatedpids);
		print "\n";
		@repeatedpids = ();
	    }
	    $apprepeatcount=0;
	    print "\t" . $p{'executable'};

	    if (isinterpreter($p{'signdata'})) {
		print color 'red' if $color;
		print (" (interpreter process)");
		if ($p{'pid'} == $$) {
		    print color 'yellow' if $color;
		    print " (me!)";
		}
	    }

	    if ($p{'csrc'} == 3 && $#{$p{'signdata'}{'Authority'}} == -1) {
		print color 'yellow';
		print (" (self-signed)");
	    } elsif ($p{'csrc'} == 3) {
		print color 'red' if $color;
		print " (invalid signature)";
	    }
	    print color 'reset' if $color;
	    print " (pid " . decorated_pid($p{'pid'}) . ")\n";

	}
	$lastapp = $p{'executable'};
    }
    if ($apprepeatcount > 0) {
	print "\t (x" . ($apprepeatcount+1) . "): ";
	$_ = decorated_pid($_) for (@repeatedpids);
	print join (', ', @repeatedpids);
	print "\n";

	$lastapp = ""; $apprepeatcount = 0;
    }
}
