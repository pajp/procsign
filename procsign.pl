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

use Mac::Processes;
use Term::ANSIColor;

my $color = 1;
$color = 0 if $ENV{'NOCOLOR'};
my @hiddenchains;
my $hideapple = 0;
my $unsigned_in_summary = 1;
my $warnuntrusted = 1;
my $appleanchorcheck = 1;
my $optc = $#ARGV + 1;
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
}
if ($optc) {
    print "Usage:\n";
    print "\t$0 [--hide-apple] [--no-color] [no-unsigned-summary]\n";
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
print 'Examining running processes... ';
while ( ($psn, $psi) = each(%Process) ) {
    print chr(8);
    print color $colors[$cid++] if $color;
    print $wheel[$wid++];
    $wid = 0 if ($wid > $#wheel);
    $cid = 0 if ($cid > $#colors);
    print color 'reset' if $color;

    my $executable = $psi->processAppSpec;
    my $pid = GetProcessPID($psn);
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
    my $path = "";
    $path = join('/', @{$ps{$psn}{'signdata'}{'Authority'}}) if $ps{$psn}{'signdata'}{'Authority'};
    $ps{$psn}{'signpath'} = $path;
    $last_validation_failure{$path} = $csrc;
    $process_signed_by{$path} = [ ] unless $process_signed_by{$path};
    push @{$process_signed_by{$path}}, $psi;
}
print chr(8) x 40;
print ' ' x 40;
print chr(8) x 40;

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
    for (@psis) {
	my $psi = $_;
	if ($lastapp eq $psi->processAppSpec) {
	    $apprepeatcount++;
	} else {
	    print color 'blue' if $color;
	    if ($apprepeatcount > 0) {
		print "\t (x" . $apprepeatcount . ")\n";
	    }
	    $apprepeatcount=0;
	    print "\t" . $psi->processAppSpec;
	    if ($ps{$psi->processNumber}{'csrc'} == 3 && $#{$ps{$psi->processNumber}{'signdata'}{'Authority'}} == -1) {
		print color 'yellow';
		print (" (self-signed)");
	    }
	    print color 'reset' if $color;
	    print " (pid " .GetProcessPID($psi->processNumber). ")\n";

	}
	$lastapp = $psi->processAppSpec;
    }
    if ($apprepeatcount > 0) {
	print "\t (x" . $apprepeatcount . ")\n";
	$lastapp = ""; $apprepeatcount = 0;
    }
}
