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
my $optc = $#ARGV + 1;
for (@ARGV) {
    if ($_ eq "--hide-apple") {
	push @hiddenchains, "Software Signing/Apple Code Signing Certification Authority/Apple Root CA";
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

my %process_signed_by;
my %chain_count;
my %ps;
while ( ($psn, $psi) = each(%Process) ) {
    my $executable = $psi->processAppSpec;
    my $pid = GetProcessPID($psn);
    my @signdata = split /\n/, `codesign -dvvv "$executable" 2>&1`;

    print color 'red' if $color;
    if (system("codesign -v $pid 2>&1")) {
	print color 'blue' if $color;
	print "\t" . $executable . "\n";
    }
    print color 'reset' if $color;
    for (@signdata) {
	chomp;
	my ($key, $value) = split /=/, $_, 2;
	$ps{$psn}{'signdata'}{$key} = [ ] unless $ps{$psn}{'signdata'}{$key};
	if ($value && $value ne "") {
	    push @{$ps{$psn}{'signdata'}{$key}}, $value;
	}
    }

    my $path = "";
    $path = join('/', @{$ps{$psn}{'signdata'}{'Authority'}}) if $ps{$psn}{'signdata'}{'Authority'};
    $chain_count{$path} = $#{$ps{$psn}{'signdata'}{'Authority'}}+1 if $ps{$psn}{'signdata'}{'Authority'};
    $ps{$psn}{'signpath'} = $path;
    $process_signed_by{$path} = [ ] unless $process_signed_by{$path};
    push @{$process_signed_by{$path}}, $psi;
}

my $lastapp = "";
my $apprepeatcount = 0;
CHAIN: for (sort keys %process_signed_by) {
    my $path = $_;
    my @psis = @{$process_signed_by{$path}};
    my $hidden = 0;
    for (@hiddenchains) {
	next CHAIN if $_ eq $path;
    }
    if ($path) {
	print "\nProcesses signed by ";
	print color 'green' if $color;
	print "$path";
	if ($chain_count{$path} < 2) {
	    print color 'yellow' if $color;
	    print ' (self-signed)';
	} else {
	    print color 'green' if $color;
	}
	print color 'reset';
	print ":\n";
    } else {
	if (!$unsigned_in_summary) {
	    next;
	}
	print "\nUnsigned processes:\n";
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
