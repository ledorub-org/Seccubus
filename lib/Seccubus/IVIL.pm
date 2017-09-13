# ------------------------------------------------------------------------------
# Copyright 2017 Frank Breedijk, Alex Smirnoff
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
package Seccubus::IVIL;

=head1 NAME $RCSfile: SeccubusIVIL.pm,v $

This Pod documentation generated from the module SeccubusIVIL gives a list
of all functions within the module.

=cut

use strict;
use Exporter;

our @ISA = ('Exporter');

our @EXPORT = qw (
        load_ivil
        load_ivil2
    );

use SeccubusV2;
use Seccubus::Workspaces;
use Seccubus::Scans;
use Seccubus::Runs;
use Seccubus::Findings;
use Seccubus::Vulnerabilities;
use Seccubus::Hostnames;
use Data::Dumper;

use Carp;
use IVIL;

sub load_ivil {
    my $ivil_xml_data = shift;
    my $scanner = shift;
    my $scanner_ver = shift;
    my $timestamp = shift;
    my $workspace = shift;
    my $scan = shift;
    my $print = shift;
    my $allowempty = shift;
    my $cdn = shift;

    my $xml = new XML::Simple;
    my $ivil = $xml->XMLin($ivil_xml_data,
                      forcearray    => [ 'finding', 'references' ],
                KeyAttr     => undef,
                SuppressEmpty   => "",
                          );

    if ( exists $ivil->{addressee} && $ivil->{addressee}->{program} eq "Seccubus" ) {
        $scan = $ivil->{addressee}->{programSpecificData}->{scan} unless $scan;
        $workspace = $ivil->{addressee}->{programSpecificData}->{workspace} unless $workspace;
    }
    confess "Unable to determine workspace" unless $workspace;
    $scan = $workspace unless $scan;

    $scanner = $ivil->{sender}->{scanner_type} unless $scanner;
    $scanner_ver = $ivil->{sender}->{version} unless $scanner_ver;

    $timestamp = $ivil->{sender}->{timestamp} unless $timestamp;
    confess "Unable to determine timestamp" unless $timestamp;

    $timestamp .= "00" if  $timestamp =~ /^\d{12}$/;
    confess "Timestamp: '$timestamp' is invalid" unless $timestamp =~ /^\d{14}$/;

    my $count = 0;
    if ( exists $ivil->{findings}->{finding} ) {
        $count = @{$ivil->{findings}->{finding}};
    }
    print "There are $count findings\n" if $print;

    if ( $count > 0 || $allowempty ) {
        # This bocks gets the ID from and/or creates the workspace, scan and run
        my $workspace_id = get_workspace_id("$workspace");
        unless ( $workspace_id ) {
            $workspace_id = create_workspace($workspace);
        }
        my $scan_id = get_scan_id($workspace_id, $scan);
        unless ( $scan_id ) {
            confess "Unable to determine scanner" unless $scanner;
            $scan_id = create_scan($workspace_id, $scan, $scanner, "Please update manually");
        }
        my $run_id = update_run($workspace_id, $scan_id, $timestamp);

        # Now we create the findings

        foreach my $finding ( @{$ivil->{findings}->{finding}} ) {
            $finding->{severity} = 99 unless defined $finding->{severity};
            $finding->{severity} = 99 if $finding->{severity} eq "";
            $finding->{severity} = 99 if $finding->{severity} == 0;
            # TODO: Seccubus currently does not handle the
            # references as specified in the IVIL format

            # Transform a vulnerability references to simple array
            my @types = qw(cve cwe eol);

            my %refs;
            if (ref($finding -> {references}) eq 'ARRAY') {
                for my $finding_ref (@{$finding -> {references}}) {
                    if (ref($finding_ref) eq 'HASH') {
                        for my $key (@types) {
                            if (ref($finding_ref -> {$key}) eq 'ARRAY') {
                                $refs{$key} = [] unless (defined $refs{$key});
                                @{$refs{$key}} = (@{$refs{$key}}, @{$finding_ref -> {$key}});
                            } elsif ($finding_ref -> {$key}) {
                                $refs{$key} = [] unless (defined $refs{$key});
                                @{$refs{$key}} = (@{$refs{$key}}, $finding_ref -> {$key});
                            }
                        }
                    }
                }
            } 

            my $unid = get_unid($workspace_id, $finding->{ip});

            # Здесь надо: если есть уязвимости типа CVE - создаём уязвимости. 
            # Если есть eol, создаём уязвимость
            # Если ничего нету, но severity = 1,2,3, ставим статус 9.

            my $severity = $finding->{severity};
            my $cves = $#{$refs{cve}};
            my $eol  = $#{$refs{eol}};
            my $cwes  = $#{$refs{cwe}};
            my $status = 1;

            my @types;
            if ($cves >= 0) {
                @types = qw(cve);
            } elsif ($eol >= 0) {
                @types = qw(eol);
            } elsif (($severity >= 1 && $severity < 99) && $cves < 0 && $cwes >0) {
                @types = qw(cwe);
            } elsif (($severity >= 1 && $severity < 99) && $cves < 0 && $eol < 0 && $cwes < 0) {
                @types = qw(ar);
                @{$refs{ar}} = 'AR:';
                $status = 9;
            }

            my $finding_id = update_finding(
                workspace_id    => $workspace_id,
                run_id      => $run_id,
                scan_id     => $scan_id,
                host        => $finding->{ip},
                port        => $finding->{port},
                plugin      => $finding->{id},
                finding     => $finding->{finding_txt},
                severity    => $finding->{severity},
                timestamp   => $timestamp,
                status      => $status,
            );

            for my $vulntype (@types) {
                for my $vulnid (@{$refs{$vulntype}}) {
                    update_vuln(
                        workspace_id    => $workspace_id,
                        run_id      => $run_id,
                        unid        => $unid,
                        scan_id     => $scan_id,
                        ip          => $finding->{ip},
                        port        => $finding->{port},
                        plugin      => $finding->{id},
                        finding_id  => $finding_id,
                        severity    => $finding->{severity},
                        timestamp   => $timestamp,
                        vulnid      => $vulnid,
                        vulntype    => $vulntype,
                    );
                }
            }

            if ( $finding->{ip} =~ /^\d+\.\d+\.\d+\.\d+$/ ) {
                update_hostname($workspace_id, $finding->{ip}, $finding->{hostname});
            }
            print "Finding: $finding->{ip}, $finding->{port}, $finding->{id}\n$finding->{finding_txt}\n" if $print >1;
        }
        return ($workspace_id, $scan_id, $run_id);
    } else {
        return (-1,-1,-1);
    }
}

# Close the PM file.
return 1;
