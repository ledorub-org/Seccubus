# Adding plugins for postprocessing of scans result
# ------------------------------------------------------------------------------
# Copyright 2017 Oleg Makarov
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

package Seccubus::Plugins;

use strict;
use Exporter;
use Seccubus::Rights;
 
our @ISA = ('Exporter');

our @EXPORT = qw (
                  new

);

our @valid_scanners = qw(OpenVAS Nessus Nmap);

use SeccubusV2;
use Seccubus::DB;
use Seccubus::Rights;
use Seccubus::Inventory;
use Data::Dumper;

sub new {
    my ($class, %args) = @_;

    my $self = bless {} , $class;

    if (-d $args{plugins_dir}) {
        $self -> {plugins_dir} = $args{plugins_dir};
    } else {
        die "Cannot find plugin directory";
    }

    if ($args{scanner} ~~ @valid_scanners) {
        $self -> {scanner}    = $args{scanner};
    } else {
        die "Not valid scanner\n";
    }

    if ($args{debug}) {
        $self -> {debug} = 1;
        print "Ok, we will show debug messages\n";
    }

    if ($args{workspace_id}) {
        $self -> {workspace_id} = $args{workspace_id};
    } else {
        die "Not valid workspace_id\n";
    }

    $self -> {inventory} = Seccubus::Inventory -> new( workspace_id => $self -> {workspace_id} );

    $self -> {plugins} = [];
    $self -> {current_plugin} = 0;
    
    return $self;
}


sub load_all_plugins {
    my $self = shift;
    my $dir = $self -> {plugins_dir};
    my $listref = $self -> {plugins};
    print "load_plugins from $dir . . .\n" if ($self -> {debug});
    opendir (my $dh, $dir) || die "$!"; 
    my @filelist;

    # Sorting files by first chars of name 
    my @tmplist = sort { $a <=> $b } readdir($dh);

    for (@tmplist) {
        next if ($_ eq '.' || $_ eq '..');

        # Parsing single plugin

        my ($name, $scanner, $state, $code) = $self -> load_plugin($_);

        next unless ($state eq "enabled");

        my $result = eval $code;

        # Check if we has exception in code

        if ($result) {
            push (@{$listref}, $result);
        } else {
            if ($self -> {debug}) {
                print "Problem with execution plugin $name\n";
                print $@;   
            }
        }
    }
    closedir DIR;
    return (0,0);
}

sub load_plugin {
    my $self = shift;
    my $plugin_file = shift;

    print "Load $plugin_file\n" if ($self -> {debug});

    my $filename = $self -> {plugins_dir} . "/" . $plugin_file;
    my $name;
    my $scanner;
    my $state;
    my $code;

    open (F, $filename);
    while (my $f_line = <F>) {
        # Parsing header
        unless ($code) {
            my ($str, $comment) = split (/\s*\#\s*/, $f_line);

            if ($comment =~ /scanner:\s+(\w+)/) {
                last if ($1 ne $self -> {scanner});
                $scanner = $1;
            } elsif ($comment =~ /name:\s+([\w\d_-]+)/) {
                $name = $1;
            } elsif ($comment =~ /state:\s+(\w+)/) {
                last if ($1 ne 'enabled');
                $state = $1;
            }
            next unless ($str);
        }
            
        $code .= $f_line;
    }
    close F;
    return undef, undef, undef, undef unless ($state);
    return ($name, $scanner, $state, $code);
}

sub test_plugin {
    my $self = shift;
    my $plugin_file = shift;

    # Define test data

    my $finding;
    $finding -> {ip}          = '127.0.0.1';
    $finding -> {unid}        = '100127000000001';
    $finding -> {scan_id}     = '150';
    $finding -> {run_id}      = '800';
    $finding -> {port}        = '8080';
    $finding -> {severity}    = '3';
    $finding -> {finding_txt} = 'Hello! This is test finding from fake scanner. We have CVE-0000-00 in port 8080';

    my ($name, $scanner, $state, $code) = $self -> load_plugin($plugin_file);
    unless ($name) {
        die "Plugin without name or wrong file format\n";
    }
    # Eval plugin code
    my $result = eval($code);
    unless ($result) {
        print "Problem with execution plugin $name\n";
        print $@;   
    }

    # Try to processing test data with plugin
    $result -> (\$finding);

    print Dumper $finding;
}

sub list {
    my $self = shift;
    print Dumper $self -> {plugins};
}


sub run {
    my $self = shift;
    my $finding = shift;
    for my $plugin_code (@{$self -> {plugins}}) {
        $plugin_code -> ($finding);
    }
}