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

    if (grep {$args{scanner} eq $_} @valid_scanners) {
        $self -> {scanner}    = $args{scanner};
    } else {
        die "Not valid scanner\n";
    }

    if ($args{timestamp} =~ /\d{14}/) {
        $self -> {timestamp} = $args{timestamp};
    } else {
        die "You need to determine timestamp";
    }

    if ($args{debug}) {
        $self -> {debug} = 1;
        print "Ok, we will show debug messages\n";
    }

    print "Scanner: " . $self -> {scanner} . "\n" if ($self -> {debug});

    if ($args{workspace_id}) {
        $self -> {workspace_id} = $args{workspace_id};
    } else {
        die "Not valid workspace_id\n";
    }

    $self -> {inventory} = Seccubus::Inventory -> new( workspace_id => $self -> {workspace_id}, 
                                                       timestamp    => $self -> {timestamp}, 
                                                     );
    $self -> {shared} = {};
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
        print "File $_ . . .\n" if ($self -> {debug});

        # Parsing single plugin

        my ($name, $scanner, $state, $code, $test_data) = $self -> load_plugin($_);

        print "$name, $scanner, $state . . .\n" if ($self -> {debug});

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
    my $test_data;

    open (F, $filename) || print "Cannot open $filename: $!\n";

    while (my $f_line = <F>) {
        chomp $f_line;
        next unless $f_line;
        unless ($code) {
            my ($str, $comment) = split (/\s*\#\s*/, $f_line);
            if ($comment =~ /scanner:\s+(\w+)/) {
                return undef, undef, undef, undef, undef unless ($1 eq $self -> {scanner} || $1 =~ /^[Aa]ll$/);
                $scanner = $1;
                print "Scanner: $scanner" if ($self -> {debug});
            } elsif ($comment =~ /name:\s+([\w\d_-]+)/) {
                $name = $1;
                print "Parsing plugin $name\n" if ($self -> {debug});
            } elsif ($comment =~ /state:\s+(\w+)/) {
                return undef, undef, undef, undef, undef if ($1 ne 'enabled');
                print "Plugin $name add to list\n" if ($self -> {debug});
                $state = $1;
            } elsif ($comment =~ /test_data:([\w\_\-\.]+):\s+"([^"]+)"/) {
                if ($test_data -> {$1}) {
                        $test_data -> {$1} .= "\n" . $2;
                    } else {
                        $test_data -> {$1} = $2;
                    }
            }
            next unless ($str);
        }
        $code .= $f_line . "\n";
    }
    close F;
    return undef, undef, undef, undef, undef unless ($state);
    return ($name, $scanner, $state, $code, $test_data);
}

sub test_plugin {
    my $self = shift;
    my $plugin_file = shift;

    # Define test data

    my ($name, $scanner, $state, $code, $test_data) = $self -> load_plugin($plugin_file);

    unless ($name) {
        die "Plugin without name or wrong file format\n";
    }

    # Default test data

    my $finding;
    $finding -> {ip}          = '127.0.0.1';
    $finding -> {unid}        = '100127000000001';
    $finding -> {scan_id}     = '150';
    $finding -> {run_id}      = '800';
    $finding -> {port}        = '8080';
    $finding -> {severity}    = '3';
    $finding -> {finding_txt} = 'Hello! This is test finding from fake scanner. We have CVE-0000-00 in port 8080';

    for my $f (keys($finding)) {
        if (!$test_data -> {$f}) {
            $test_data -> {$f} = $finding -> {$f};
        }
    }


    # If test_data determine in plugin file:
    for my $test_key (keys($test_data)) {
        $finding -> {$test_key} = $test_data -> {$test_key};
    } 

    # Eval plugin code
    my $plugin_code = eval($code);
    unless ($plugin_code) {
        print "Problem with execution plugin $name\n";
        $self -> show_code($code, $@);
        die;
    }

    # Try to processing test data with plugin
    eval {
        $plugin_code -> (\$finding, \$self -> {inventory});
    };
    if ($@) {
        print "Problem with execution plugin $name\n";
        $self -> show_code($code, $@);
        die;
    }

    print "Executed normally\n";
    exit;
}

sub run {
    my $self = shift;
    my $finding = shift;
    for my $plugin_code (@{$self -> {plugins}}) {
        my $ret = $plugin_code -> ($finding, \$self -> {inventory});
        #unless ($ret == 1) {
        #    print "Unable to execute plugin ($ret)\n" if ($self -> {debug});
        #}
    }
}

sub show_code {
    my $self = shift;
    my $code = shift;
    my $errorline = shift;

    my ($highlight) = $errorline =~ /line (\d+).$/;
    $highlight = "0$highlight" if ($highlight < 10);

    # Colorize console

    my %c = ('blue'           => "\x1b[34m",
             'red'            => "\x1b[31m",
             'gray'           => "\x1b[0;37m",
             'bold_blue'      => "\x1b[1;34m",
             'bold_red'       => "\x1b[1;31m",
             'white_on_blue'  => "\x1b[1;37;44m",
             'gray_on_blue'   => "\x1b[0;37;44m",
             'black_on_white' => "\x1b[1;30;47m",
             'red_on_white'   => "\x1b[1;31;47m",
             'yellow'         => "\x1b[1;33m",
             'yellow_on_blue' => "\x1b[1;33;44m",
             'blue_on_white'  => "\x1b[1;34;47m",
             'reset'          => "\x1b[0m",
    );

    print "\n";
    print "  " . $c{red} . $@ . $c{reset} . "\n";
    my @code = split(/\n/, $code);
    my $num = "00";
    for (@code) {
        $num++;
        print "$c{yellow}" if ($num eq $highlight);
        print '  ' . $num . '  ' . $_ . "\n";
        print "$c{reset}" if ($num eq $highlight);
    }
    print "\n";
}