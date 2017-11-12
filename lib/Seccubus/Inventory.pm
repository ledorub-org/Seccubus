# ------------------------------------------------------------------------------
# Copyright 2017
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

package Seccubus::Inventory;

use strict;
use Exporter;
 
our @ISA = ('Exporter');

our @EXPORT = qw (
    new
    add_network_oblect
);

use Carp;
use Net::IP;
use Socket;
use Data::Dumper;

use SeccubusV2;
use Seccubus::DB;
use Seccubus::Rights;
use Seccubus::Hostnames;

sub new {
    my ($class, %args) = @_;

    my $self = bless {} , $class;
    die "Workspace number not set" unless ($args{workspace_id});

    $self -> {workspace_id} = $args{workspace_id};
    $self -> {cache} = {};

    if (may_write($self -> {workspace_id})) {
        $self -> {write} = 1;
    }

    if (may_read($self -> {workspace_id})) {
        $self -> {read} = 1;
    }

    if ($args{timestamp}) {
        $self -> {timestamp} = $args{timestamp};
    } else {
        # Если нет таймстампа, берём 
        $self -> {timestamp} = time();
    }

    if ($args{test_run}) {
        $self -> {test_run} = 1;
    }

    return $self;
}

sub parse_path {
    my ($self, $ipath) = @_;
    my @path;
    while ($ipath =~ /\/([\w\.\-\_\s]+)|("([^"]+)")/) {
        if ($1) {
            push (@path, $1); 
        } elsif ($3) {
            push (@path, $3); 
        }
        $ipath = $';
    }
    my $path;

    my $last = $#path;

    $path -> {host} = get_unid($self -> {workspace_id},$path[0]);
    for (my $step = 1; $step <= $#path;  $step += 2) {
        my $key = $path[$step];
        my $value = $path[$step + 1];
        push( @{$path -> {path}}, [$path[$step], $path[$step + 1]] );
    }
    return $path;
}  

sub add_object {
    my ($self, $ipath) = @_;
    my $path = $self -> parse_path($ipath);
    # insert (or just get id) host
    my $id = $self ->  insert(parent_id => 0, key => 'host', value => $path -> {host});

    # insert containers
    for my $array (@{$path -> {path}}) {
         my ($key, $value) = @{$array};
        $id = $self ->  insert(parent_id => $id, key => $key, value => $value);        
    }
    return $id;
}


sub check_object {
    my ($self, $parent_id, $key, $value) = @_;
    my $query;
    my @values;
    if ($value eq '' or $value eq 0) {
        $query = "select id from inventory where `parent_id` = ? and `key` = ?";
        @values = ($parent_id, $key);
    } else {
        $query = "select id from inventory where `parent_id` = ? and `key` = ? and `value` = ?";
        @values = ($parent_id, $key, $value);
    }
    my @result = sql( "return"    => "array",
                      "query"     => $query,
                      "values"    => \@values,
                    );
    return $result[0] if ($#result == 0);
    die "Strange problem: many objects with same (parent_id, key, value)\n" if ($#result > 0);
    return 0;
}

sub check_object_by_id {
    my ($self, $id) = @_;

    my $query = "select count(id) from inventory where `id` = ? and workspace_id = ?";
    my @result = sql( "return"    => "array",
                      "query"     => $query,
                      "values"    => [$id, $self -> {workspace_id}],
                    );
    return 1 if ($#result == 0);
    return 0;
}

sub update_timestamp {
    my ($self, $obj_id) = @_;
    my $query = "update inventory set timestamp = ? where id = ?";
    my $ref = sql( "return"    => "handle",
                   "query"     => $query,
                   "values"    => [$self -> {timestamp}, $obj_id],
                 );
}

sub get_id_by_key_value{
    my ($self, $key, $value) = @_;

}

sub insert {
    my ($self, %args) = @_;

    return 0 if ($self -> {test_run});

    # Use cache for fast processing
    if ($self -> {cache} -> {$args{parent_id}} -> {$args{key}} -> {$args{value}}) {
        return $self -> {cache} -> {$args{parent_id}} -> {$args{key}} -> {$args{value}};
    }
    # We check if object with this parent already exists
    my $check_id = $self -> check_object($args{parent_id}, $args{key}, $args{value});
    if ($check_id) {
        $self -> {cache} -> {$args{parent_id}} -> {$args{key}} -> {$args{value}} = $check_id;
        # Update timestamp in this object to actual
        $self -> update_timestamp($check_id);
        return $check_id;
    }

    $args{timestamp} = $self -> {timestamp};
    $args{change_timestamp} = $self -> {timestamp};
    $args{workspace_id} = $self -> {workspace_id};
    my @keys;
    my @values;
    my $args;
    my $query = "insert into inventory (";
    for (keys %args) {
        push (@keys,'`' . $_ . '`');
        push (@values, "?");
        push (@$args, $args{$_});
    }
    $query .= join (", ", @keys) . ") values (" ;
    $query .= join (", ", @values) . ")";

    my $id = sql( "return"    => "id",
                  "query"     => $query,
                  "values"    => $args,
                 );
    $self -> {cache} -> {$args{parent_id}} -> {$args{key}} -> {$args{value}} = $id;
    return $id;
}

sub search {
    my ($self, %args) = @_;

    my @qargs;
    my $query = "select id, parent_id, `key`, `value` from inventory where workspace_id = ?";

    push (@qargs, $self -> {workspace_id});
    if ($args{key}) {
        $query .= " and where `key` = ?";
        push (@qargs, $args{key});
    }
    if ($args{value}) {
        $query .= " and where `value` like ?";
        push (@qargs, $args{value});
    }

    my @result = sql( "return"    => "array",
                "query" => $query,
                "values"    => \@qargs,
              );

    return @result;
}

return 1;
    