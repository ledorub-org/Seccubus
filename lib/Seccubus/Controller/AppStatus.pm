# ------------------------------------------------------------------------------
# Copyright 2017 Frank Breedijk
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
package Seccubus::Controller::AppStatus;
use Mojo::Base 'Mojolicious::Controller';

use strict;

# This action will render a template
sub read {
	my $self = shift;

	my $data = $self->req->json();
	my $errorstatus = $self->param('errorcode');

	$errorstatus = 200 unless $errorstatus;
	$errorstatus = 200 if $errorstatus < 1;

	if ( $data && exists $data->{errorstatus} ) {
		$errorstatus = $data->{errorstatus};
	}

	my $json = [];
	my $status = 200;

	my @configs = qw(
		/home/seccubus/etc/config.xml
		/etc/seccubus/config.xml
		/opt/seccubus/etc/config.xml
        etc/config.xml
		etc/dummy.config.xml
   	);

	my @dirs = qw (
		modules
		scanners
		bindir
		configdir
		dbdir
	);

    #my $env;
    #foreach my $k ( sort keys %ENV ) {
    #    $env .= "$k - $ENV{$k}\n";
    #}
    #push @$json, { name => "Environment " , result => "OK", message => $env };

	my $config_found = 0;
	my $config_file = "";
	foreach my $config ( @configs ) {
		if ( -e $config ) {
			$config_found = 1;
			$config_file = $config;
		}
	}
	if( $config_found) {
		push @$json, { name => "Configuration file", result => "OK", message => "Configuration file found at '$config_file'"};
	} else {
		push @$json, { name => "Configuration file", result => "Error", message => "Configuration file could not be found. Please copy one of the example configuration files to one of the following locations and edit it:" . join(", ",@configs)};
		$status = $errorstatus;
		goto EXIT;
	}

	require SeccubusV2;
	my $config = SeccubusV2::get_config();

	##### Test paths
	foreach my $dir ( @dirs ) {
		if ( ! -d $config->{paths}->{$dir} ) {
			push @$json, { name => "Path $dir", result => "Error", message => "The path for '$dir', '$config->{paths}->{$dir}' defined in '$config_file', does not exist"};
			$status = $errorstatus;
			goto EXIT;
		} else {
			push @$json, { name => "Path $dir", message => "The path for '$dir', '$config->{paths}->{$dir}' defined in '$config_file', was found", result => "OK"};
		}
	}

	##### Test database login
	require Seccubus::DB;
	my $dbh = Seccubus::DB::open_database();

	if ( ! $dbh ) {
		push @$json, { name => "Database login", message => "Unable to log into the the database. Either the definitions in '$config_file' are incorrect or you need to create '$config->{database}->{engine}' database '$config->{database}->{database}' on host '$config->{database}->{host}' and grant user '$config->{database}->{user}' the rights to login in with the specified password.\nFor mysql execute the following command: create database $config->{database}->{database};grant all privileges on $config->{database}->{database}.* to $config->{database}->{user} identified by '<password>';exit", result => "Error"};
		$status = $errorstatus;
		goto EXIT;
	} else {
		push @$json, { name => "Database login", message => "Login to database '$config->{database}->{database}' on host '$config->{database}->{host}' with the credentials from '$config_file', was successful", result => "OK"};
	}

	##### Test database tables
	my $current_db_version = $SeccubusV2::DBVERSION;

	# Make sure login to the database was successful
	my $tables = Seccubus::DB::sql( return	=> "ref",
			  	      query	=> "show tables",
				    );

	if ( ! @$tables ) {
		my $file = $config->{paths}->{dbdir} . "/structure_v$current_db_version" . "\." . $config->{database}->{engine};
		push @$json, { name => "Database structure", message => "Your database seems to be empty, please execute the sql statements in '$file' to create the required tables", result => "Error"};
		$status = $errorstatus;
		goto EXIT;
		# TODO: Add link to screen that does this for the user
		# my $api = "api/updateDB.pl?toVersion=$current_db_version&action=structure";
	} else {
		push @$json, { name => "Database structure", message => "Your database does have datastructures in it.", result => 'OK'};
	}

	##### Test the default DB data version
    my $version;
	eval {

		( $version ) = Seccubus::DB::sql(
            return	=> "array",
			query	=> "SELECT value FROM config
			            WHERE name = 'version'",
		);

    } or do {
        my $file = $config->{paths}->{dbdir} . "/data_v$current_db_version" . "\." . $config->{database}->{engine};
        push @$json, { name => "Database data", message => "Your database is missing data, please execute the sql statements in '$file' to insert the base data into the database", result => 'OK'};
        $status = $errorstatus;
        goto EXIT;
        # TODO: Direct user to a helpfull screen
        # my $api = "api/updateDB.pl?toVersion=&action=data";
        # $message = "$msg. API Call: '$api'";
    };
	if ( $version != $current_db_version ) {
		my $file = $config->{paths}->{dbdir} . "/";
		if ( $version eq "" ) {
			$file .= "data_v$current_db_version." . $config->{database}->{engine};
		} elsif ( $version < $current_db_version ) {
			$file .= "upgrade_v" . $version . "_v" . ($version+1) . "." . $config->{database}->{engine};
		} else {
			push @$json, { name => "Database version error", message => "Your database returned version number '$version', the developers for Seccubus do not know what to do with this", result => "Error"};
			$status = $errorstatus;
			goto EXIT;
		}
		push @$json,{ name => "Database version", message => "Your database is not current, please execute the sql statements in '$file' to update the database to the next version and rerun this test", result => 'Error'};
		$status = $errorstatus;
		goto EXIT;
	} else {
		push @$json,{ name => "Database version", message => "Your database has the base data and is the current version.", result => 'OK'};
	}

	##### Test if the user is logged in
    my $header_name = $config->{auth}->{http_auth_header};
    my $header_value = "";
    $header_value = $self->req->headers->header($header_name) if $header_name;
    my $u = $self->session->{user};
    if ( ( $self->app->mode() eq "production" && $header_name ) || ( $self->app->mode() eq "development" && $header_value ) ) {
        $ENV{SECCUBUS_USER} = $header_value;
    } elsif ( $u && Seccubus::Users::check_password($u->{name},undef,$u->{hash}) ) {
        $ENV{SECCUBUS_USER} = $u->{name};
    } else {
        $ENV{SECCUBUS_USER} = "Not logged in";
    }
    my ( $userid, $valid, $isadmin, $message ) = Seccubus::Users::get_login();
    if ( $valid ) {
        push @$json, {name => "Authentication", message => "You are logged in: $message", result => 'OK'};
    } else {
        push @$json, {name => "Authentication", message => "You are not in: $message", result => 'Error'};
    }

	##### Test SMTP config
	if ( ! exists $config->{smtp} ) {
		push @$json, {name => "SMTP configuration", message => "No smtp configuration specified in you config file, notification will NOT be sent", result => 'Warn'};
	} elsif(  ! exists $config->{smtp}->{server} ) {
		push @$json, {name => "SMTP configuration", message => "No smtp server specified", result => "Warn"};
	} elsif( ! gethostbyname($config->{smtp}->{server}) ) {
		push @$json, {name => "SMTP configuration", message => "Cannot resolve smtp server $config->{smtp}->{server}", result => "Warn"};
	} elsif( ! exists $config->{smtp}->{from} ) {
		push @$json, {name => "SMTP configuration", message => "No from address specified", result => "Warn"};
	} elsif ( $config->{smtp}->{from} !~ /^[\w\.\+]+\@[\w\d\.]+$/ ) {
		push @$json, {name => "SMTP configuration", message => "$config->{smtp}->{from} doesn't apear to be a valid email address", result => "Error"};
	} else {
		push @$json, {name => "SMTP configuration", message => "SMTP configuration OK", result => "OK"};
	}


EXIT:
	$self->render(
		json => $json,
		status => $status,
	);
}

1;
