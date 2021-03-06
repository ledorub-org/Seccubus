# Template findings processing plugin for Seccubus
# Header should to contain three fields: name, scanner, and state. 

# ------------------------------------------------------------------------------
# Header:
# ------------------------------------------------------------------------------
# name:    All_scanner_ip_collector
# scanner: All
# state:   enabled 
# ------------------------------------------------------------------------------

sub {
    my $ref = shift; # This is reference to finding. 
                     # You can use $$ref -> {finding_field_name}. eg: $$ref -> {ip}.
                     # See doc in Plugins.pm for details

    my $inventory = shift; # This is ref to inventory object.

    my $ip = $$ref -> {ip};

    $$inventory -> add_object('/' . $ip . '/ipaddr/' . $ip);


    return 1; # You should return 1 if the plugin has normally executed and 0 in other case.
}