# Template findings processing plugin for Seccubus
# Header should to contain three fields: name, scanner, and state. 

# ------------------------------------------------------------------------------
# Header:
# ------------------------------------------------------------------------------
# name:    Template
# scanner: All
# state:   enabled 
# ------------------------------------------------------------------------------
# Test data (optional):
# ------------------------------------------------------------------------------
# test_data:ip:          "127.0.0.1"
# test_data:port:        "8080"
# test_data:finding_txt: "blahblah cpe:/a:roundcube:webmail:1.0.3 blahblah"
# ------------------------------------------------------------------------------

sub {
    my $ref = shift; # This is reference to finding. 
                     # You can use $$ref -> {finding_field_name}. eg: $$ref -> {ip}.
                     # See doc in Plugins.pm for details


    my $inventory = shift; # This is ref to inventory object.

    # Example: find CVE number in finding_txt 

    $ref -> {finding_txt} =~ /(CVE-\d+-\d+)/;

    # Add CVE number to finding struct for use in other (next) plugins

    $$ref -> {CVE} = $1;

    return 0; # You should return 0 if the plugin has normally executed and 1 in other case.
}