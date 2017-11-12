# Template findings processing plugin for Seccubus
# Header should to contain three fields: name, scanner, and state. 

# ------------------------------------------------------------------------------
# Header:
# ------------------------------------------------------------------------------
# name:    CPEDetector
# scanner: OpenVAS
# state:   enabled 
# ------------------------------------------------------------------------------
# Test data:
# ------------------------------------------------------------------------------
# test_data:finding_txt: "blahblah cpe:/a:roundcube:webmail:1.0.3 blahblah\nLocation: /home/blabla"
# ------------------------------------------------------------------------------

sub {
    my $ref = shift; # This is reference to finding. 
                     # You can use $$ref -> {finding_field_name}. eg: $$ref -> {ip}.
                     # See doc in Plugins.pm for details


    my $inventory = shift; # This is ref to inventory object.

    if ($$ref -> {finding_txt} =~ /cpe:\/a:([\w\:\.\d\-\_]+)/) {
        my $cpe = $1;
        my ($location) = $$ref -> {finding_txt} =~ /Location: (\/[\d\w\-\_\.\/]+)/;

        my ($vendor, $software, $version) = split(/:/, $cpe);

        my $ip = $$ref -> {'ip'};
        my $port = $$ref -> {'port'};
        my ($portnum, $proto) = split("/", $port);
        $port = "$proto/$portnum";

        unless ($port =~ /[Gg]ener(ic)|(al)/) {
            $$inventory -> add_object('/' . $ip . '/ipaddr/' . $ip . '/container/ports/' . $port . '/container/service/' . $vendor . ' ' . $software . '/' . $version);
            if ($location) {
                $$inventory -> add_object('/' . $ip . '/ipaddr/' . $ip . '/container/ports/' . $port . '/container/service/' . $vendor . ' ' . $software . '/' . $version . '/location/"' . $location . '"' );
            }
        }
        $$inventory -> add_object('/' . $ip . '/container/software/' . $vendor . ' ' . $software . '/' . $version);
        if ($location) {
            $$inventory -> add_object('/' . $ip . '/container/software/' . $vendor . ' ' . $software . '/' . $version . '/location/"' . $location . '"');
        }
    }
    return 1; # You should return 1 if the plugin has normally executed and 0 in other case.
}
