#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);

use Test::More tests => 2;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $servers = $data->[1];
    my $server_port = $servers->[2]->{'port'};
    my $host = "http://localhost:$server_port";

    my $ua = LWP::UserAgent->new();
    my $res = $ua->get("$host/tokens?id=some-id");
    is($res->code(), 200, 'Got tokens for identifier');
    my $content = decode_json($res->decoded_content());
    my ($access_token, $id_token) =
        @{$content}{qw(access_token id_token)};
    
    my $uri = URI->new("$host/domain/203.in-addr.arpa");
    $uri->query_form(id_token     => $id_token,
                     access_token => $access_token);
    $res = $ua->get($uri->as_string());
    is($res->code(), 200, 'Used tokens to fetch page');
}

END {
    stop_test_servers($pids);
}

1;
