#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);

use Test::More tests => 5;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $servers = $data->[1];
    my $server_port = $servers->[2]->{'port'};
    my $host = "http://localhost:$server_port";

    my $ua = LWP::UserAgent->new();
    my $res = $ua->get("$host/tokens?id=some-id");
    is($res->code(), 200, 'Got tokens');
    my $token_data = decode_json($res->decoded_content());
    my ($access, $refresh) =
        @{$token_data}{qw(access_token refresh_token)};

    my $uri = URI->new("$host/tokens/revoke");
    $uri->query_form(
        id    => 'some-id',
        token => $access
    );
    $res = $ua->post($uri->as_string());
    is($res->code(), 200, 'Revoked access token successfully');

    $res = $ua->post($uri->as_string());
    is($res->code(), 400, 'Unable to re-revoke token');

    $uri->query_form(
        id    => 'some-id',
        token => $refresh
    );
    $res = $ua->post($uri->as_string());
    is($res->code(), 200, 'Revoked refresh token successfully');

    $res = $ua->post($uri->as_string());
    is($res->code(), 400, 'Unable to re-revoke token');
}

END {
    stop_test_servers($pids);
}

1;
