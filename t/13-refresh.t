#!/usr/bin/perl

use warnings;
use strict;

use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);

use Test::More tests => 8;

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
    my ($id_token, $access_token, $refresh_token) =
        @{$token_data}{qw(id_token access_token refresh_token)};

    my $uri = URI->new("$host/tokens");
    $uri->query_form(
        id            => 'some-id',
        refresh_token => $access_token
    );
    $res = $ua->get($uri->as_string());
    is($res->code(), 400, 'Unable to refresh using access token');

    $uri->query_form(
        id            => 'some-id',
        refresh_token => $refresh_token
    );
    $res = $ua->get($uri->as_string());
    is($res->code(), 200, 'Refreshed token successfully');

    my $token_data2 = decode_json($res->decoded_content());
    my ($access_token2, $refresh_token2) =
        @{$token_data2}{qw(access_token refresh_token)};

    isnt($access_token2, $access_token, 'Access token changed');
    is($refresh_token2, $refresh_token, 'Refresh token did not change');

    $uri = URI->new("$host/domain/203.in-addr.arpa");
    $uri->query_form(
        id_token     => $id_token,
        access_token => $access_token
    );
    $res = $ua->get($uri->as_string());
    ok((not $res->is_success()), 'Unable to use old access token');
    is($res->code(), HTTP_FORBIDDEN, 'Got correct response code');

    $uri->query_form(
        id_token     => $id_token,
        access_token => $access_token2
    );
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Able to use new access token');
}

END {
    stop_test_servers($pids);
}

1;
