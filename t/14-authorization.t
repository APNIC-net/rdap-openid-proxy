#!/usr/bin/perl

use warnings;
use strict;

use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);

use Test::More tests => 7;

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

    my $uri = URI->new("$host/domain/203.in-addr.arpa");
    $uri->query_form(
        id_token     => $id_token,
        access_token => $access_token,
    );
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), "Fetched object using tokens");
    my $content = decode_json($res->decoded_content());
    ok($content->{'entities'},
        'Authenticated query result contains entities');

    $uri->query_form(
        id_token => $id_token,
    );
    my $req = HTTP::Request->new();
    $req->method('GET');
    $req->uri($uri);
    $req->header('Authorization', 'Bearer '.$access_token);
    $res = $ua->request($req);
    ok($res->is_success(), "Fetched object using header");
    $content = decode_json($res->decoded_content());
    ok($content->{'entities'},
        'Authenticated query result contains entities');

    $req = HTTP::Request->new();
    $req->method('GET');
    $req->uri($uri);
    $res = $ua->request($req);
    ok((not $res->is_success()), "Unable to fetch object");
    is($res->code(), HTTP_FORBIDDEN, 'Got correct response code');
}

END {
    stop_test_servers($pids);
}

1;
