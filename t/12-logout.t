#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);
use HTTP::CookieJar::LWP;

use Test::More tests => 11;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $servers = $data->[1];
    my $server_port = $servers->[2]->{'port'};
    my $host = "http://localhost:$server_port";

    my $jar = HTTP::CookieJar::LWP->new();
    my $ua = LWP::UserAgent->new(cookie_jar => $jar);

    my $res = $ua->get("$host/farv1_session/login?id=some-id");
    is($res->code(), 200, 'Authenticated request was successful');

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Authenticated request was successful');
    my $content = decode_json($res->content());
    ok($content->{'entities'},
        'Authenticated request contains entities');

    $res = $ua->get("$host/farv1_session/logout");
    is($res->code(), 200, 'Logout request was successful');
    $content = decode_json($res->content());
   
    is($content->{'notices'}->[0]->{'title'}, 'Logout Result',
        'Got logout result in notices');
    like($content->{'notices'}->[0]->{'description'}->[0], 
        qr/succeeded/i,
        'Got logout description in notices');

    like($content->{'notices'}->[1]->{'description'}->[0], 
        qr/access token revocation succeeded/i,
        'Got access token revocation description in notices');

    like($content->{'notices'}->[2]->{'description'}->[0], 
        qr/refresh token revocation succeeded/i,
        'Got refresh token revocation description in notices');

    my ($cookie) = $jar->cookies_for('http://localhost');
    ok((not $cookie), 'Cookie unset on logout');
 
    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Request now treated as unauthenticated');
    $content = decode_json($res->content());
    ok((not $content->{'entities'}),
        'Unauthenticated request does not contain entities');
}

END {
    stop_test_servers($pids);
}

1;
