#!/usr/bin/perl

use warnings;
use strict;

use JSON::XS qw(decode_json);

use lib './t/lib';
use APNIC::RDAP::OpenID::Test::Utils qw(start_test_servers
                                        stop_test_servers);
use HTTP::CookieJar::LWP;

use Test::More tests => 15;

my $pids;

{
    my $data = start_test_servers();
    $pids = $data->[0];
    my $servers = $data->[1];
    my $server_port = $servers->[2]->{'port'};
    my $host = "http://localhost:$server_port";

    my $jar = HTTP::CookieJar::LWP->new();
    my $ua = LWP::UserAgent->new(cookie_jar => $jar);
    my $res = $ua->get("$host/help");
    is($res->code(), 200, 'Help request was successful');
    my $content = decode_json($res->content());

    ok($content->{'farv1_openidcConfiguration'},
        'Got OIDC configuration in help response');

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Unauthenticated request was successful');
    $content = decode_json($res->content());
    ok((not $content->{'entities'}),
        'Unauthenticated request does not contain entities');

    $res = $ua->get("$host/farv1_session/login?id=some-id");
    is($res->code(), 200, 'Authenticated request was successful');
    $content = decode_json($res->content());

    ok(exists $content->{'iss'},
        'Login response includes issuer identifier');

    ok($content->{'sessionInfo'},
        'Login response includes session information');
    ok($content->{'sessionInfo'}->{'tokenExpiration'},
        'Login response includes token expiration information');
    ok(exists $content->{'sessionInfo'}->{'tokenRefresh'},
        'Login response includes token refresh information');

    my ($cookie) = $jar->cookies_for('http://localhost');
    ok($cookie, 'Cookie was set on login');

    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 200, 'Authenticated request was successful');
    $content = decode_json($res->content());
    ok($content->{'entities'},
        'Authenticated request contains entities');

    sleep(2);
    $res = $ua->get("$host/domain/203.in-addr.arpa");
    is($res->code(), 403, 'Authenticated request failed (expired)');

    $jar->clear();
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
