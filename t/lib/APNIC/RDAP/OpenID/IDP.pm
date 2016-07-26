package APNIC::RDAP::OpenID::IDP;

use warnings;
use strict;

use APNIC::RDAP::OpenID::Utils qw(access_token_hash);

use Bytes::Random::Secure;
use Crypt::JWT qw(encode_jwt);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(encode_json decode_json);
use LWP::UserAgent;
use MIME::Base64 qw(encode_base64);

use constant PRIVATE_KEY_JSON => '{"d":"DK9qxQ4F5SsCxL1PjJ9FUHhMYpZP4-bus5iRvJTSv2eIzXAJpkMzMovB9HBslL2eoYd0PpI4yYrRnuqzkkCg-ftKcddJ9VsBoWVLzyVcvlTFyHKQ8Uio0rWaSxc_Hf58Yd2mp42YLABFEw9YWz-a8II_V40OP16XbuIQr5s8VrfNwQ0LoKAct1YMHo_ZU6KokplOWxreAv3LVFC4aJFNrGYs4e8Nkom8ylQgn6CS-iAzSDNnjfnWfTfJQ2ERhBF9HxfJtyypeaBe77QUkMcPynfSVs5XeIJG5UyjYtAMNAR4a4cdwf_eLz4ErjczPblGun9Dku1D0JCafjCq4tenGQ","dp":"CsQu_wsHtW-XL_Y3yHItcWVFwrEMM4eKgmd1-ruoKgMMWV3M4L0T1uSBBnibdMZaGjzMY4hlCct3zRb3bknNmC28ivLhSqVqsHHSkGij8wMbCdBKKMuItxqqnVv3W2KaX6lUj-kNkyGPamRgQfv37UGmQw1on_fktObnfgyC16M","dq":"WKrRjaJnTguGg6E4FZPDBDbroIXmuHksb__x1yBr3QwnBbhKR8xMQ-1JXnMsLFzRba_5fbRBMxi6Nkh1BXulM-golBb4QwBgth3NmO3XZ5vR5FXsHqANiDdYXmtL3xZC4-DNpGseviecuVY9FRow2F7p1Ys0dwF711QUr6Y-bQk","e":"AQAB","kty":"RSA","n":"o5ZjkAIp3syDw_VV1WzN6lHZqONpZJZyYBOcuH9Ps_MdXdalvsIdGnGrLilbo2xFrK-Xhp9ZwR0S7WC-Duu1-y11bZmhVF_cWwWaEMh7gFQHhEyjZ8AH05d5b5r14xC-OrzT1RgQml4nDm2Vih-LI2wYRSIK5vTBtiBrR6Cwm8T5UCvbPf-0EoYjHyYcVqzJ6ry5bjx3-MD9gkA6wOJ53i-uAQ2_dNXKnw38yomJmrqVzj1wStBUJ0KN2iqzxCXWh49soYg9lQbO7ogDX_pezWYpvakypCO32nZwLIa5q5DLh9XdcmQ-j9oYLQi_Lo-C7Dvj8deEEbYfdO0J8r-knQ","p":"xA1_e45i57HM5W0GhSd4QH7WYsmBkgNqw3cr5ss2rROWL8-BkVEzkVhEf0xReNZzaowHtKgxqa7hzx3XQphanpMB-CJxxpOe00uKpogrgeONHi7NXGCPlmXW42AmFHubuWrIiPh-oER3fxiWHJxW3eXujT4TBM15Va9dmtomkD8","q":"1ZuX40dz08Kcp_Q3K9Azawh3xSSeOsuJSihLMvNEhXocGSNYa7d3IzWdHP0zmia__s8FSR3DneygfoApr_r7Nx64VTdWGs6JTVbfurJZQv6fExUfBZKT28JsiYBXbRFLyuKKfqIdOMkbrOpXXBoamVlrW6EWRFZzpHSAKraLFCM","qi":"wyXbLeLLv84lTBb1-1EvJ6R1kSchE0pp0Kp7ZZt7Of68fs95bX0xJg0ytsjbyu-O9UjAJAWdgkr3kT4vei1WIGxVozigKi1RCEjXK28hCArDUx4Ritwe1XUAjMF1Kvd_ei35mApYPuLgHi3Rg4uoHqxvG7tO-erYKMnunHJ6O74"}';
use constant PUBLIC_KEY_JSON => '{"kid":1,"e":"AQAB","kty":"RSA","n":"o5ZjkAIp3syDw_VV1WzN6lHZqONpZJZyYBOcuH9Ps_MdXdalvsIdGnGrLilbo2xFrK-Xhp9ZwR0S7WC-Duu1-y11bZmhVF_cWwWaEMh7gFQHhEyjZ8AH05d5b5r14xC-OrzT1RgQml4nDm2Vih-LI2wYRSIK5vTBtiBrR6Cwm8T5UCvbPf-0EoYjHyYcVqzJ6ry5bjx3-MD9gkA6wOJ53i-uAQ2_dNXKnw38yomJmrqVzj1wStBUJ0KN2iqzxCXWh49soYg9lQbO7ogDX_pezWYpvakypCO32nZwLIa5q5DLh9XdcmQ-j9oYLQi_Lo-C7Dvj8deEEbYfdO0J8r-knQ"}';

my @PURPOSES = qw(domainNameControl
                  personalDataProtection
                  technicalIssueResolution
                  domainNameCertification);

our $VERSION = '0.01';

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;

    if (not defined $self->{"port"}) {
        $self->{"port"} = 8081;
    }

    my $ua = LWP::UserAgent->new();
    $self->{'ua'} = $ua;

    $self->{'brs'} =
        Bytes::Random::Secure->new(Bits        => 64,
                                   NonBlocking => 1);

    my $d = HTTP::Daemon->new(
        LocalPort => $self->{"port"},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $d) {
        die "Unable to start server: $!";
    }
    $self->{"port"} = $d->sockport();
    $self->{"d"} = $d;

    bless $self, $class;
    return $self;
}

sub error
{
    my ($self, $code) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    return $response;
}

sub success
{
    my ($self, $data) = @_;

    my $response = HTTP::Response->new(200);
    if ($data) {
        $response->header('Content-Type' => 'application/json');
        $response->content(encode_json($data));
    }
    return $response;
}

sub get_openid_configuration
{
    my ($self) = @_;

    my $port = $self->{'port'};
    my $base = "http://localhost:$port";
    my %data = (
        issuer                 => "test-iss",
        authorization_endpoint => "$base/authorise",
        token_endpoint         => "$base/token",
        userinfo_endpoint      => "$base/userinfo",
        revocation_endpoint    => "$base/revoke",
        jwks_uri               => "$base/jwks",
    );

    return $self->success(\%data);
}

sub authorise
{
    my ($self, $c, $r) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();
    my %args = $uri->query_form();

    my ($scope, $client_id, $redirect_uri, $id, $response_type, $state) =
        @args{qw(scope client_id redirect_uri id response_type state)};

    my ($code, $access_token, $refresh_token, $session_state) =
        map { $self->{'brs'}->bytes_hex(32) }
            (1..4);

    my $at_hash = access_token_hash('RS256', $access_token);

    my %payload = (
        aud     => $client_id,
        iss     => 'test-iss',
        exp     => time() + 3600,
        azp     => $client_id,
        at_hash => $at_hash,
    );

    my $private_key = decode_json(PRIVATE_KEY_JSON);
    my $id_token =
        encode_jwt(
            payload       => \%payload,
            alg           => 'RS256',
            key           => $private_key,
            extra_headers => { kid => 1 }
        );

    $self->{'data'}->{$code} = {
        access_token  => $access_token,
        refresh_token => $refresh_token,
        id_token      => $id_token,
        token_type    => 'bearer',
        expires_in    => 3600,
    };
    $self->{'refresh_tokens'}->{$refresh_token} = {
        access_token => $access_token
    };
    $self->{'access_tokens'}->{$access_token} = {
        name    => $session_state,
        purpose => $PURPOSES[int(rand(@PURPOSES))],
    };

    my %data = (
        code          => $code,
        authuser      => 0,
        session_state => $session_state,
        prompt        => 'consent'
    );

    my $res = HTTP::Response->new(302);
    $uri = URI->new($redirect_uri);
    my %qf = $uri->query_form();
    $uri->query_form(%qf, %data, state => $state);
    $res->header(Location => $uri->as_string());

    return $res;
}

sub userinfo
{
    my ($self, $c, $r) = @_;

    my $auth = $r->header('Authorization');
    
    my ($access_token) = ($auth =~ /^Bearer\s+(.*)$/);
    if (not $access_token) {
        warn "No token in Authorization header";
        return $self->error(HTTP_FORBIDDEN);
    }
    
    my $data = $self->{'access_tokens'}->{$access_token};
    if (not $data) {
        warn "Unknown access token";
        return $self->error(HTTP_FORBIDDEN);
    }

    return $self->success($data);
}

sub get
{
    my ($self, $c, $r) = @_;

    my $path = $r->uri()->path();

    if ($path eq '/.well-known/openid-configuration') {
        return $self->get_openid_configuration();
    } elsif ($path eq '/authorise') {
        return $self->authorise($c, $r);
    } elsif ($path eq '/jwks') {
        return $self->success({ keys => [ decode_json(PUBLIC_KEY_JSON) ] });
    } elsif ($path eq '/userinfo') {
        return $self->userinfo($c, $r);
    } else {
        return $self->error(HTTP_NOT_FOUND);
    }
}

sub post_token
{
    my ($self, $c, $r) = @_;

    my $content = $r->content();
    my $uri = URI->new("http://www.example.com/asdf.html?$content");
    my %input_data = $uri->query_form();

    my $refresh_token = $input_data{'refresh_token'};
    my $grant_type = ($input_data{'grant_type'} || '');

    if ($refresh_token and ($grant_type eq 'refresh_token')) {
        my $access_token = $self->{'brs'}->bytes_hex(32);
        my $old_access_token =
            $self->{'refresh_tokens'}->{$refresh_token}->{'access_token'};
        if (not $old_access_token) {
            warn "Old refresh token not found";
            return $self->error(HTTP_BAD_REQUEST);
        }
        $self->{'refresh_tokens'}->{$refresh_token} = $access_token;
        $self->{'access_tokens'}->{$access_token} =
            delete $self->{'access_tokens'}->{$old_access_token};

        my %data = (
            access_token  => $access_token,
            refresh_token => $refresh_token,
            token_type    => 'bearer',
            expires_in    => 3600
        );

        return $self->success(\%data);
    }

    my $code = $input_data{'code'};
    my $response_data = $self->{'data'}->{$code};
    if (not $response_data) {
        warn "Code '$code' not found";
        return $self->error(HTTP_BAD_REQUEST);
    }

    return $self->success($response_data);
}

sub post_revoke
{
    my ($self, $c, $r) = @_;

    my $content = $r->content();
    my $uri = URI->new("http://www.example.com/asdf.html?$content");
    my %data = $uri->query_form();
    my $token = $data{'token'};
    if ($self->{'access_tokens'}->{$token}) {
        delete $self->{'access_tokens'}->{$token};
    } elsif ($self->{'refresh_tokens'}->{$token}) {
        delete $self->{'refresh_tokens'}->{$token};
    } else {
        warn "Revocation failed";
        return $self->error(HTTP_BAD_REQUEST);
    }
    return $self->success();
}

sub post
{
    my ($self, $c, $r) = @_;

    my $uri  = $r->uri();
    my $path = $uri->path();
    my %args = $uri->query_form();

    if ($path eq '/token') {
        return $self->post_token($c, $r);
    } elsif ($path eq '/revoke') {
        return $self->post_revoke($c, $r);
    } else {
        return $self->error(HTTP_NOT_FOUND);
    }
}

sub run
{
    my ($self) = @_;

    my $d = $self->{"d"};
    while (my $c = $d->accept()) {
        while (my $r = $c->get_request()) {
            my $method = $r->method();
            my $path = $r->uri()->path();
            print STDERR "$method $path\n";

            my @args = ($c, $r);
            my $res = eval {
	        ($method eq 'GET')  ? $self->get(@args)
	      : ($method eq 'POST') ? $self->post(@args)
                                    : $self->error(HTTP_NOT_FOUND);
            };
            if (my $error = $@) {
                print STDERR "Unable to process request: $error\n";
                $c->send_error(500);
            } else {
                warn "sending response";
                my $res_str = $res->as_string();
                $res_str =~ s/\n/\\n/g;
                $res_str =~ s/\r/\\r/g;
                print STDERR "$res_str\n";
                $c->send_response($res);
            }
        }
        $c->close();
        undef $c;
    }
}

1;
