package APNIC::RDAP::OpenID::Proxy;

use warnings;
use strict;

use APNIC::RDAP::OpenID::Utils qw(access_token_hash);

use Crypt::JWT qw(decode_jwt);
use Data::Dumper;
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(encode_json decode_json);
use OIDC::Lite::Client::WebServer;
use OIDC::Lite::Model::IDToken;

use constant BAD_REQUEST => HTTP::Response->new(HTTP_BAD_REQUEST);

our $VERSION = '0.01';

sub load_keys
{
    my ($ua, $idp_data) = @_;

    my $jwks_uri = $idp_data->{'discovery'}->{'jwks_uri'};
    if ($jwks_uri) {
        my $res = $ua->get($jwks_uri);
        if (not $res->is_success()) {
            die "Unable to fetch key URI: ".Dumper($res);
        }
        my $jwk_data = decode_json($res->decoded_content());
        $idp_data->{'keys'} =
            { map { $_->{'kid'} => $_ }
                  @{$jwk_data->{'keys'} || []} };
    }

    return $idp_data;
}

sub load_idp
{
    my ($ua, $idp_details) = @_;

    my ($id, $secret, $discovery_uri) =
        @{$idp_details}{qw(id secret discovery_uri)};

    my $res = $ua->get($discovery_uri);
    if (not $res->is_success()) {
        die "Unable to fetch discovery URI: ".Dumper($res);
    }
    my $data = decode_json($res->decoded_content());

    my $client =
        OIDC::Lite::Client::WebServer->new(
            authorize_uri    => $data->{'authorization_endpoint'},
            access_token_uri => $data->{'token_endpoint'},
            secret           => $idp_details->{'secret'},
            id               => $idp_details->{'id'}
        );

    my %idp_data = (
        discovery => $data,
        client    => $client,
    );

    load_keys($ua, \%idp_data);

    return \%idp_data;
}

sub load_idps
{
    my ($ua, $idp_details) = @_;

    my %idp_data =
        map { $_ => load_idp($ua, $idp_details->{$_}) }
            keys %{$idp_details};

    return \%idp_data;
}

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;

    if (not defined $self->{"port"}) {
        $self->{"port"} = 8080;
    }

    if ($self->{'no_tls_checks'}) {
        $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
    }

    my $ua = LWP::UserAgent->new();
    $self->{'ua'} = $ua;

    my %idp_details = %{$self->{'idp_details'}};
    my %idp_data = %{load_idps($ua, \%idp_details)};
    $self->{'idp'} = \%idp_data;

    $self->{'idp_iss_to_name'} =
        { map { $idp_data{$_}->{'discovery'}->{'issuer'} => $_ }
            keys %idp_data };

    my $d = HTTP::Daemon->new(
        LocalPort => $self->{"port"},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $d) {
        die "Unable to start server: $!";
    }
    my $port = $d->sockport();
    $self->{"port"} = $port;
    $self->{"d"} = $d;

    $self->{'redirect_uri'}
        =~ s/^http:\/\/localhost:0\//http:\/\/localhost:$port\//;

    bless $self, $class;
    return $self;
}

sub id_to_idp_name
{
    my ($self, $id) = @_;

    my $idp_client;
    for my $idp_mapping (@{$self->{'idp_mappings'}}) {
        my $re = $idp_mapping->[0];
        if ($id =~ /$re/) {
            return $idp_mapping->[1];
        }
    }

    return;
}

sub id_to_idp_client
{
    my ($self, $id) = @_;

    my $idp_name = $self->id_to_idp_name($id);
    return $self->{'idp'}->{$idp_name}->{'client'};
}

sub response
{
    my ($self, $code, $notices, $extra) = @_;

    my $response = HTTP::Response->new();
    $response->code($code);
    $response->header("Content-Type" => "application/rdap+json");

    my @notices = (
        @{$notices || []},
        @{$self->{'notices'} || []}
    );

    $response->content(
        encode_json({
            %{$extra || {}},
            (@notices ? (notices => @notices)  : ()),
        })
    );

    return $response;
}

sub error
{
    my ($self, $code, $notices) = @_;

    return $self->response($code, $notices, { errorCode => $code });
}

sub success
{
    my ($self, $notices, $extra) = @_;

    return $self->response(HTTP_OK, $notices, $extra);
}

sub post_token_revoke
{
    my ($self, $c, $r) = @_;

    my %args = $r->uri()->query_form();
    my ($id, $token) = @args{qw(id token)};

    my $idp_name = $self->id_to_idp_name($id);
    my $discovery = $self->{'idp'}->{$idp_name}->{'discovery'};
    my $idp_revocation_uri = $discovery->{'revocation_endpoint'};
    if (not $idp_revocation_uri) {
        print STDERR "IDP '$idp_name' does not support revocation\n";
        return $self->error(
            HTTP_BAD_REQUEST,
            [ { title       => "Token Revocation Result",
                description => "Token Revocation Not Supported" } ]
        );
    }

    my $req = HTTP::Request->new();
    $req->uri($idp_revocation_uri);
    $req->method('POST');
    $req->content('token='.$token);
    $req->header('Content-Type' => 'application/x-www-form-urlencoded');

    my $ua = $self->{'ua'};
    my $res = $ua->request($req);
    if ($res->code() != HTTP_OK) {
        return $self->error(
            HTTP_BAD_REQUEST,
            [ { title       => "Token Revocation Result",
                description => "Token Revocation Failed" } ]
        );
    }

    return $self->success(
        [ { title       => "Token Revocation Result",
            description => "Token Revocation Succeeded" } ]
    );
}

sub post
{
    my ($self, $c, $r) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();

    if ($path eq '/tokens/revoke') {
	return $self->post_token_revoke($c, $r);
    } else {
        return $self->error(HTTP_NOT_FOUND);
    }
}

sub get_query
{
    my ($self, $path, $args) = @_;

    my $base_rdap_url = $self->{'base_rdap_url'};
    my $ua = $self->{'ua'};
    my $new_uri = URI->new($base_rdap_url.$path);
    $new_uri->query_form(%{$args});
    my $res = $ua->get($new_uri->as_string());
    return $res;
}

sub get_query_unauthenticated
{
    my ($self, $path, $args) = @_;

    my $filters = $self->{'filters'}->{'unauthenticated'};
    if ($filters->{'deny'}) {
        return $self->error(HTTP_FORBIDDEN);
    }

    my $res = $self->get_query($path, $args);
    my %data = %{decode_json($res->content())};

    if ($filters->{'no_entities'}) {
        delete $data{'entities'};
    }

    $res->content(encode_json(\%data));
    return $res;
}

sub get_query_authenticated
{
    my ($self, $path, $args, $id_token, $access_token) = @_;

    my $filters = $self->{'filters'}->{'authenticated'};
    if ($filters->{'pass_purpose'}) {
        my $id_token_obj = OIDC::Lite::Model::IDToken->load($id_token); 
        my $iss = $id_token_obj->payload()->{'iss'};
        my $idp_name = $self->{'idp_iss_to_name'}->{$iss};
        
        my $discovery = $self->{'idp'}->{$idp_name}->{'discovery'};
        my $userinfo_uri = $discovery->{'userinfo_endpoint'};
        my $req = HTTP::Request->new();
        $req->header('Authorization', 'Bearer '.$access_token);
        $req->uri($userinfo_uri);
        $req->method('GET');
        my $ua = $self->{'ua'};
        my $res = $ua->request($req);
        if ($res->code() != HTTP_OK) {
            warn "Unable to fetch userinfo";
            return $self->error($res->code());
        }
        my $data = decode_json($res->decoded_content());
        if ($data->{'purpose'}) {
            warn "Purpose: ".$data->{'purpose'};
            $args->{'purpose'} = $data->{'purpose'};
        }
    }

    if ($filters->{'pass_authenticated'}) {
        $args->{'authenticated'} = 1;
    }

    return $self->get_query($path, $args);
}

sub validate_id_token
{
    my ($self, $id_token, $access_token) = @_;

    my $id_token_obj = OIDC::Lite::Model::IDToken->load($id_token);
    my ($aud, $iss, $exp, $at_hash, $azp, $sub, $iat) =
        @{$id_token_obj->payload}{qw(aud iss exp at_hash azp sub iat)};

    my $time = time();
    if ($time >= $exp) {
        warn "Authentication has expired";
        return;
    }
    my $name = $self->{'idp_iss_to_name'}->{$iss};
    if (not $name) {
        warn "Unknown iss";
        return;
    }
    my $client_id = $self->{'idp_details'}->{$name}->{'id'};
    if ($aud ne $client_id) {
        warn "aud is incorrect (should be '$client_id', is '$aud')";
        return;
    }
    if ($azp and $azp ne $client_id) {
        warn "azp is incorrect (should be '$client_id', is '$azp')";
        return;
    }

    my $alg = $id_token_obj->header()->{'alg'};
    if ($alg) {
        my $kid = $id_token_obj->header()->{'kid'};
        my $idp = $self->{'idp'}->{$name};
        my $key = $idp->{'keys'}->{$kid};
        if (not $key) {
            load_keys($self->ua(), $idp);
            $key = $idp->{'keys'}->{$kid};
            if (not $key) {
                warn "Unable to find key";
                return;
            }
        }
        my $dec = eval { decode_jwt(token => $id_token, key => $key); };
        if (my $error = $@) {
            warn "Unable to verify signature";
            return;
        }
    }

    if ($access_token and $at_hash) {
        my $hash = access_token_hash($alg, $access_token);
        if (not $hash) {
            die "Unable to verify at_hash (internal error)";
        }
        if ($hash ne $at_hash) {
            warn "Unable to verify at_hash";
            return;
        }
    }

    return 1;
}

sub get_query_using_token
{
    my ($self, $c, $r) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();
    my %args = $uri->query_form();

    my ($access_token, $id_token) =
        delete @args{qw(access_token id_token)};
    if (not $access_token) {
        my $header_value = $r->header('Authorization');
        ($access_token) = ($header_value =~ /^Bearer\s+(.*)$/i);
    }
    if (not $access_token) {
        warn "No access token found";
        return $self->error(HTTP_FORBIDDEN);
    }

    # Do not pass the access token here, since it might have been
    # refreshed since the ID token was issued.
    my $res = $self->validate_id_token($id_token);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST);
    }

    return $self->get_query_authenticated($path, \%args,
                                          $id_token, $access_token);
}

sub retrieve_tokens
{
    my ($self, $c, $r, $code) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();
    my $port = $self->{'port'};
    my %args = $uri->query_form();

    my $data = decode_json($args{'state'});
    my $id = $data->[0];
    my $prev_args = $data->[2];

    my $idp_client = $self->id_to_idp_client($id);
    if (not $idp_client) {
        warn "No IDP client";
        return;
    }

    my $tokens = $idp_client->get_access_token(
        code         => $code,
        redirect_uri => $self->{'redirect_uri'},
    );
    if (not $tokens) {
        warn $idp_client->errstr();
        return;
    }

    my $requires_refresh =
        ($prev_args->{'refresh'} || '') eq 'true';
    if ($requires_refresh and not $tokens->refresh_token()) {
        warn "No refresh token";
        return;
    }

    return $tokens;
}

sub get_query_using_code
{
    my ($self, $c, $r) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();
    my %args = $uri->query_form();

    my ($code, $state) = delete @args{qw(code state)};    

    my $tokens = $self->retrieve_tokens($c, $r, $code);
    if (not $tokens) {
        return $self->error(HTTP_BAD_REQUEST);
    }

    my $access_token = $tokens->access_token();
    my $id_token = $tokens->id_token();

    my $res = $self->validate_id_token($id_token, $access_token);
    if (not $res) {
        return $self->error(HTTP_BAD_REQUEST);
    }

    my $data = decode_json($state);
    my $prev_path = $data->[1];

    if ($prev_path eq '/tokens') {
        my %data = (
            "access_token" => $access_token,
            "id_token"     => $id_token,
            "token_type"   => "bearer",
            "expires_in"   => $tokens->expires_in(),
            ($tokens->refresh_token())
                ? ("refresh_token" => $tokens->refresh_token())
                : (),
        );
        return $self->success([], \%data);
    } else {
        return $self->get_query_authenticated($prev_path, \%args,
                                              $id_token, $access_token);
    }
}

sub refresh_token
{
    my ($self, $c, $r) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();
    my %args = $uri->query_form();
    my $port = $self->{'port'};

    my $id = $args{'id'};
    my $name = $self->id_to_idp_name($id);
    my $idp_client = $self->id_to_idp_client($id);
    if (not $idp_client) {
        warn "Could not find an IDP client";
        return $self->error(HTTP_BAD_REQUEST);
    }
    my $access_token = $idp_client->refresh_access_token(
        refresh_token => $args{'refresh_token'}
    );
    if (not $access_token) {
        warn $idp_client->errstr();
        return $self->error(HTTP_BAD_REQUEST);
    }

    my %data = (
        "access_token"  => $access_token->access_token(),
        "token_type"    => "bearer",
        "expires_in"    => $access_token->expires_in(),
        "refresh_token" => ($access_token->refresh_token()
                            || $args{'refresh_token'})
    );

    return $self->success([], \%data);
}

sub authenticate_user
{
    my ($self, $c, $r) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();
    my %args = $uri->query_form();
    my $port = $self->{'port'};

    my $id = $args{'id'};
    my $idp_client = $self->id_to_idp_client($id);
    if (not $idp_client) {
        warn "Could not find an IDP client";
        return $self->error(HTTP_BAD_REQUEST);
    }

    my $refresh_required =
        ($path eq 'tokens' and (($args{'refresh'} || '') eq 'true'));

    my $auth_uri = URI->new($self->{'redirect_uri'});
    my %extra = (
        login_hint => $id,
        # These are Google-specific parameters.
        ($refresh_required)
            ? (approval_prompt => 'force',
               access_type     => 'offline')
            : (),
    );
    my $redirect_uri =
        $idp_client->uri_to_redirect(
            redirect_uri => $auth_uri->as_string(),
            scope        => 'openid',
            state        => encode_json([$id, $path, \%args]),
            extra        => \%extra,
        );

    my $res = HTTP::Response->new(HTTP_FOUND);
    $res->header(Location => $redirect_uri);
    return $res;
}


sub get
{
    my ($self, $c, $r) = @_;

    my $uri = $r->uri();
    my $path = $uri->path();
    my %args = $uri->query_form();

    if ($args{'id_token'}) {
        return $self->get_query_using_token($c, $r);
    } elsif ($args{'code'}) {
        return $self->get_query_using_code($c, $r);
    } elsif ($args{'id'} and $args{'refresh_token'} and $path eq '/tokens') {
        return $self->refresh_token($c, $r);
    } elsif ($args{'id'}) {
        return $self->authenticate_user($c, $r);
    } else {
        return $self->get_query_unauthenticated($path, \%args);
    }
}

sub run
{
    my ($self) = @_;

    my $d = $self->{"d"};
    while (my $c = $d->accept()) {
        print STDERR "Accepted connection $c\n";
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
                $c->send_response($self->error(HTTP_INTERNAL_SERVER_ERROR));
            } else {
                my $res_str = $res->as_string();
                $res_str =~ s/\n/\\n/g;
                $res_str =~ s/\r/\\r/g;
                print STDERR "$res_str\n";
                $c->send_response($res);
                print STDERR "Sent response\n";
            }
            last;
        }
        $c->close();
        undef $c;
        print STDERR "Finished with connection $c\n";
    }
}

1;
