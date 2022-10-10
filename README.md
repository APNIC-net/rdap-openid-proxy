# rdap-openid-proxy

An OpenID Connect authentication proxy for an RDAP server, based on
[draft-ietf-regext-rdap-openid](https://tools.ietf.org/html/draft-ietf-regext-rdap-openid-17).
This is a proof-of-concept only, and is not intended for production
use.

## Dependencies

Perl dependencies are listed in `Makefile.PL`.

## Installation

    perl Makefile.PL
    make
    make test
    sudo make install

## Configuration

Configuration is in YAML format, like so:

    port: {port}
    base_rdap_url: {base-rdap-url}
    dnt_supported: {boolean}
    issuer_identifier_supported: {boolean}
    implicit_token_refresh_supported: {boolean}
    idp_details:
      {name}:
        id: {idp-client-id}
        name: {idp-name}
        secret: {idp-client-secret}
        discovery_uri: {idp-discovery-uri}
      ...
    redirect_uri: {redirect-uri}
    idp_mappings:
      - [ {regex}, {name} ]
      - ...
    filters:
      unauthenticated:
        {filter_name}: {enabled}
      authenticated:
        {filter_name}: {enabled}

`port` is the port on which the server will run.

`base_rdap_url` is the base URL of the RDAP server for which this
server is operating as a proxy.

`dnt_supported` indicates whether 'do not track'-style functionality
is supported (defaults to false).

`issuer_identifier_supported` indicates whether the client can
specify an ISS value manually in a 'login' request (defaults to
true).

`implicit_token_refresh_supported` indicates whether the server will
attempt to refresh the access token if it has expired (defaults to
true).

`idp_details` maps from a server-specific name for an
identity provider to the configuration details for that provider.
`idp-name` is a descriptive string that is returned in the RDAP
`/help` response.

`idp_mappings` is a list of lists, where each element list contains a
Perl regular expression and an identity provider name.  This is used
to map from the user-provided `id` argument to an identity provider:
the provider for the first expression that matches the `id` argument
will be used for the relevant request.  [Provider issuer
discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery)
is not currently implemented.

`filters` affect how requests to or responses from the proxied RDAP
server are handled.  For unauthenticated requests, two filters
are defined:

   * `no_entities`, which strips top-level entities from the response; and
   * `deny`, which returns `403 Forbidden` for all requests.

For authenticated requests, two filters are defined:

   * `pass_authenticated`, which passes an `authenticated=1` query
     argument to the backend; and
   * `pass_purpose`, which passes the purposes from the user's claims
     to the backend.

## Example usage

Using a configuration file like so, with Google as the provider:

    port: 38279
    base_rdap_url: http://rdap.apnic.net
    idp_details:
      google:
        id: {client-id}.apps.googleusercontent.com
        secret: {client-secret}
        discovery_uri: https://accounts.google.com/.well-known/openid-configuration
    idp_mappings:
      - [ "@gmail.com", "google" ]
    filters:
      unauthenticated:
        no_entities: 1

A standard request can be sent like so:

    $ curl http://localhost:38279/domain/203.in-addr.arpa
    {"ldhName":"203.in-addr.arpa", ...

To log in via an OIDC provider, the client sends a request to the
'login' endpoint.  (In this instance, because there is only one IDP,
there is no need to provide the identifier in the request.  However,
depending on the configuration, an identifier and/or an issuer
identifier may need to be provided.)

After logging in successfully, subsequent RDAP requests will be
considered authenticated.

## Notes

   * This has been tested with Google's identity provider and with
     Keycloak.  Other providers may not work as expected.

## License

See [LICENSE.txt](LICENSE.txt).
