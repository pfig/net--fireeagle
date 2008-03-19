package Net::FireEagle;

# Client library for FireEagle
use strict;
use base qw/Class::Data::Inheritable Class::Accessor/;
use LWP;
use CGI;
require Net::OAuth::Request;
require Net::OAuth::RequestTokenRequest;
require Net::OAuth::AccessTokenRequest;
require Net::OAuth::ProtectedResourceRequest;

BEGIN {
    eval {  require Math::Random::MT };
    unless ($@) {
        Math::Random::MT->import(qw(srand rand));
    }
}

our $VERSION = '0.5';
our $DEBUG   = 0;

# FireEagle Endpoint URLs
our $REQUEST_TOKEN_URL = 'https://fireeagle.yahooapis.com/oauth/request_token';
our $AUTHORIZATION_URL = 'https://fireeagle.yahoo.net/oauth/authorize';
our $ACCESS_TOKEN_URL  = 'https://fireeagle.yahooapis.com/oauth/access_token';
our $QUERY_API_URL     = 'https://fireeagle.yahooapis.com/api/0.1/user';
our $UPDATE_API_URL    = 'https://fireeagle.yahooapis.com/api/0.1/update';

our $SIGNATURE_METHOD  = 'HMAC-SHA1';
our $UNAUTHORIZED      = "Unauthorized.";

__PACKAGE__->mk_classdata(
    required_constructor_params => [qw(consumer_key consumer_secret)]
);
__PACKAGE__->mk_classdata(
    access_token_params => [qw(access_token access_token_secret)]
);

__PACKAGE__->mk_accessors(
    @{ __PACKAGE__->required_constructor_params },
    @{ __PACKAGE__->access_token_params },
);

=head1 NAME

Net::FireEagle - access Yahoo's new FireEagle developer service

=head2 SYNOPSIS


    # Set up Fire Eagle oauth
    my $fe = Net::FireEagle::Client->new( consumer_key    => $consumer_key, 
                                          consumer_secret => $consumer_secret );

    # Resume previous Fire Eagle oauth, feed access token and secret
    my $fe2 = Net::FireEagle::Client->new( consumer_key        => $consumer_key, 
                                           consumer_secret     => $consumer_secret, 
                                           access_token        => $access_token, 
                                           access_token_secret => $access_token_secret );

    # Send this to user to grant authorization for this app
    my $auth_url = $fe->authorization_url;

    # Save these in DB to restore previous Fire Eagle oauth session
    my $access_token = $fe->access_token;
    my $access_token_secret = $fe->access_token_secret;

    # Can't query or update location without authorization
    my $loc = $fe->location_query;

    my $return = $fe->location_update( "500 Third St., San Francisco, CA" );

=head1 ABOUT

Fire Eagle is a site that stores information about your location. With 
your permission, other services and devices can either update that 
information or access it. By helping applications respond to your 
location, Fire Eagle is designed to make the world around you more 
interesting! Use your location to power friend-finders, games, local 
information services, blog badges and stuff like that...

For more information see http://fireeagle.yahoo.net/

=head1 AUTHENTICATION

For more information read this

http://fireeagle.yahoo.net/developer/documentation/getting_started

but, in short you have to first get an API key from the FireEagle site. 
Then using this consumer key and consumer secret you have to 
authenticate the relationship between you and your user. See the script 
C<fireagle-authorise> for an example of how to do this.


=head1 METHODS

=cut

=head2 new <opts>

Create a new FireEagle object. This must have the options

=over 4

=item consumer_key 

=item consumer_secret

=back

which you can get at http://fireeagle.yahoo.net/developer/manage

then, when you have your per-user authentication tokens (see above) you 
can supply

=over 4

=item access_token

=item access_token_secret

=back

=cut

sub new {
    my $proto  = shift;
    my $class  = ref $proto || $proto;
    my %params = @_;
    my $client = bless \%params, $class;

    # Verify arguments
    $client->_check;

    # Set up LibWWWPerl for HTTP requests
    $client->{browser} = LWP::UserAgent->new;

    if ( $client->has_access_token ) {

        # Mark as authorized
        $client->{authorized} = 1;
    } else {

        # Set up request_token
        $client->{authorized} = 0;
        $client->request_request_token;
        $client->{authorization_url} = $client->get_authorization_url;
    }

    # Client Object
    return $client;
}



# Validate required constructor params
sub _check {
    my $self = shift;
    foreach my $param ( @{ $self->required_constructor_params } ) {
        if ( not defined $self->{$param} ) {
            die "Missing required parameter '$param'";
        }
    }
}

=head2 has_access_token 

=cut

sub has_access_token {
    my $self = shift;
    foreach my $param ( @{ $self->access_token_params } ) {
        if ( not defined $self->{$param} ) { return 0; }
    }
    return 1;
}

# generate a random number 
sub _nonce {
    return int( rand( 2**32 ) );
}

sub _request_access_token {
    my $self = shift;
    print "REQUESTING ACCESS TOKEN\n" if $DEBUG;
    my $access_token_request = Net::OAuth::AccessTokenRequest->new(
        consumer_key     => $self->{consumer_key},
        consumer_secret  => $self->{consumer_secret},
        request_url      => $ACCESS_TOKEN_URL,
        request_method   => 'GET',
        signature_method => $SIGNATURE_METHOD,
        timestamp        => time,
        nonce            => $self->_nonce,
        token            => $self->{request_token},
        token_secret     => $self->{request_token_secret},
    );
    $access_token_request->sign;

    die "COULDN'T VERIFY! Check OAuth parameters.\n"
      unless $access_token_request->verify;

    # Construct request URL and send request via browser GET
    my $access_token_request_url =
      $ACCESS_TOKEN_URL . '?' . $access_token_request->to_post_body;
    my $access_token_response =
      $self->{browser}->get($access_token_request_url);

    die $access_token_response->status_line
      unless ( $access_token_response->is_success );

    # Cast response into CGI query for EZ parameter decoding
    my $access_token_response_query =
      new CGI( $access_token_response->content );

    # Split out token and secret parameters from the access token response
    $self->{access_token} = $access_token_response_query->param('oauth_token');
    $self->{access_token_secret} =
      $access_token_response_query->param('oauth_token_secret');

    die "ERROR: FireEagle did not reply with an access token"
      unless ( $self->{access_token} && $self->{access_token_secret} );
}

=head2 request_request_token 

=cut

sub request_request_token {
    my $self                  = shift;
    my $request_token_request = Net::OAuth::RequestTokenRequest->new(
        consumer_key     => $self->{consumer_key},
        consumer_secret  => $self->{consumer_secret},
        request_url      => $REQUEST_TOKEN_URL,
        request_method   => 'GET',
        signature_method => $SIGNATURE_METHOD,
        timestamp        => time,
        nonce            => $self->_nonce,
    );
    $request_token_request->sign;

    die "COULDN'T VERIFY! Check OAuth parameters.\n"
      unless $request_token_request->verify;

    # Construct request URL and send request via browser GET
    # TODO - construct this using URI or something?
    my $request_token_request_url =
      $REQUEST_TOKEN_URL . '?' . $request_token_request->to_post_body;
    my $request_token_response =
      $self->{browser}->get($request_token_request_url);

    die $request_token_response->status_line
      unless ( $request_token_response->is_success );

    # Cast response into CGI query for EZ parameter decoding
    my $request_token_response_query =
      new CGI( $request_token_response->content );

    # Split out token and secret parameters from the request token response
    $self->{request_token} =
      $request_token_response_query->param('oauth_token');
    $self->{request_token_secret} =
      $request_token_response_query->param('oauth_token_secret');

}

=head2 get_authorization_url

=cut

sub get_authorization_url {
    my $self = shift;
    return undef unless $self->{request_token};
    return $AUTHORIZATION_URL . '?oauth_token=' . $self->{request_token};
}

=head2 clicked_authorization_url

=cut

sub clicked_authorization_url {
    my $self = shift;
    return if $self->{authorized};
    $self->_request_access_token;
    $self->{authorized} = 1;
}

=head2 location_query

=cut

sub location_query {
    my $self = shift;
    return $UNAUTHORIZED unless $self->{authorized};
    my $user_location_request = Net::OAuth::ProtectedResourceRequest->new(
        consumer_key     => $self->{consumer_key},
        consumer_secret  => $self->{consumer_secret},
        request_url      => $QUERY_API_URL,
        request_method   => 'GET',
        signature_method => $SIGNATURE_METHOD,
        timestamp        => time,
        nonce            => $self->_nonce,
        token            => $self->{access_token},
        token_secret     => $self->{access_token_secret},
    );
    $user_location_request->sign;

    die "COULDN'T VERIFY! Check OAuth parameters.\n"
      unless $user_location_request->verify;

    my $user_location_request_url =
      $QUERY_API_URL . '?' . $user_location_request->to_post_body;
    my $user_location_response =
      $self->{browser}->get($user_location_request_url);

    die $user_location_response->status_line
      unless ( $user_location_response->is_success );

    return $user_location_response->content;
}

=head2 location_update <location>

=cut

sub location_update {
    my ( $self, $location ) = @_;
    return $UNAUTHORIZED unless $self->{authorized};

    my $update_location_request = Net::OAuth::ProtectedResourceRequest->new(
        consumer_key     => $self->{consumer_key},
        consumer_secret  => $self->{consumer_secret},
        request_url      => $UPDATE_API_URL,
        request_method   => 'POST',
        signature_method => $SIGNATURE_METHOD,
        timestamp        => time,
        nonce            => $self->_nonce,
        token            => $self->{access_token},
        token_secret     => $self->{access_token_secret},
        extra_params     => { address => $location, }
    );
    $update_location_request->sign;

    die "COULDN'T VERIFY! Check OAuth parameters.\n"
      unless $update_location_request->verify;

    my $update_location_request_url = $UPDATE_API_URL;
    my $update_location_response =
      $self->{browser}
      ->post( $update_location_request_url, $update_location_request->to_hash );

    die $update_location_response->status_line
      unless ( $update_location_response->is_success );

    return $update_location_response->content;
}

=head1 RANDOMNESS

If C<Math::Random::MT> is installed then any nonces
generated will use a Mersenne Twiser instead of Perl's
built in randomness function.

=head1 BUGS

Non known

=head1 DEVELOPERS

The latest code for this module can be found at

http://svn.unixbeard.net/simon/Net-FireEagle

=head1 AUTHOR

Simon Wistow <swistow@sixapart.com>

Based on work by Marc Powell at Yahoo! Brickhouse and Aaron Straup Cope

=head1 COPYRIGHT

Copyright 2008 - Simon Wistow and Yahoo! Brickhouse

Distributed under the same terms as Perl itself.

See L<perlartistic> and L<perlgpl>.

=cut

1;
