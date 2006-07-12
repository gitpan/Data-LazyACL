package Data::LazyACL;

use strict;
use Math::BigInt;
use Carp;
use Readonly;
use vars qw/$VERSION/;

$VERSION = '0.01';

Readonly my $ADMIN_NUMBER => -1;

sub new {
    my $class = shift;
    my $s     = {};

    bless $s , $class;
}

sub set_all_access_keys {
    my $s           = shift;
    my $access_keys = shift;

    my $digit = 1;
    for  my $access_key ( @{ $access_keys }  ) {
    
        if( $access_key eq 'admin' ) {
            croak q{You can not use reserved word 'admin' as access key.};
        }
        
        $s->{access_key}{ $access_key } = $digit;   
        $digit++;
    }
    $s->{access_key}{admin} = $ADMIN_NUMBER;
}

sub has_privilege {
    my $s           = shift;
    my $access_key  = shift;

    return 0 unless defined $s->{token};
    # admin
    return 1 if $s->{token} eq $ADMIN_NUMBER ;

    my $access_digit =  $s->{access_key}{ $access_key } ;
    
    croak 'can not find access key [' . $access_key . ']' unless $access_digit;
    my $acl = Math::BigInt->new( 2 );
    $acl->bpow( $access_digit - 1 );
    return $acl->band( $s->{token} ) ? 1 : 0;
}

sub set_token {
    my $s       = shift;
    my $token   = shift;
    $s->{token} = $token ;
}

sub generate_token {
    my $s           = shift;
    my $access_keys = shift;
    
    my $acl = Math::BigInt->new();

    for my $access_key ( @{ $access_keys } ) {
        return $ADMIN_NUMBER if $access_key eq 'admin';

        my $digit   = $s->{access_key}{ $access_key } ;
        
        croak 'can not find access key [' . $access_key . ']' unless $digit;

        my $i       = Math::BigInt->new( 2 );

        $acl->badd( $i->bpow( $digit -1 ) );
    }
    return $acl->numify();

}


1;

=head1 NAME

Data::LazyACL - Simple and Easy Access Control List

=head1 DESCRIPTION

I am tired of having multiple flags or columns or whatever to implement Access
Control List , so I create this module.

This module is simple and easy to use,  a user only need to have a token
to check having access or not.

=head1 SYNOPSYS

 my $acl = Data::LazyACL->new();
 $acl->set_all_access_keys( [qw/edit insert view/]);

 # maybe you want to store this token into user record.
 my $token = $acl->generate_token([qw/view insert/]);

 $acl->set_token( $token );

 if ( $acl->has_privilege( 'view' ) ) {
    print "You can view me!!\n";
 }

 if ( $acl->has_privilege( 'edit' ) ) {
    print "Never Dispaly\n";
 }

=head1 METHODS

=head2 new()

Constractor.

=head2 set_all_access_keys( \@access_keys )

Set all access keys. You can never change this array of order once you
generate token , otherwise you will messup permissins. When you want to add new keys then just append.  

=head2 $token = generate_token( \@user_access_keys )

Generate token. You may want to save this token for per user.

=head2 set_token( $token )

You need to set $token to use has_privilege() method. the has_privilege()
method check privilege based on this token.

If you want to have all access then use reserve keyword 'admin' .

 my $admin_token = $acl->set_token( 'admin' );

=head2 has_privilege( $access_key )

check having privilege or not for the access_key.

=head2 Token can be big number

Token can be big number when you add a lot of access keys, so I suggest
you treat Token as String not Integer when you want to store it into database.

=head1 AUTHOR

Tomohiro Teranishi <tomohiro.teranishi+cpan@gmail.com>

=head1 COPYRIGHT

This program is free software. you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
