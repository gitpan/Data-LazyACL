use Test::More qw/no_plan/;
use Test::Exception;
use strict;

use_ok( 'Data::LazyACL' );

basic();
a_lot();

sub basic {
    my $acl = Data::LazyACL->new();
    $acl->set_all_access_keys( [qw/edit insert view/] );
     
    my $token = $acl->generate_token([qw/edit insert/]);
    
    $acl->set_token( $token );
    
    ok(  $acl->has_privilege( 'edit'    ) ); 
    ok(  $acl->has_privilege( 'insert'  ) );
    ok( !$acl->has_privilege( 'view'    ) );
    ok(  $acl->has_privilege( 'admin'   ) );
    throws_ok( sub { $acl->has_privilege( 'boo' )  } , qr{can not find access key \[boo\]});
    
    my $admin_token =  $acl->generate_token([qw/edit admin/]);
    
    $acl->set_token( $admin_token );
    
    ok(  $acl->has_privilege( 'view' ) );
    
    throws_ok( sub { $acl->set_all_access_keys([qw/admin/]) } , qr{You can not use reserved word 'admin' as access key.} );
}


sub a_lot {
    my $acl = Data::LazyACL->new();

    my @master = map { 'access_' . $_ } (0...10000);
    
    $acl->set_all_access_keys( \@master );

    my $token = $acl->generate_token( [qw/access_0 access_1/] );
    
    $acl->set_token( $token );
    ok(  $acl->has_privilege( 'access_0' ) );
    ok(  $acl->has_privilege( 'access_1' ) );
    ok(  !$acl->has_privilege( 'access_8941' ) );
    
}
