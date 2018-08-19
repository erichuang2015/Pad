// Begin
ready( function() {
	var
	t	= byId( 'tagline' ),
	c	= byId( 'copyright' ),
	x	= byId( 'csp' );
	
	// Auto-size
	t.style.resize	= 'none';
	c.style.resize	= 'none';
	x.style.resize	= 'none';
	listen( t, 'input, drop, paste', function( e ) {
		resize( this );
	}, false );
	
	listen( c, 'input, drop, paste', function( e ) {
		resize( this );
	}, false );
	
	listen( x, 'input, drop, paste', function( e ) {
		resize( this );
	}, false );
} );
