// Begin
ready( function() {
	
	// Add components
	toolAdd();
	
	var
	t	= byId( 'body' );
	
	// Record last cursor position on blur
	listen( t, 'blur', function( e ) {
		updateLastPos( this );
	}, false );
	
	// Auto-size
	t.style.resize	= 'none';
	listen( t, 'input, drop, paste', function( e ) {
		resize( this );
	}, false );
	
	// Annotations
	listen( t, 'keydown', function( e ) {
		format( this, e );
	}, false );
} );
