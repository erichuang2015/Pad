'use strict';

// Markers
var
lastStart	= 0,		// Last cursor start
lastEnd		= 0,		// Last cursor end
showtool	= false;	// Toolbar on/off

// Formatting templates
var
toolbarTpl	=				// Formatting toolbar
"<strong>(B)old</strong>, <em>(I)talic</em>, (L)ink, (H)eading, <del>(S)trike</del>",

videoTpl	= "\n!![{desc}]({name})\n",	// Video (server-side)
imageTpl	= "\n![{desc}]({name})\n",	// Embedded image
linkTpl		= "[{desc}]({name})",		// Link URL
headerTpl	= "\n\n{num} {txt}  \n",	// Heading
underTpl	= "\n{desc}\n{under}\n";	// Underline

// Get element by id
function byId( n ) {
	return document.getElementById( n );
}

// Create a new element
function create( n ) {
	return document.createElement( n );
}

// Set element attribute
function attr( e, n, v ) {
	e.setAttribute( n, v );
}

// Update global cursor position
function updateLastPos( el ) {
	lastStart	= el.selectionStart;
	lastEnd		= el.selectionEnd;
}

// Attach event listener
function listen( t, e, f, m ) {
	var 
	v = e.split( ',' ).map( ( item ) => item.trim() ),
	l = v.length,
	m = m || false;
	
	for ( var i = 0; i < l; i++ ) {
		t.addEventListener( v[i], f, m );
	}
}

// Template placeholder replacements
function template( tpl, data ) {
	for ( var key in data ) {
		tpl	= 
		tpl.replace( 
			new RegExp( '{' + key + '}', 'g' ), 
			data[key] 
		);
	}
	
	return tpl;
}

// String repeater helper
function repeat( t, n ) {
	var s = '';
	while ( n-- > 0) {
		s += t;
	}
	return s;
}

// Bytes to abbreviation
function bts( b, de ) {
	if ( b == 0 ) {
		return '0 bytes';
	}
	
	var
	k	= 1024,
	d	= de || 2,
	s	= [ 'B', 'KB', 'MB', 'GB', 'TB' ],
	i	= Math.floor( Math.log( b ) / Math.log( k ) );
	
	return Math.round( b / Math.pow( k, i ), d ) + '' + s[i];
}

// Move cursor to position
function moveTo( el, s, e ) {
	el.selectionStart	= s;
	el.selectionEnd		= e;
	updateLastPos( el );
}

// Move cursor to end of string
function moveEnd( el, txt ) {
	var
	s	= selection( el ),
	l	= s.range + txt.length;
	moveTo( el, l, l );
}

// Insert character at cursor position
function insertTxt( el, txt ) {
	var
	s = selection( el ),
	l = s.start + txt.length;
	
	el.value = 
		el.value.substring( 0, s.start ) + txt + 
		el.value.substring( s.end, el.value.length );
	
	moveTo( el, l, l );
}

// Move cursor to last position and insert text
function mvInsertTxt( el, txt ) {
	if ( el.selectionStart || el.selectionStart == '0' ) {
		moveTo( el, lastStart, lastEnd );
		insertTxt( el, txt );
	}
	updateLastPos( el );
}

// Auto-adjust textarea height
function resize( txt ) {
	txt.style.resize	= 'none';
	
	// Reset
	txt.style.height	= 'auto';
	txt.style.height	= txt.scrollHeight + 'px';
}

// Add the toolbar
function toolAdd() {
	var
	tool		= create( 'div' ),
	body		= document.getElementsByTagName('body')[0];
	
	attr( tool, 'id', 'toolbar' );
	attr( tool, 'class', 'modal abs' );
	
	tool.innerHTML	= toolbarTpl;
	body.appendChild( tool );
}

// Show toolbar
function toolOn() {
	byId( 'toolbar' ).style.display	= 'block';
	showtool				= true;
}

// Hide toolbar
function toolOff() {
	byId( 'toolbar' ).style.display	= 'none';
	showtool				= false;
}

// Very rudimentary Markdown commands
function toolbar( txt, key, e ) {
	var s	= selection( txt );
	
	// Called function
	switch( key ) {
		case 27:	// Escape
		case 67:	// C / Cancel
			break;
			
		case 66:	// B / Bold
			insertTxt( txt, '**' + s.range + '**' );
			break;
		
		case 72:	// H / Headings
			var h = prompt( 'Heading level (1 - 6)', '' ) || 1;
			if ( h < 1 || h > 6 ) { h = 1 }
			insertTxt( txt, template( headerTpl, {
				'txt': s.range,
				'num': repeat( '#', h )
			} ) );
			break;
			
		case 73:	// I / Italic
			insertTxt( txt, '*' + s.range + '*' );
			break;
			
		case 76:	// L / Hyperlink
			var ln = prompt( 'Enter URL', '' ) || '#';
			insertTxt( txt, template( linkTpl, {
				'desc': s.range,
				'name': ln
			} ) );
			break;
			
		case 83:	// S / Strikethrough
			insertTxt( txt, '~~' + s.range + '~~' );
			break;
			
		case 85:	// U / Underline
			// Match line to highlighted range length
			var ul  = '-'.repeat( s.range.length );
			insertTxt( txt, template( underTpl, {
				'desc': s.range,
				'under': ul
			} ) );
			break;
	}
	
	toolOff();
}

// Selected text range
function selection( el ) {
	var s = 
	{
		'start'	: el.selectionStart,
		'end'		: el.selectionEnd
	};
	s.range = el.value.substring( s.start, s.end ).trim();
	return s;
}

// Formatting toolbar
function format( txt, e ) {
	var key	=  e.keyCode || e.charCode || e.which;
	
	// Toolbar is already active
	if  ( showtool == true ) {
		e.preventDefault();
		toolbar( txt, key, e );
		return;
	}
	
	// Check for Enter first
	if  ( key !== 13 ) {
		return;
	}
	
	var s = selection( txt );
	
	// Do we have a selection
	if ( s.range == '' ) {
		return;
	}
	
	toolOn();
	e.preventDefault();
}

// Document load
function ready( func ) {
	if ( document.readyState === 'complete' ) {
		return func();
	}
	
	listen( document, 'DOMContentLoaded', func, false );
}



