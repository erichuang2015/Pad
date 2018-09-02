<?php declare( strict_types = 1 );

/**
 *  This file should be deleted immediately after setup
 */


define( 'COMPLETE', <<<HTML
<h1>Setup complete</h1>
You can now <a href="/">login</a> using the following credentials:<br />
Username: {username}<br />
Password: {password}<br /><br /><br />

There won't be any posts until you enter the  
<a href="/manage">management area</a> and create one.

<h3>Remember to delete this file after setup is complete.</h3>
HTML
);

define( 'USER_EXISTS', <<<HTML
<h1>Error:</h1>
A user already exists in the database.<br />
This file should not be run twice.<br />
Run <strong>/data/create.sh</strong> to start fresh.
HTML
);

define( 'ERROR_DATABASE', <<<HTML
<h1>Error:</h1>
Couldn't connect to the database<br />
Please ensure the database location is correct and readable in  
<strong>config.php</strong>
HTML
);

define( 'ERROR_DBVERSION', <<<HTML
<h1>Error:</h1>
Couldn't prepare database query.<br />
Please ensure your SQLite version is 3.7.0 or greater.
HTML
);

define( 'ERROR_QUERY', <<<HTML
<h1>Error:</h1>
Couldn't execute query.<br />
Please ensure that the database tables have been created by  
running <strong>/data/create.sh</strong>.
HTML
);

define( 'ERROR_INSERT', <<<HTML
<h1>Error:</h1>
Couldn't create new user<br />
Please ensure that the database tables are in the correct  
format by running <strong>/data/create.sh</strong>.
HTML
);

define( 'ERROR_PHP', <<<HTML
<h1>Error:</h1>
Couldn't execute some needed functions.<br />
Please ensure your PHP version is 7.0.28 or greater.
HTML
);



// Do not edit the following lines
define( 'INCLUDED', 1 );
require( 'config.php' );


/**
 *  Setup output environment
 */

// Clear unneded headers
\header_remove( 'X-Powered-By' );

// Setup content type
\header( 'Content-Type: text/html; charset=utf-8', true );

// Add Anti-XSS headers
\header( 'X-XSS-Protection: 1; mode=block', true );
\header( 'X-Content-Type-Options: nosniff', true );
\header( 'X-Frame-Options: deny', true );
\header( "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'", true );

/**
 *  Begin database setup and tests
 */
try {
	// Database options
	$opts	= [
		\PDO::ATTR_TIMEOUT =>	\DATA_TIMEOUT,
		\PDO::ATTR_DEFAULT_FETCH_MODE	=> \PDO::FETCH_ASSOC,
		\PDO::ATTR_PERSISTENT		=> false,
		\PDO::ATTR_EMULATE_PREPARES	=> false,
		\PDO::ATTR_ERRMODE		=> \PDO::ERRMODE_EXCEPTION
	];

	$db	= new \PDO( \DATA, null, null, $opts );
} catch( \PDOException $e ) {
	die( ERROR_DATABASE );
}

try {
	$db->exec( 'PRAGMA journal_mode = WAL;' );
	$db->exec( 'PRAGMA foreign_keys = ON;' );
} catch( \PDOException $e ) {
	die( ERROR_DBVERSION );
}

$stm	= $db->prepare( "SELECT COUNT(id) FROM users;" );
if ( $stm->execute() ) {
	$c = $stm->fetchColumn();
	if ( !empty( $c ) ) {
		die( USER_EXISTS );
	}
} else {
	die( ERROR_QUERY );
}

/**
 *  Begin credential setup and tests
 */
// New user ID
$uid	= 0;
$pass	= '';
$passh	= '';
try {
	// Generate new password
	$pass	= \bin2hex( \random_bytes( 12 ) );
	
	// Standard hash
	$passh	= 
	\base64_encode(
		\password_hash(
			\base64_encode(
				\hash( 'sha384', $pass, true )
			),
			\PASSWORD_DEFAULT
		)
	);
} catch( Exception $e ) {
	die( ERROR_PHP );
}
	
// Create default account with admin status
$stm	= 
$db->prepare( 
	"INSERT INTO users ( username, password, status ) 
		VALUES( :username, :password, :status )";
);

if ( $stm->execute( [
	':username'	=> DEFAULT_USER,
	':password'	=> $passh,
	':status'	=> AUTH_ADMIN
] ) ) {
	$uid = $db->lastInsertId();
}
	
if ( empty( $uid ) ) {
	die( ERROR_INSERT );
}

die( \strtr( COMPLETE, [ 
	'{username}' => DEFAULT_USER,
	'{password}' => $pass
] ) );
