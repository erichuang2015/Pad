<?php

/**
 *  Core site settings
 */

/**
 *  Relative path based on config.php file location
 */
define( 'PATH',		\realpath( \dirname( __FILE__ ) ) . '/' );

/**
 *  Remember to enable write permissions to site.json and site.db. 
 *  If you intend to run the /data/backup.sh script, also enable write 
 *  permissions to the /data/backups folder
 */
define( 'SETTINGS',		PATH . 'data/site.json' );

/**
 *  Database location
 */
define( 'DATA',		PATH . 'data/site.db' );

/**
 *  Database connection timeout
 */
define( 'DATA_TIMEOUT',	5 );

/**
 *  Cache directory
 */
deifine( 'CACHE',		PATH . 'data/cache/' );

/**
 *  Cache duration
 */
define( 'CACHE_TTL',		1800 );		// 30 minutes

/**
 *  Language translation file
 */
define( 'LANGUAGE',		'data/language.en-us.json' );

/**
 *  This setting is only needed once during setup
 */
define( 'DEFAULT_USER',	'admin' );

/**
 *  Theme directory
 */
define( 'THEME_DIR',		'themes/' );

/**
 *  Set true for sites behind Tor
 */
define( 'SKIP_LOCAL',		true );


/**
 *  User authorization levels
 */
define( 'AUTH_ADMIN',		99 );
define( 'AUTH_EDITOR',	10 );
define( 'AUTH_USER',		0 );
define( 'AUTH_BANNED',	-1 );





// Do not edit the following lines
if ( !defined('INCLUDED') ) { 
	die(); 
}

