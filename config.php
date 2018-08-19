<?php

/**
 *  Core site settings
 */
define( 'SETTINGS',		'data/site.json' );

/**
 *  Database location
 */
define( 'DATA',		'data/site.db' );

/**
 *  Database connection timeout
 */
define( 'DATA_TIMEOUT',	5 );

/**
 *  This setting is only needed once during setup
 */
define( 'DEFAULT_USER',	'admin' );

/**
 *  Remember to enable write permissions to site.json and site.db. 
 *  If you intend to run the /data/backup.sh script, also enable write 
 *  permissions to the /data/backups folder
 */

/**
 *  Theme directory
 */
define( 'THEME_DIR',		'themes/' );

/**
 *  Set true for sites behind Tor
 */
define( 'SKIP_LOCAL',		true );






// Do not edit the following lines
if ( !defined('INCLUDED') ) { 
	die(); 
}

