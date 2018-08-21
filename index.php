<?php declare( strict_types = 1 );

/**
 *  Site messages
 */
define( 'MSG_LOGIN',		'Please login first' );
define( 'MSG_NOTFOUND',	'Page not found' );
define( 'MSG_CODEDETECT',	'Error: Server-side code detected' );
define( 'MSG_REGCLOSED',	'Registrations are closed' );
define( 'MSG_PASSMATCH', 	'Passwords must match' );
define( 'MSG_PASSERROR',	'Password error' );
define( 'MSG_LOGINERROR',	'Login error' );
define( 'MSG_FORMEXP',	'Form expired' );
define( 'MSG_DENIED',		'Permission to access or modify this resource is denied' );

/**
 *  Pagination
 */
define( 'PREV_PAGE', 		'Previous' );
define( 'NEXT_PAGE', 		'Next' );
define( 'NAV_TPL',		'<li><a href="{url}">{page}</a></li>' );


/**
 *  Anti-cross-site request forgery token size
 */
define( 'CSRF_BYTES',		8 );

/**
 *  Token generation/matching hash
 */
define( 'CSRF_HASH',		'tiger160,4' );


/**
 *  Hard limits
 */

// Maximum password length ( recommend between 2048 and 8096 )
define( 'PASS_MAX',		2048 );


// Limit for years of past posts
define( 'YEAR_END',		2000 );

// Visitor signature hash
define( 'SIG_HASH',		'tiger160,4' );

// Session defaults
define( 'SESSION_EXP',	300 );
define( 'SESSION_BYTES',	12 );
define( 'SESSION_NAME',	'pad' );

// Cookie defaults
define( 'COOKIE_EXP', 	86400 );
define( 'COOKIE_PATH',	'/' );


/**
 *  Default content security policy is to restrict everything to 
 *  the current host
 */
define( 'DEFAULT_CSP',	"default-src 'self'; frame-ancestors 'none'" );
define( 'DEFAULT_JCSP',	<<<JSON
{
	"default-src"		: "'self'",
	"frame-ancestors"	: "'none'"
}
JSON
);




/**
 *  URL validation regular expressions
 */
define(
	'RX_URL', 
	'~^(http|ftp)(s)?\:\/\/((([a-z|0-9|\-]{1,25})(\.)?){2,9})($|/.*$){4,255}$~i'
);


define( 'RX_XSS2',		'/(<(s(?:cript|tyle)).*?)/ism' );
define( 'RX_XSS3',		'/(document\.|window\.|eval\(|\(\))/ism' );
define( 'RX_XSS4',		'/(\\~\/|\.\.|\\\\|\-\-)/sm' );



// Do not edit the following 2 lines
define( 'INCLUDED', 1 );
require( 'config.php' );


/**
 *  Security 
 */

/**
 *  Process HTTP_* variables
 */
public function httpHeaders() {
	static $headers;
	
	if ( isset( $headers ) ) {
		return $headers;
	}
	
	$headers = [];
	foreach ( $_SERVER as $k => $v ) {
		if ( 0 === \strncasecmp( $k, 'HTTP_', 5 ) ) {
			$a = \explode( '_' ,$k );
			\array_shift( $a );
			\array_walk( $a, function( &$r ) {
				$r = \ucfirst( \strtolower( $r ) );
			} );
			
			$headers[ \implode( '-', $a ) ] = $v;
		}
	}
	
	return $headers;
}
	
/**
 *  Get IP address
 */
private function getIP() : string {
	static $ip;
	
	if ( isset( $ip ) ) {
		return $ip
	}
		
	$ip	= $_SERVER['REMOTE_ADDR'];
	$va	=
	( SKIP_LOCAL ) ?
	\filter_var( $ip, \FILTER_VALIDATE_IP ) : 
	\filter_var(
		$ip, 
		\FILTER_VALIDATE_IP, 
		\FILTER_FLAG_NO_PRIV_RANGE | 
		\FILTER_FLAG_NO_RES_RANGE
	);
	
	$ip = ( false === $va ) ? '' : $ip;
	
	return $ip;
}
	
/**
 *  Guess if current request is secure
 */
function isSecure() : bool {
	$ssl	= $_SERVER['HTTPS'] ?? '0';
	$port	= ( int ) ( $_SERVER['SERVER_PORT'] ?? 80 );
	if ( $ssl == 'on' || $ssl == '1' ) {
		return true;
	}
	
	if ( $port == 443 ) {
		return true;
	}
	
	return false;
}
	
/**
 *  Create current visitor's browser signature by sent headers
 */
function signature( bool $raw ) {
	static $rawsig;
	static $sig;
	
	if ( $raw ) {
		if ( isset( $rawsig ) ) {
			return $rawsig;
		}
	} else {
		if ( isset( $sig ) ) {
			return $sig;
		}
	}
	
	// Headers to skip because they change too often
	$skip_headers		= 
	[
		'Accept-Datetime',
		'Accept-Encoding',
		'Content-Length',
		'Authorization',
		'Cache-Control',
		'Content-Type',
		'Content-Md5',
		'Connection',
		'Forwarded',
		'Referer',
		'Cookie',
		'Expect',
		'Accept',
		'Pragma',
		'Date',
		'TE'
	];
		
	$headers	= httpHeaders();
	$search	= 
	\array_intersect_key( 
		\array_keys( $headers ), 
		\array_reverse( $this->skip_headers ) 
	);
		
	$match		= '';
	foreach ( $headers as $k => $v ) {
		$match	.= $v[0];
	}
	
	$rawsig	= $match;
	$sig		= \hash( SIG_HASH, $match ); 
		
	return $raw ? $rawsig : $sig
}




/**
 *  Helpers
 */

/**
 *  Suhosin aware checking for function availability
 *  
 *  @param string $func Function name
 *  @return boolean true If the function exists
 */
function missing( $func ) {
	if ( \extension_loaded( 'suhosin' ) ) {
		$exts = \ini_get( 'suhosin.executor.func.blacklist' );
		if ( !empty( $exts ) ) {
			$blocked	= \explode( ',', \strtolower( $exts ) );
			$blocked	= \array_map( 'trim', $blocked );
			$search	= \strtolower( $func );
			
			return (
				false	== \function_exists( $func ) && 
				true	== array_search( $search, $blocked ) 
			);
		}
	}
	
	return !\function_exists( $func );
}

/**
 *  Load file contents and check for any server-side code		
 */
function loadFile( $name ) {
	static $loaded	= [];
	
	// Check if already loaded
	if ( isset( $loaded[$name] ) ) {
		return $loaded[$name];
	}
	
	if ( \file_exists( $name ) ) {
		$data = \file_get_contents( $name );
		if ( false !== \strpos( $data, '<?' ) ) {
			die( MSG_CODEDETECT );
		}
		$loaded[$name] = $data;
		return $data;
	}
	
	return null;
}

/**
 *  Flatten a multi-dimensional array into a path map
 *  
 *  @link https://stackoverflow.com/a/2703121
 */ 
function flatten(
	array		$items, 
	string		$delim	= ':'
) {
	$it	= new \RecursiveIteratorIterator( 
			new \RecursiveArrayIterator( $items )
		);
	
	$out	= [];
	foreach ( $it as $leaf ) {
		$path = '';
		foreach ( \range( 0, $it->getDepth() ) as $depth ) {
			$path .= 
			\sprintf( 
				"$delim%s", 
				$it->getSubIterator( $depth )->key() 
			);
		}
		$out[$path] = $leaf;
	}
	
	return $out;
}

/**
 *  Load and process language file
 */
function language() {
	static $data;
	
	if ( isset( $data ) ) {
		return $data;
	}
	$file	= loadFile( LANGUAGE );
	$terms	= decode( $file );
	
	$data	= empty( $terms ) ? [] : $terms;
	return $data;
}

/**
 *  Term replacement helper
 *  Flattens multidimensional array into {$prefix:group:label...} format
 *  and replaces matching placeholders in content
 *  
 *  @param string	$prefix		Replacement prefix E.G. 'lang'
 *  @param array	$data		Multidimensional array
 *  @param string	$content	Placeholders to replace
 *  @return string
 */ 
function prefixReplace(
	string		$prefix, 
	array		$data, 
	string		$content
) : string {
	// Find placeholders with given prefix
	\preg_match_all( 
		'/\{' . $prefix . '(\:[\:a-z]{1,100})\}/g', 
		$content, $matches 
	);
	
	// Convert data to :group:label... format
	$terms	= flatten( $data );
	
	// Replacements list
	$rpl	= [];
	
	$c	= count( $matches );
	
	// Set {prefix:group:label... } replacements or empty string
	for( $i = 0; $i < $c; $i++ ) {
		$rpl['{' . $prefix . $m[1] . '}']	= 
			$terms[$m[1]] ?? '';
	}
	
	return \strtr( $content, $rpl );
}

/**
 *  Scan template for language placeholders
 *  
 *  @param string	$tpl	Loaded template data
 *  @return string
 */
function parseLang( string $tpl ) : string {
	$lang		= language();
	return prefixReplace( 'lang', $lang, $tpl );
}

/**
 *  UTC timestamp
 */
function utc( $stamp = null ) : string {
	return \gmdate( 'Y-m-d H:i:s', $stamp ?? time() );
}

/***
 *  ATOM compatible UTC timestamp
 */
function rfcDate( $stamp = null ) : string {
	$fmt	= \date( 'D, d M Y H:i:s T', $stamp ?? time() );
	
	return \gmdate( \DATE_RFC2822, \strtotime( $fmt ) );
}

/**
 *  Ensure date arguments don't exceed today
 */
function enforceDates( array $args ) : array {
	$now	= time();
	
	// Requested year/month/day
	$year		= ( int ) ( $args['year'] ?? date( 'Y', $now ) );
	$month		= ( int ) ( $args['month'] ?? date( 'n', $now ) );
	$day		= ( int ) ( $args['day'] ?? date( 'j', $now ) );
	
	// Current year/month/day
	$m		= ( int ) date( 'n', $now );
	$y		= ( int ) date( 'Y', $now );
	$d		= ( int ) date( 'j', $now );
	
	// Enforce date ranges
	$year		= ( $year > $y || $year < YEAR_END ) ? 
				$y : $year;
	
	// Current year? Enforce month to current month
	if ( $y == $year ) { 
		$month	= ( $month > $m || $month <= 0 ) ? 
				$m : $month;
	
	// No more than 12 months
	} else {
		$month = ( $month <= 0 || $month > 12 ) ? 
				1 : $month;
	}
	
	// Days in requested year and month
	$days	= \cal_days_in_month( \CAL_GREGORIAN, $month, $year );
	
	// No more than the number of days in requested month
	$day	= ( $day <= 0 || $day > $days ) ? 1 : $day;
	
	// No more than the current day, if it's the current year/month
	if ( $year == $y && $month == $m ) {
		if ( $day > $d ) {
			$day = $d;
		}
	}
	
	return [ $year, $month, $day ];
}

/**
 *  Safely encode to JSON
 */
function encode( array $data ) : string {
	return 
	\json_encode( 
		$data, 
		\JSON_HEX_TAG | \JSON_HEX_APOS | \JSON_HEX_QUOT | 
		\JSON_HEX_AMP | \JSON_UNESCAPED_UNICODE | 
		\JSON_PRETTY_PRINT 
	);
}

/**
 *  Safely decode JSON to array
 */
function decode( string $data ) : array {
	$data = 
	\json_decode( 
		\utf8_encode( $data ), true, 10, 
		\JSON_BIGINT_AS_STRING
	);
	
	if ( empty( $data ) ) {
		return [];
	}
	
	if ( false === $data ) {
		return [];
	}
	return $data;
}

/**
 *  Load settings
 */
function settings() : array {
	static $data;
	
	if ( isset( $data ) ) {
		return $data;
	}
	
	$file	= loadFile( SETTINGS );
	if ( empty( $file ) ) {
		die( 'Error loading settings' );
	}
	$data = decode( $data );
	
	return $data;
}

/**
 *  Merge modified settings and save configuration
 */
function saveSettings( array $params ) : int {
	$data			= settings();
	$data['settings']	= $params;
	
	$out			= encode( $data );
	return \file_put_contents( SETTINGS, $out );
}

/**
 *  Cleanup and other extras
 */
function shutdown() {
	cacheGC();
}

/**
 *  Caching
 */

/**
 *  Create cache save path based on current cache directory
 *  
 *  @param string	$key	Generated cache key
 *  @param bool		$create Create path structure if true
 *  @param string	$root	Default page root to begin
 *  @return string
 */
function cachePath(
	string		$key,
	bool		$create,
	string		$root		= \CACHE
) : string {
	$segs	= \rtrim( $root, '/' ) . '/';
	$parts	= \str_split( $key, 4 );
		
	// Only getting creation path
	if ( !$create ) {
		return
		$segs . '/' . \implode( '/', $parts ) . '/' . $key;
	}
	
	// Iterate through segments and create each directory
	foreach ( $parts as $part ) {
		$segs .= $s . $part;
		writeDir( $segs );
	}
	
	return $segs . '/' . $key;
}
	
/**
 *  Create a directory if it doesn't exist
 *  Owner: read/write
 *  Everyone else: read
 *  
 *  @param string	$dir	Directory to make / set permissions
 */
function writeDir( string $dir ) {
	if ( !\is_dir( $dir ) ) {
		\mkdir( $dir, 0644 );
	}
}

/**
 *  Check if cache content exists and hasn't expired yet
 *  
 *  @param string	$path		Cache data file
 *  @return bool
 */
function cacheHit( string $path ) : bool {
	if ( empty( $this->path ) ) {
		return false;
	}
	
	if ( \file_exists( $path ) ) {
		$t = \filemtime( $path );
		if ( false === $t ) {
			return false;
		}
		return ( time() - $t ) < CACHE_TTL;
	}
	
	return false;
}

/**
 *  Get cached data (if any) by URI key
 *  
 *  @return string
 */
function getCache( string $uri ) : string {
	$key	= \hash( 'sha256', $uri );
	$path	= cachePath( $key, false );
	
	if ( cacheHit( $path ) ) {
		return \file_get_contents( $path );
	}
	
	return '';
}

/**
 *  Save content to cache
 *  
 *  @param string	$uri		URI to set cache to
 *  @param string	$content	Cache data
 */
function saveCache( string $uri, string $content ) : bool {
	$key	= \hash( 'sha256', $uri );
	$path	= cachePath( $key, true );
	
	// Something went wrong?
	if ( empty( $path ) ) {
		return false;
	}
	
	return 
	\file_put_contents( $path, $content ) ? true : false;
}

/**
 *  Directory iterator helper
 *  
 *  @param string	$root	Directory root
 *  @return RecursiveIteratorIterator
 */
function getDirectory( $root ) {
	return
	new \RecursiveIteratorIterator(
		new \RecursiveDirectoryIterator( 
			$root, \FilesystemIterator::SKIP_DOTS |
				\FilesystemIterator::FOLLOW_SYMLINKS
		), 
		\RecursiveIteratorIterator::CHILD_FIRST
	);
		
}

/**
 *  Garbage collection of old cache files
 *  
 *  @link https://stackoverflow.com/a/42945163
 *  @link https://stackoverflow.com/a/10609967
 *  
 *  @param string	$root	Cache path directory
 */
function cacheGC( string $root = \CACHE ) {
	
	// Cache directory
	$dir	= getDirectory( $root );
	
	// Exclude files with an extension (E.G. readme.md)
	$it	= 
	new \RegexIterator( 
		$dir, '/^([^.]+)$/i', 
		\RecursiveRegexIterator::GET_MATCH 
	);
	
	// Current time
	$now	= time();
	
	// Iterate through each file
	foreach ( $it as $file ) {
		
		// Check for cache expiration
		if ( ( $now - $file->getCTime() ) >  CACHE_TTL ) {
			
			// Check path
			$path = $info->getRealPath();
			
			// No conflict or errors?
			if ( false !== $path ) {
				\unlink( $path );
			}
		}
	}
}



/**
 *  Database
 */

/**
 *  Get database connection
 */
function getDb() {
	static $db;
	
	if ( isset( $db ) ) {
		return $db;
	}
	
	$opts	= [
		\PDO::ATTR_TIMEOUT		=> \DATA_TIMEOUT,
		\PDO::ATTR_DEFAULT_FETCH_MODE	=> \PDO::FETCH_ASSOC,
		\PDO::ATTR_PERSISTENT		=> false,
		\PDO::ATTR_EMULATE_PREPARES	=> false,
		\PDO::ATTR_ERRMODE		=> 
			\PDO::ERRMODE_EXCEPTION
	];
	
	$db	= new \PDO( \DATA, null, null, $opts );
	$db->exec( 'PRAGMA journal_mode = WAL;' );
	$db->exec( 'PRAGMA foreign_keys = ON;' );
	
	return $db;
}

/**
 *  Get parameter result from database
 */
function getResults(
	string		$sql, 
	array		$params
) : array {
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( $params ) ) {
		return $stm->fetchAll();
	}
	return [];
}

/**
 *  Create database update
 */
function setUpdate(
	string		$sql,
	array		$params
) : bool {
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( $params ) ) {
		return true;
	}
	return false;
}

/**
 *  Insert record into database and return last ID
 */
function setInsert(
	string		$sql,
	array		$params
) : int {
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( $params ) ) {
		( int ) $db->lastInsertId();
	}
	return 0;
}

/**
 *  Get a single item by ID
 */
function getSingle( int $id, string $sql ) : array {
	$data	= getResults( $sql, [ ':id' => $id ] );
	if ( empty( $data ) ) {
		return $data[0];
	}
	return [];
}

/**
 *  Get post details (for siblings)
 */
function findPreviewById( int $id ) : array {
	return 
	getSingle( 
		$id, 
		"SELECT * FROM post_preview WHERE id = :id LIMIT 1;" 
	);
}

/**
 *  Get post by ID
 */
function findPostById( int $id ) : array {
	return 
	getSingle( 
		$id, 
		"SELECT * FROM page_view WHERE id = :id LIMIT 1;"
	);
}

/**
 *  Get post by ID and URL slug
 */
function findPostByIdSlug( int $id, string $slug ) : array {
	$sql	= 
	"SELECT * FROM page_view 
		WHERE id = :id AND slug = :slug LIMIT 1;";
	
	return 
	getSingle( $sql, [ ':id' => $id, ':slug' => $slug ] );
}

/**
 *  Get post by date and slug permalink
 */
function findPostByPermalink( string $link ) : array {
	$sql	=
	"SELECT * FROM page_view 
		WHERE permalink = :link LIMIT 1;";
		
	return getSingle( $sql, [ ':link' => $link ] );
}

/**
 *  Get post sibling posts
 */
function findPostSiblings( int $prev, int $next ) : array {
	$out	= [];
	
	if ( $prev > 0 ) {
		$out[] = findPreviewById( $prev );
	}
	if ( $next > 0 ) {
		$out[] = findPreviewById( $next );
	}
	
	return $out;
}

/**
 *  Get posts for the homepage
 */
function findPostsByIndex(
	array	$data,
	bool	$drafs = false 
) : array {
	$conf		= settings();
	$sst		= $drafts ? '' : 'WHERE status > 0';
	$sql		=
	"SELECT * FROM index_view $sst LIMIT :limit OFFSET :offset;";
	
	$page		= ( int ) ( $data['page'] ?? 1 );
	$limit		= ( int ) ( $conf['page_limit'] ?? 15 );
	$param	= [
		':limit'	=> $limit,
		':offset'	=> $limit * ( $page - 1 )
	];
	
	return getResults( $sql, $params );
}

/**
 *  Get posts by date archive
 */
function findPostsArchive( array $data ) : array {
	$conf		= settings();
	$dates		= enforceDates( $data );
	$page		= ( int ) ( $data['page'] ?? 1 );
	$search	= [ $dates[0] ];
	
	if ( !empty( $route['month'] ) ) {
		$search[] = $raw[1];
	}
	
	if ( !empty( $route['day'] ) ) {
		$search[] = $raw[2];
	}
	
	switch ( count( $search ) ) {
		case 3:
			$label	= 'archive_ymd';
			break;
		
		case 2:
			$label	= 'archive_ym';
			break;
			
		default:
			$label	= 'archive_y';
	}
	
	$limit	= ( int ) ( $conf['page_limit'] ?? 15 );
	$sql	=
	"SELECT * FROM index_view WHERE $label = :search 
		LIMIT :limit OFFSET :offset;";
	
	$param	= [
		':search'	=> \implode( '/', $search ),
		':limit'	=> $limit,
		':offset'	=> $limit * ( $page - 1 )
	];
	
	return getResults( $sql, $params );
}

/**
 *  Full text post search
 */
function findPostBySearch( int $page, string $search ) : array {
	$conf	= settings();
	$limit	= ( int ) ( $conf['page_limit'] ?? 15 );
	$ssql	= 
	"SELECT docid FROM post_search WHERE body 
		MATCH :search LIMIT :limit OFFSET :offset";
	
	// Get document ids ( post ids ) from search results
	$ids	= getResults( $sql, [ ':search' => $search ];
	if ( empty( $ids ) ) {
		return [];
	}
	
	// Generate parameters
	$param = [];
	foreach ( $ids as $id ) {
		$param[':id_' . $id] = $id;
	}
	
	$keys	= implode( ', ', array_keys( $param ) );
	$sql	= 
	"SELECT * FROM index_view WHERE id IN ( $keys )";
	
	return getResults( $sql, $param );
}

/**
 *  Apply tags to given post
 */
function setTags( int $id, array $tags ) {
	if ( empty( $tags ) ) {
		return;
	}
	
	$sql = 
	"INSERT INTO tag_view ( name, slug, page_id ) 
		VALUES ( :name, :slug, :id )";
	
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	foreach ( $tags as $k => $v ) {
		$stm->execute( [
			':name'	=> $v,
			':slug'	=> slugify( $v ),
			':id'		=> $id
		] );
	}
	
}

/**
 *  Store new post
 */
function newPost( array $data ) : array {
	$sql		= 
	"INSERT INTO posts ( title, parent_id, user_id, summary, 
		body, published ) VALUES ( :title, :parent, 
		:user_id, :summary, :body, :published;";
	
	$params	= [
		':title'	=> $data['title'],
		':parent'	=> $data['parent'] ?? 0,
		':user_id'	=> $data['user_id'],
		':summary'	=> $data['summary'],
		':body'	=> $data['body'],
		':published'	=> $data['published'],
		':status'	=> $data['status']
	];
	
	$data['id'] = setInsert( $sql, $params );
	setTags( $data['id'], $data['tags'] );
	
	return $data;
}

/**
 *  Edit existing post
 */
function editPost( array $data ) {
	$sql		= 
	"UPDATE posts SET title = :title, summary = :summary, 
		body = :body, published = :published 
		WHERE id = :id;";
	
	$params	= [
		':title'	=> $data['title'],
		':summary'	=> $data['summary'],
		':body'	=> $data['body'],
		':published'	=> $data['published'],
		':status'	=> $data['status']
	];
	
	setUpdate( $sql, $params );
	setTags( $data['id'], $data['tags'] );
	
	return $data;
}

/**
 *  Helper to create new post or edit existing
 */
function savePost( array $data ) {
	$id = $data['id'] ?? 0;
	
	if ( $id > 0 ) {
		return editPost( $data );
	}
	return newPost( $data );
}



/**
 *  User data functions
 */

/**
 *  Find user authorization by cookie lookup
 */
function findCookie( string $lookup ) : array {
	$sql = "SELECT * FROM login_view
		WHERE lookup = :lookup LIMIT 1;";	
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( [ ':lookup' => $lookup ] ) ) {
		$results = $stm->fetchAll();
	}
	
	if ( empty( $results ) ) {
		return [];
	}
	
	$user	= $results[0];
	
	// Check for cookie expiration
	if ( 
		( time() - ( ( int ) $user['updated'] ) ) > 
		COOKIE_EXP
	) {
		$user['lookup']	= 
		resetLookup( ( int ) $user['id'] );
	}
	
	return $user;
}

/**
 *  Reset cookie lookup token
 */
function resetLookup( int $id ) {
	$db	= getDb();
	$stm	= 
	$db->prepare( 
		"UPDATE logins SET lookup = '' 
			WHERE user_id = :id;" 
	);
	
	if ( $stm->execute( [ ':id' => $id ] ) ) {
		// SQLite should have generated a new random token
		$rst = 
		$db->prepare( 
			"SELECT lookup FROM logins WHERE 
				user_id = :id;"
		);
		if ( $rst->execute( ':id' => $id ] ) ) {
			return $stm->fetchColumn();
		}
	}
	
	return '';
}

/**
 *  Get profile details by id
 */
function findUserById( int $id ) : array {
	$sql		= 
	"SELECT * FROM profiles WHERE id = :id LIMIT 1;";
	$data	= getResults( $sql, [ ':id' => $id ] );
	if ( empty( $data ) ) {
		return [];
	}
	return $data[0];
}

/**
 *  Get login details by username
 */
function findUserByUsername( string $username ) : array {
	$sql		= 
	"SELECT * FROM login_pass WHERE username = :user LIMIT 1;";
	$data	= getResults( $sql, [ ':user' => $username ] );
	if ( empty( $data ) ) {
		return [];
	}
	return $data[0];
}

/**
 *  Save user details by creating a new record or updating existing one
 */
function saveUser( array $data ) : array {
	if ( $data['id'] > 0 ) {
		$sql	= 
		"UPDATE users SET bio = :bio, display = :display, 
			status = :status
			WHERE id = :id;";
		
		setUpdate( $sql, [ 
			':bio'		=> $data['bio'], 
			':display'	=> $data['display'], 
			':status'	=> $data['status'], 
			':id'		=> $data['id']
		] );
		
		return $data;
	} 
	
	$sql	= 
	"INSERT INTO users ( username, password, status ) 
		VALUES( :username, :password, :status )";
	
	$data['id'] = 
	setInsert( $sql, [ 
		':username'	=> $data['username'],
		':password'	=> hashPassword( $data['password'] ),
		':status'	=> $data['status']
	] );
	
	return $data;
}

/**
 *  Set a new password for the user
 */
function savePassword( int $id, string $password ) : bool {
	$sql	= 
	"UPDATE users SET password = :password 
		WHERE id = :id";
	
	return
	setUpdate( $sql, [ 
		':password'	=> hashPassword( $password ), 
		':id'		=> $id 
	] );
}

/**
 *  Hash password
 */
function hashPassword( string $password ) : string {
	return 
	\base64_encode(
		\password_hash(
			\base64_encode(
				\hash( 'sha384', $password, true )
			),
			\PASSWORD_DEFAULT
		)
	);
}

/**
 *  Check hashed password
 */
function verifyPassword( 
	string		$password, 
	string		$stored 
) : bool {
	$stored = \base64_decode( $stored, true );
	if ( false === $stored ) {
		return false;
	}
	
	return 
	\password_verify(
		\base64_encode( 
			\hash( 'sha384', $password, true )
		),
		$stored
	);
}
	
/**
 *  Check if user password needs rehashing
 */
function passNeedsRehash( 
	string		$stored 
) : bool {
	$stored = \base64_decode( $stored, true );
	if ( false === $stored ) {
		return false;
	}
	
	return 
	\password_needs_rehash( $stored, \PASSWORD_DEFAULT );
}


/**
 *  Form processing
 */

/**
 *  Check for deletion request and confirmation
 */
function postDeleteCheck( $data ) {
	$conf	= settings();
	$root	= getRoot( $conf );
	
	// Delete check
	if ( !$data['delete'] && !$data['delconf'] ) {
		return;
	}
	
	// Nothing to delete
	if ( empty( $data['id'] ) ) {
		sendPage( $conf, 'manage' );
	} else {
		$post = 
		findPreviewById( ( int ) $data['id'] );
		
		// Delete requested, but nothing to delete?
		if ( empty( $post ) ) {
			notfound();
		}	
	}
}

/**
 *  Process post input filter with user details
 */
function postForm( array $filter, array $user ) {
	$data				= 
	\filter_input_array( \INPUT_POST, $filter );
	
	// Delete check
	postDeleteCheck( $data );
	
	$data['slug']			= 
	slugify( 
		$data['slug'] ?? $data['title'],
		$data['title']
	);
	
	$data['status']		= 
	empty( $data['preview'] ) ? 0 : 1;
	
	if ( empty( $data['summary'] ) ) {
		$data['summary']	= 
		smartTrim( \strip_tags( $data['body'] ) ) );
	} else {
		$data['summary']	= 
		pacify( \strip_tags( $data['summary'] ) );
	}
	
	if ( !empty( $data['id'] ) ) {
		$data['user_id'] = $user['id'];
	}
	
	
	$post	= savePost( $data );
	sendPage( $conf, $post['id'] . '/' . $post['slug'], 201 );
}



/**
 *  Filters
 */

/**
 *  Convert a string into a page slug
 *  
 *  @param string	$title	Fallback title to generate slug
 *  @param string	$text	Text to transform into a slug
 *  @return string
 */
function slugify( 
	string		$title, 
	string		$text		= ''
) :string {
	if ( empty( $text ) ) {
		$text = $title;
	}

	$text = \preg_replace( '~[^\\pL\d]+~u', ' ', $text );
	$text = \preg_replace( '/\s+/', '-', \trim( $text ) );
	
	// Last chance
	if ( empty( $text ) ) {
		return \hash( 'md5', $title );
	}
	
	return \strtolower( smartTrim( $text ) );
}

/**
 *  Limit a string without cutting off words
 *  
 *  @param string	$val	Text to cut down
 *  @param int		$max	Content length (defaults to 100)
 *  @return string
 */
function smartTrim(
	string		$val, 
	int		$max		= 100
) : string {
	$val	= \trim( $val );
	$len	= \mb_strlen( $val );
	
	if ( $len <= $max ) {
		return $val;
	}
	
	$out	= '';
	$words	= \preg_split( '/([\.\s]+)/', $val, -1, 
			\PREG_SPLIT_OFFSET_CAPTURE | 
			\PREG_SPLIT_DELIM_CAPTURE );
		
	for ( $i = 0; $i < \count( $words ); $i++ ) {
		$w	= $words[$i];
		// Add if this word's length is less than length
		if ( $w[1] <= $max ) {
			$out .= $w[0];
		}
	}
	
	$out	= \preg_replace( "/\r?\n/", '', $out );
	
	// If there's too much overlap
	if ( \mb_strlen( $out ) > $max + 10 ) {
		$out = \mb_substr( $out, 0, $max );
	}
	
	return $out;
}
	
	
/**
 *  HTML Filtering
 */


/**
 *  Strip unusable characters from raw text/html and conform to UTF-8
 *  
 *  @param string	$html	Raw content body to be cleaned
 *  @param bool		$entities Convert to HTML entities (defaults to true)
 *  @return string
 */
function pacify( 
	string		$html, 
	bool		$entities	= false 
) : string {
	$html		= \trim( $html );
	$html		= \iconv( 'UTF-8', 'UTF-8//IGNORE', $html );
	
	// Remove control chars except linebreaks/tabs etc...
	$html		= 
	\preg_replace(
		'/[\x00-\x08\x0B\x0C\x0E-\x1F\x80-\x9F]/u', 
		'', $html
	);
	
	// Non-characters
	$html		= 
	\preg_replace(
		'/[\x{fdd0}-\x{fdef}]/u', '', $html
	);
	
	// UTF unassigned, formatting, and half surrogate pairs
	$html		= 
	\preg_replace(
		'/[\p{Cs}\p{Cf}\p{Cn}]/u', '', $html
	);
		
	// Convert Unicode character entities?
	if ( $entities ) {
		$html	= 
		\mb_convert_encoding( 
			$html, 'HTML-ENTITIES', "UTF-8" 
		);
	}
	
	return \trim( $html );
}
	
/**
 *  HTML safe character entities in UTF-8
 *  
 *  @param string	$v	Raw text to turn to HTML entities
 *  @param bool		$quotes	Convert quotes (defaults to true)
 *  @return string
 */
function entities( 
		string		$v, 
		bool		$quotes	= true 
) : string {
	if ( $quotes ) {
		return \htmlentities( 
			\iconv( 'UTF-8', 'UTF-8', $v ), 
			\ENT_QUOTES | \ENT_SUBSTITUTE, 
			'UTF-8'
		);
	}
	
	return \htmlentities( 
		\iconv( 'UTF-8', 'UTF-8', $v ), 
		\ENT_NOQUOTES | \ENT_SUBSTITUTE, 
		'UTF-8'
	);
}

/**
 *  Filter URL
 *  This is not a 100% foolproof method, but it's better than nothing
 *  
 *  @param string	$txt	Raw URL attribute value
 *  @param bool		$xss	Filter XSS possibilities
 *  @param string	$prefix	URL prefix to prepend
 *  @return string
 */
function cleanUrl( 
	string		$txt, 
	bool		$xss		= true, 
	string		$prefix	= '' 
) : string {
	if ( empty( $txt ) ) {
		return '';
	}
	
	// Default filter
	if ( \filter_var( $txt, \FILTER_VALIDATE_URL ) ) {
		// XSS filter
		if ( $xss ) {
			if ( !\preg_match( RX_URL, $txt ) ){
				return '';
			}	
		}
		
		if ( 
			\preg_match( RX_XSS2, $txt ) || 
			\preg_match( RX_XSS3, $txt ) || 
			\preg_match( RX_XSS4, $txt ) 
		) {
			return '';
		}
		
		// Return as/is
		return  $txt;
	}
	
	return entities( $prefix . $txt );
}

	
/**
 *  Clean DOM node attribute against whitelist
 *  
 *  @param DOMNode	$node	Object DOM Node
 *  @param array	$white	Whitelist of allowed tags and params
 */
function cleanAttributes(
	\DOMNode	&$node,
	array		$white
) {
	if ( !$node->hasAttributes() ) {
		return null;
	}
	
	foreach ( 
		\iterator_to_array( $node->attributes ) as $at
	) {
		$n = $at->nodeName;
		$v = $at->nodeValue;
		
		// Default action is to remove attribute
		// It will only get added if it's safe
		$node->removeAttributeNode( $at );
		if ( \in_array( $n, $white[$node->nodeName] ) ) {
			switch ( $n ) {
				case 'longdesc':
				case 'url':
				case 'src':
				case 'href':
					$v = cleanUrl( $v );
					break;
					
				default:
					$v = entities( $v );
			}
			
			$node->setAttribute( $n, $v );
		}
	}
}

/**
 *  Scrub each node against white list
 *  @param DOMNode	$node	Document element node to filter
 *  @param array	$white	Whitelist of allowed tags and params
 *  @param array	$flush	Elements to remove from document
 */
function scrub(
	\DOMNode	$node,
	array		$white,
	array		&$flush		= []
) {
	if ( isset( $white[$node->nodeName] ) ) {
		// Clean attributes first
		cleanAttributes( $node, $white );
		if ( $node->childNodes ) {
			// Continue to other tags
			foreach ( $node->childNodes as $child ) {
				scrub( $child, $white, $flush );
			}
		}
		
	} elseif ( $node->nodeType == \XML_ELEMENT_NODE ) {
		// This tag isn't on the whitelist
		$flush[] = $node;
	}
}


/**
 *  Tidy settings
 *  
 *  @param string	$text	Unformatted, unfiltered raw HTML
 *  @return string
 */
function tidyup( string $text ) : string {
	if ( missing( 'tidy_repair_string' ) ) {
		return $text;
	}
	
	$opt = [
		'bare'					=> 1,
		'hide-comments' 			=> 1,
		'drop-proprietary-attributes'	=> 1,
		'fix-uri'				=> 1,
		'join-styles'				=> 1,
		'output-xhtml'			=> 1,
		'merge-spans'				=> 1,
		'show-body-only'			=> 0,
		'wrap'					=> 0
	];
	
	return \trim( \tidy_repair_string( $text, $opt ) );	
}

/**
 *  Embedded media
 *  
 *  @param string	$html	Pre-filtered HTML to replace media tags
 *  @return string
 */
function embeds( string $html ) : string {
	$filter		= 
	[
		// YouTube syntax
		'/\[youtube http(s)?\:\/\/(www)?\.?youtube\.com\/watch\?v=([0-9a-z_]*)\]/is'
		=> 
		'<div class="media"><iframe width="560" height="315" src="https://www.youtube.com/embed/$3" frameborder="0" allowfullscreen></iframe></div>',
		
		'/\[youtube http(s)?\:\/\/(www)?\.?youtu\.be\/([0-9a-z_]*)\]/is'
		=> 
		'<div class="media"><iframe width="560" height="315" src="https://www.youtube.com/embed/$3" frameborder="0" allowfullscreen></iframe></div>',
		
		'/\[youtube ([0-9a-z_]*)\]/is'
		=> 
		'<div class="media"><iframe width="560" height="315" src="https://www.youtube.com/embed/$1" frameborder="0" allowfullscreen></iframe></div>',
		
		// Vimeo syntax
		'/\[vimeo ([0-9]*)\]/is'
		=> 
		'<div class="media"><iframe src="https://player.vimeo.com/video/$1?portrait=0" width="500" height="281" frameborder="0" allowfullscreen></iframe></div>',
		
		'/\[vimeo http(s)?\:\/\/(www)?\.?vimeo\.com\/([0-9]*)\]/is'
		=> 
		'<div class="media"><iframe src="https://player.vimeo.com/video/$3?portrait=0" width="500" height="281" frameborder="0" allowfullscreen></iframe></div>',
		
		// Peertube
		'/\[peertube http(s)?\:\/\/(.*?)\/videos\/watch\/([0-9\-a-z_]*)\]/is'
		=>
		'<div class="media"><iframe width="560" height="315" sandbox="allow-same-origin allow-scripts" src="https://$2/videos/embed/$3" frameborder="0" allowfullscreen></iframe></div>'
	];
		
	return 
	\preg_replace( 
		\array_keys( $filter ), 
		\array_values( $filter ), 
		$html 
	);
}

/**
 *  Convert Markdown formatted text into HTML tags
 *  
 *  Inspired by : 
 *  @link https://gist.github.com/jbroadway/2836900
 *  
 *  @param string	$html	Pacified text to transform into HTML
 *  @param string	$prefix	URL prefix to prepend text
 *  @return string
 */
function markdown( $html, $prefix = '' ) {
	$filters	= 
	[
		// Links / Images with alt text
		'/(\!)?\[([^\[]+)\]\(([^\)]+)\)/s'	=> 
		function( $m ) use ( $prefix ) {
			$i = \trim( $m[1] );
			$t = \trim( $m[2] );
			$u = cleanUrl( \trim( $m[3] ), true, $prefix );
				
			return 
			empty( $i ) ?
				\sprintf( "<a href='%s'>%s</a>", $t, $u ) :
				\sprintf( "<img src='%s' alt='%s' />", $u, $t );
		},
		
		// Bold / Italic / Deleted / Quote text
		'/(\*(\*)?|_(_)?|\~\~|\:\")(.*?)\1/'	=>
		function( $m ) {
			$i = \strlen( $m[1] );
			$t = \trim( $m[4] );
			
			switch ( true ) {
				case ( false !== \strpos( $m[1], '~' ) ):
					return \sprintf( "<del>%s</del>", $t );
					
				case ( false !== \strpos( $m[1], ':' ) ):
						return \sprintf( "<q>%s</q>", $t );
						
				default:
					return ( $i > 1 ) ?
						\sprintf( "<strong>%s</strong>", $t ) : 
						\sprintf( "<em>%s</em>", $t );
			}
		},
		
		// Centered text
		'/(\n(\-\>+)|\<center\>)([\pL\pN\s]+)((\<\-)|\<\/center\>)/'	=> 
		function( $m ) {
			$t = \trim( $m[3] );
			return \sprintf( '<div style="text-align:center;">%s</div>', $t );
		},
		
		// Headings
		'/([#]{1,6}+)\s?(.+)/'			=>
		function( $m ) {
			$h = \strlen( trim( $m[1] ) );
			$t = \trim( $m[2] );
			return \sprintf( "<h%s>%s</h%s>", $h, $t, $h );
		}, 
		
		// List items
		'/\n(\*|([0-9]\.+))\s?(.+)/'		=>
		function( $m ) {
			$i = \strlen( $m[2] );
			$t = \trim( $m[3] );
			return ( $i > 1 ) ?
				\sprintf( '<ol><li>%s</li></ol>', $t ) : 
				\sprintf( '<ul><li>%s</li></ul>', $t );
		},
		
		// Merge duplicate lists
		'/<\/(ul|ol)>\s?<\1>/'			=> 
		function( $m ) { return ''; },
		
		// Blockquotes
		'/\n\>\s(.*)/'				=> 
		function( $m ) {
			$t = \trim( $m[1] );
			return \sprintf( '<blockquote><p>%s</p></blockquote>', $t );
		},
		
		// Merge duplicate blockquotes
		'/<\/(p)><\/(blockquote)>\s?<\2>/'	=>
		function( $m ) { return ''; },
		
		// Block of code
		'/\n`{3,}(.*)\n`{3,}/'			=>
		function( $m ) { 
			$t = \trim( $m[1] );
			return \sprintf( '\n<pre><code>%s</code></pre>\n', $t );
		},
		
		// Inline code
		'/`(.*)`/'				=>
		function( $m ) {
			$t = \trim( $m[1] );
			return \sprintf( '<code>%s</code>', $t );
		},
		
		// Horizontal rule
		'/\n-{5,}/'				=>
		function( $m ) { return '<hr />'; },
		
		// Fix paragraphs after block elements
		'/\n([^\n(\<\/ul|ol|li|h|blockquote|code|pre)?]+)\n/'		=>
		function( $m ) {
			return '</p><p>';
		}
	];
	
	return
	\trim( \preg_replace_callback_array( $filters, $html ) );
}

	
/**
 *  Clean entry title
 *  
 *  @param string	$title	Raw title entered by the user
 *  @return string
 */
function title( string $text ) : string {
	return smtartTrim( pacify( $text ) );
}

/**
 *  Filter username
 *  
 *  @param string	$text	Raw username entered into field
 *  @return string
 */
function username( string $text ) : string {
	$text = title( $text );
	
	return 
	\trim( \preg_replace( '~[^\\pL_\-\.\d]+~u', '', $text ) );
	//\preg_replace( '/^[a-z0-9_\-\.]/i', '', $text ); 
}

/**
 *  Password filter
 */
function password( $value ) : string {
	$value = pacify( $value ?? ''  );
	
	// Passwords only set to max size
	return 
	smartTrim( $value, PASS_MAX );
}
	
/**
 *  Handle tags
 */
function taglist( $value ) : array {
	$value	= pacify( $value ?? '' );
	$vals	= \explode( ',', $value );
	$uf	= [];
	foreach ( $vals as $v) {
		$uf[] = pacify( $v );
	}
	return $uf;
}

/**
 *  Datetime filter
 */
function datetime( $value ) : int {
	$test = \strtotime( pacify( $value ) ?? \utc() );
	
	return ( false === $test ) ? time() : $test;
}

/**
 *  HTML whitelist filter
 */
function html( $value ) : string {
	static $white;
	
	if ( !isset( $white ) ) {
		$conf		= settings();
		$white		= $conf['whitelist'];
	}
	
	// Preliminary cleaning
	$html		= pacify( $value, true );
	
	// Clean up HTML
	$html		= tidyup( $html );
	
	// Encode 
	$html		= \preg_replace_callback( 
				'/<code>(.*)</code>/ism', 
				function ( $m ) {
					return
					entities( $m[1] );
				}, $html
			);
	
	$ent		= \libxml_disable_entity_loader( true );
	$err		= \libxml_use_internal_errors( true );
	
	$dom		= new \DOMDocument();
	$dom->loadHTML( 
		$html, 
		\LIBXML_HTML_NOIMPLIED | \LIBXML_HTML_NODEFDTD | 
		\LIBXML_NOERROR | \LIBXML_NOWARNING | 
		\LIBXML_NOXMLDECL | \LIBXML_COMPACT | 
		\LIBXML_NOCDATA | \LIBXML_NONET
	);
		
	$domBody	= 
		$dom->getElementsByTagName( 'body' )->item( 0 );
	
	// Iterate through every HTML element 
	foreach ( $domBody->childNodes as $node ) {
		scrub( $node, $white, $flush );
	}
	
	// Apply Markdown formatting
	$html		= markdown( $html, $prefix );
	
	// Apply embedded media
	return embeds( $html );
}

/**
 *  Helper to indicate if a checkbox should be checked based on value
 */
function checkedCheckbox( $value ) {
	$ch = ( bool )( $value ?? false );
	
	return $ch ? 'checked' : '';
}

/**
 *  Helper to check if a template contains a placeholder term
 */
function tplHas( string $haystack, string $term ) {
	return \strpos( $tpl, '{' . $term . '}' ) !== false;
}

/**
 *  Session functions
 */

/**
 *  Set session handler functions
 */
function setSessionHandler() {
	\session_set_save_handler( [
		'sessionOpen', 
		'sessionClose', 
		'sessionRead', 
		'sessionWrite', 
		'sessionDestroy', 
		'sessionGC', 
		'sessionCreateID'
	] );	
}

/**
 *  Does nothing
 */
function sessionOpen( $path, $name ) { return true; }
function sessionClose() { return true; }

/**
 *  Create session ID in the database and return it
 */
function sessionCreateID() {
	$id	= \bin2hex( \random_bytes( SESSION_BYTES ) );
	$sql	= 
	"INSERT OR IGNORE INTO sessions ( session_id )
		VALUES ( :id );";
		
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( [ ':id' => $id ] ) ) {
		return $id;
	}
	
	// Something went wrong with the database
	die();
}

/**
 *  Delete session
 */
function sessionDestroy( $id ) {
	$sql	= 
		"DELETE FROM sessions 
			WHERE session_id = :id LIMIT 1;";
		
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( [ ':id' => $id ] ) ) {
		return true;
	}
	return false;
}
	
/**
 *  Garbage collection
 */
function sessionGC( $max ) {
	$sql	= 
	"DELETE FROM sessions WHERE 
		strftime( '%s', 'now' ) - 
		strftime( '%s', updated ) > :gc;";
	
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( [ ':gc' => $max ] ) ) {
		return true;
	}
	return false;
}
	
/**
 *  Read session data by ID
 */
function sessionRead( $id ) {
	$sql	= 
	"SELECT session_data FROM sessions 
		WHERE session_id = :id LIMIT 1;";
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( [ ':id' => $id ] ) ) {
		return $stm->fetchColumn();
	}
	
	return '';
}

/**
 *  Store session data
 */
function sessionWrite( $id, $data ) {
	$sql	= 
	"INSERT OR REPLACE INTO ( session_id, session_data )
		VALUES( :id, :data );";
	
	$db	= getDb();
	$stm	= $db->prepare( $sql );
	
	if ( $stm->execute( [ 
		':id'		=> $id, 
		':data'	=> $data 
	] ) ) {
		return true;
	}
	return false;
}


/**
 *  Reset authenticated user data types for processing
 */
function formatAuthUser( $user ) {
	return [
		'id'		=> ( int ) ( $user['id'] ?? 0 ),
		'status'	=> ( int ) ( $user['status'] ?? 0 ),
		'name'		= $user['name'] ?? '',
		'auth'		= $user['auth'] ?? ''
	];
}
	
/**
 *  Check user authentication session
 */
function authUser() : array {
	sessionCheck();
	
	if ( 
		empty( $_SESSION['user'] ) || 
		!\is_array(  $_SESSION['user'] ) 
	) { 
		// Session was empty? Check cookie lookup
		$cookie	= $_COOKIE['user'] ?? '';
		if ( empty( $cookie ) ) {
			return [];
		}
		// Sane defaults
		if ( mb_strlen( $cookie, '8bit' ) > 255 ) {
			return [];
		}
		$user	= findCookie( pacify( $cookie ) );
		
		if ( empty( $user ) ) {
			return [];
		}
		
		// Fetched results must be 6 rows
		if ( count( $user ) !== 6 ) { return []; }
		
		// User found, apply authorization
		setAuth( $user );
		return $_SESSION['user'];
		
	} else {
		// Fetched results must be a 4-item array
		$user		= $_SESSION['user'];
		if ( count( $user ) !== 4 ) { 
			$_SESSION['user']	= '';
			return []; 
		}
	}
	
	// Reset data types
	$user			= formatAuthUser( $user );
	
	// Check session against current browser signature
	$sig			= signature();
	$hash			= 
	\hash( 'tiger160,4', $sig . $user['name'] );
	
	// Check browser signature against auth token
	if ( 0 != \strcmp( 
		( string ) $user['auth'], $hash 
	) ) { return []; }
		
	return $user;
}
	
/**
 *  Apply user auth session and save the current signature hash
 */
function setAuth( array $user ) {
	sessionCheck();
	
	// Reset data types
	$user			= formatAuthUser( $user );
	
	$sig			= signature();
	$hash			= 
	\hash( 'tiger160,4', $sig . $user['name'] );
	
	
	$_SESSION['user']	= [
		'id'		=> $user['id'],
		'status'	=> $user['status'],
		'name'		=> $user['name'],
		'auth'		=> $hash
	];
	
	// Set cookie lookup code
	\setcookie( 'user', $user['lookup'], 1, COOKIE_PATH );
}
	
/**
 *  End user session
 */
function endAuth() {
	sessionCheck( true );
	\setcookie( 'user', '', time() - COOKIE_EXP, COOKIE_PATH );
}
	
/**
 *  Session owner and staleness marker
 *  
 *  @link https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions
 */
function sessionCanary( string $visit = '' ) {
	$_SESSION['canary'] = 
	[
		'exp'		=> time() + SESSION_EXP,
		'visit'	=> 
		empty( $visit ) ? 
			\bin2hex( \random_bytes( 12 ) ) : $visit
	];
}
	
/**
 *  Check session staleness
 */
function sessionCheck( bool $reset = false ) {
	setSessionHandler();
	session( $reset );
	
	if ( empty( $_SESSION['canary'] ) ) {
		sessionCanary();
		return;
	}
	
	if ( time() > ( int ) $_SESSION['canary']['exp'] ) {
		$visit = $_SESSION['canary']['visit'];
		\session_regenerate_id( true );
		sessionCanary( $visit );
	}
}

/**
 *  End current session activity
 */
function cleanSession() {
	if ( \session_status() === \PHP_SESSION_ACTIVE ) {
		\session_unset();
		\session_destroy();
		\session_write_close();
	}
}

/**
 *  Initiate a session if it doesn't already exist
 *  Optionally reset and destroy session data
 */
function session( $reset = false ) {
	if ( \session_status() === \PHP_SESSION_ACTIVE && !$reset ) {
		return;
	}
	
	if ( \session_status() != \PHP_SESSION_ACTIVE ) {
		\session_name( SESSION_NAME );
		\session_start();
	}
	if ( $reset ) {
		\session_regenerate_id( true );
		foreach ( \array_keys( $_SESSION ) as $k ) {
			unset( $_SESSION[$k] );
		}
	}
}


/**
 *  Verify anti-cross-site request forgery token
 */
function checkCsrf(
	string		$form,
	string		$csrf
) : bool {
	if ( empty( $_SESSION['form_' . $form ] ) ) {
		return false;
	}
	
	$hex	= $_SESSION['form_' . $form ];
	$hash	= \hash( CSRF_HASH, $form . $hex );
	
	return \hash_equals( $csrf, $hash );
}
	
/**
 *  Generate anti-cross-site request forgery token
 */
function getCsrf( string $form ) : string {
	$hex				= 
		\bin2hex( \random_bytes( CSRF_BYTES ) );
	$_SESSION['form_' . $form ]	= $hex;
	
	return \hash( CSRF_HASH, $form . $hex );
}



/**
 *  HTTP Response
 */

/**
 *  Safety headers
 *  
 *  @param string	$chk	Content checksum
 *  @param bool		$send	CSP Send Content Security Policy header
 *  @param bool		$type	Send content type (html)
 */
function preamble(
	string	$chk		= '', 
	bool	$send_csp	= true,
	bool	$send_type	= true
) {
	$conf	= settings();
	\header_remove( 'X-Powered-By' );
	
	if ( $send_type ) {
		\header( 
			'Content-Type: text/html; charset=utf-8', 
			true 
		);
	}
	
	\header( 'X-XSS-Protection: 1; mode=block', true );
	\header( 'X-Content-Type-Options: nosniff', true );
	
	// Frames should be handled via the CSP
	\header( 'X-Frame-Options: deny', true );
	
	// Check if TLS is forced or if the client requested HTTPS
	$tls	= $conf['force_tls'] ?? false;
	if ( $tls || isSecure() ) {
		\header(
			'Strict-Transport-Security: ' . 
			'max-age=31536000; includeSubdomains;', 
			true
		);
	}
	
	// If sending CSP and content checksum isn't used
	if ( $send_csp ) {
		$cjp = $conf['csp'] ?? DEFAULT_CSP;
		$csp = 'Content-Security-Policy: ';
		foreach ( $cjp as $k => $v ) {
			$csp .= "$k $v;";
		}
		\header( \rtrim( $csp, ';' ), true );
	
	// Content checksum used
	} elseif ( !empty( $chk ) ) {
		\header( 
			"Content-Security-Policy: default-src " .
			"'self' '{$chk}'", 
			true
		);
	}
}

/**
 *  Create HTTP status code message
 */
function httpCode(
	string		$proto,
	int		$code
) {
	switch ( $code ) {
		case 100:
			$msg = 'Continue';
			break;
			
		case 101:
			$msg = 'Switching Protocols';
			break;
			
		case 200:
			$msg = 'OK';
			break;
			
		case 201:
			$msg = 'Created';
			break;
			
		case 202:
			$msg = 'Accepted';
			break;
			
		case 203:
			$msg = 'Non-Authoritative Information';
			break;
			
		case 204:
			$msg = 'No Content';
			break;
			
		case 205:
			$msg = 'Reset Content';
			break;
			
		case 206:
			$msg = 'Partial Content';
			break;
			
		case 300:
			$msg = 'Multiple Choices';
			break;
			
		case 301:
			$msg = 'Moved Permanently';
			break;
			
		case 302:
			$msg = 'Moved Temporarily';
			break;
			
		case 303:
			$msg = 'See Other';
			break;
			
		case 304:
			$msg = 'Not Modified';
			break;
			
		case 305:
			$msg = 'Use Proxy';
			break;
			
		case 400:
			$msg = 'Bad Request';
			break;
			
		case 401:
			$msg = 'Unauthorized';
			break;
			
		case 402:
			$msg = 'Payment Required';
			break;
			
		case 403:
			$msg = 'Forbidden';
			break;
			
		case 404:
			$msg = 'Not Found';
			break;
				
		case 405:
			$msg = 'Method Not Allowed';
			break;
			
		case 406:
			$msg = 'Not Acceptable';
			break;
			
		case 407:
			$msg = 'Proxy Authentication Required';
			break;
			
		case 408:
			$msg = 'Request Time-out';
			break;
			
		case 409:
			$msg = 'Conflict';
			break;
			
		case 410:
			$msg = 'Gone';
			break;
			
		case 411:
			$msg = 'Length Required';
			break;
			
		case 412:
			$msg = 'Precondition Failed';
			break;
			
		case 413:
			$msg = 'Request Entity Too Large';
			break;
			
		case 414:
			$msg = 'Request-URI Too Large';
			break;
			
		case 415:
			$msg = 'Unsupported Media Type';
			break;
			
		case 500:
			$msg = 'Internal Server Error';
			break;
			
		case 501:
			$msg = 'Not Implemented';
			break;
			
		case 502:
			$msg = 'Bad Gateway';
			break;
			
		case 503:
			$msg = 'Service Unavailable';
			break;
			
		case 504:
			$msg = 'Gateway Time-out';
			break;
			
		case 505:
			$msg = 'HTTP Version not supported';
			break;
			
		default:
			die( 'Unknown status code "' . $code . '"' );
	}
	
	\header( $proto . ' ' . $code . ' ' . $msg, true );
}

/**
 *  Current website with protocol prefix
 *  
 *  @return string
 */
function website() {
	$url	= isSecure() ? 'https://' : 'http://';
	return $url . $_SERVER['SERVER_NAME'];
}

/**
 *  Current full URI including website
 */
function fullURI() {
	return website() . $_SERVER['REQUEST_URI'];
}

/**
 *  Print headers, content, and end execution
 *  
 *  @param int		$code		HTTP Status code
 *  @param string	$content	Page data to send to client
 *  @param bool		$cache		Cache page data if true
 */
function send(
	int		$code		= 200,
	string 	$content	= '',
	bool		$cache		= false
) {
	$proto	= $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
	httpCode( $proto, $code );
	preamble();
	
	echo $content;
	
	// Also save to cache?
	if ( $cache ) {
		saveCache( fullURI(), $content );
	}
	
	// End
	die();
}

/**
 *  Login path redirect helper
 *  
 *  @param array	$conf		Configuration settings
 *  @param string	$redir		Relative path to prepend login
 */
function sendLogin( array $conf, string $redir = '' ) {
	$path = getRoot( $conf ) . 'login/';
	
	// Send redirect with current website prefixed
	redirect( 401, website() . $path . $redir );
}

/**
 *  Multi-page redirect helper
 *  
 *  @param array	$conf		Configuration settings
 *  @param string	$page		Relative path to redirect
 *  @param int		$code		HTTP Status code
 */
function sendPage( 
	array		$conf,
	string		$page		= '',
	int		$code		= 200
) {
	$page = getRoot( $conf ) . $page;
	
	// Send redirect with requested code
	redirect( $code, website() . $page );
}

/**
 *  Redirect with status code
 *  
 *  @param int		$code		HTTP Status code
 *  @param string	$path		Full URL to from current domain
 */
function redirect(
	int		$code		= 200,
	string		$path		= ''
) {
	\ob_end_clean();
	$conf	= settings();
	
	$url	= parse_url( $path );
	$host	= $url['host'] ?? '';
	
	// Arbitrary redirect attempt?
	if ( $host != $_SERVER['SERVER_NAME'] ) {
		die( 'Invalid URL' );
	}
	
	// Get get current path
	$path	= getRoot( $conf ) . $url['path'] ?? '';
	
	// Directory traversal
	$path	= \preg_replace( '/\.{2,}', '.', $path );
	
	if ( false === \headers_sent() ) {
		\header( 'Location: ' . $path, true, $code );
		die();
	}
	$html = "<html>" . 
	"<head><meta http-equiv=\"refresh\" content=\"0;url=\"$path\"></head>".
	"<body><a href=\"$path\">continue</a></body></html>";
	
	die( $html );
}


/**
 *  Get the configured theme
 * 
 *  @param array	$conf		Configuration settings
 *  @param bool		$feed		Set true if this is a feed page
 *  @param bool		$admin		Set true if this is an admin page
 *  
 *  @return string
 */
function getTheme(
	array		$conf,
	bool		$feed		= false,
	bool		$admin		= false
) {
	static $theme;
	if ( $admin ) {
		return getAdminTheme();
	}
	if ( $feed ) {
		return THEME_DIR . 'feed/';
	}
	
	// Already loaded?
	if ( isset( $theme ) ) {
		return $theme;
	}
	$theme		= THEME_DIR . $conf['theme'] . '/';
	return $theme;
}

/**
 *  Get the configured theme
 *  
 *  @return string
 */
function getAdminTheme() {
	static $mtheme;
	
	// Already loaded?
	if ( isset( $mtheme ) ) {
		return $mtheme;
	}
	
	$mtheme	= THEME_DIR . 'manage/';
	return $mtheme;
}

/**
 *  Get formatting template
 *  
 *  @param array	$conf		Configuration settings
 *  @param string	$name		HTML template name
 *  @param bool		$feed		Set true if this is a feed page
 *  @param bool		$admin		Set true if this is an admin page
 *  @return string
 */
function getTemplate(
	array		$conf,
	string		$name,
	bool		$feed	= false,
	bool		$admin	= false
) {
	if ( $admin ) {
		return getAdminTheme() . $name . '.html';
	}
	return getTheme( $conf, $feed, $admin ) . $name . '.html';
}

/**
 *  Generate timezone select
 *  
 *  @link https://stackoverflow.com/a/17355238
 *  
 *  @param string	$selected	Currently set timezone
 *  @return string
 */
function timezoneSelect( string $selected ) : string {
	$zones	= 
	\DateTimeZone::listIdentifiers( \DateTimeZone::ALL );
	
	$offsets	= [];
	foreach ( $zones as $tz ) {
		$t		= new \DateTimeZone( $tz );
		$offsets[$t]	= $tz->getOffset( new \DateTime );
	}
	
	\asort( $offsets );
	$out		= 
	'<select name="timezone" id="timezone" required>';
	
	foreach ( $offsets as $tz => $offset ) {
		$prefix	= ( $offset < 0 ) ? '-' : '+';
		$format	= \gmdate( 'H:i', \abs( $offset ) );
		$nice		= "UTC${prefix}${format}";
		$out		.=
		$tz == $selected ? 
		"<option value=\"{$tz}\" selected>${nice} $tz</option>" :
		"<option value=\"{$tz}\">${nice} $tz</option>";
	}
	
	return $out . '</select>';
}

/**
 *  Site root
 *  
 *  @return string
 */
function getRoot( $conf ) {
	return \rtrim( $conf['webroot'] ?? '',  '/' ) . '/';
}

/**
 *  Format post results with given template parameters
 *  
 *  @param array	$conf		Configuration settings
 *  @param array	$results	List of posts to format
 *  @param bool		$feed		Set true if this is a feed page
 *  @param bool		$admin		Set true if this is an admin page
 *  @return string
 */
function formatPosts( $conf, $results, $feed, $admin ) {
	$htpl			= 
	getTemplate( $conf, 'postfrag', $feed, $admin );
	
	$atpl			= 
	getTemplate( $conf, 'authorfrag', $feed, $admin );
	
	$out			= '';
	$root			= getRoot( $conf );
	
	foreach ( $results as $k => $v ) {
		// Set relative post edit path
		$v['post_edit']	= $root . $v['post_edit'];
		
		$out			.= 
		formatPost( $conf, $htpl, $atpl, $v );
	}
	
	return $out;
}

/**
 *  Format individual post
 *  
 *  @param array	$ptpl		Post template
 *  @param string	$atpl		Author template fragment
 *  @param array	$post		Post row from database
 *  @return string
 */
function formatPost( $conf, $htpl, $atpl, $post ) {
	$root			= getRoot( $conf );
	// Format author details
	$post['author']	= 
	\strtr( $atpl, [ 
		'{name}'	=> $post['author'],
		'{parmalink}'	=> \rtrim( $root, '/' ) . 
					$post['authorlink']
	] );
	
	// Parse content into HTML if full page requested
	$post['body']		=> 
		$conf['show_full'] ? html( $post['body'] ) : '';
	
	return \strtr( $htpl, $post );
}

/**
 *  Next/Previous navigation links
 *  
 *  @param array	$conf		Configuration settings
 *  @param int		$page		Current pagination index
 *  @param int		$count		Number of records in this index
 *  @return string
 */
function navPage( $conf, $page, $count ) {
	$pm	= $page - 1;
	$pp	= $page + 1;
	$lm	= $conf['page_limit'];
	$root	= getRoot( $conf );
	
	$out	= '';
	
	// If we're past the first page, add previous page link
	if ( $pm > 0 ) {
		$out .= 
		\strtr( NAV_TPL, [
			'{url}' 	=> $root . 'page' . $pm,
			'{page}'	=> PREV_PAGE
		] );
	}
	
	// If we're at the page limit, add the next page link
	if ( $count >= $lm ) {
		$out .= 
		\strtr( NAV_TPL, [
			'{url}'	=> $root . 'page' . $pp,
			'{page}'	=> NEXT_PAGE
		] );
	}
	
	return $out;
}

/**
 *  Format links to neighboring pages
 *  
 *  @param array	$conf		Configuration settings
 *  @param array	$siblings	Posts to create link details
 *  @return string
 */
function siblingPages( $conf, array $siblings ) {
	$root	= rtrim( getRoot( $conf ), '/' );
	$out	= '';
	foreach ( $siblings as $s ) {
		$out .= \strtr( NAV_TPL [
			'{url}'	=> $root . $s['permalink'],
			'{page}'	=> $s['title']
		] );
	}
	
	return $out;
}


/**
 *  List / Index / Archive page format helper
 */
function indexView(
	string		$theme,
	array		$conf,
	array		$results,
	int		$page		= 1,
	bool		$feed		= false,
	bool		$admin		= false,
	string		$search	= ''
) {
	$root		= getRoot( $conf );
	$content	= 
	\strtr( $theme, [
		'{theme}'		=> getTheme( $conf, $feed, $admin ),
		'{date_gen}'		=> rfcDate(),
		'{page_title}'	=> $conf['title'],
		'{tagline}'		=> $conf['tagline'],
		'{home}'		=> $root,
		'{manage}'		=> $root . 'manage',
		'{search}'		=> $search,
		'{copyright}'		=> $conf['copyright'],
		'{page_body}'		=> 
			formatPosts( $conf, $results, $feed, $admin ),
		'{navpages}'		=> 
			navPage( $conf, $page, count( $results ) )
	] );
	
	return parseLang( $content );
}




/**
 *  Page routing
 */

/**
 *  Paths are sent in bare. Make them suitable for matching.
 *  
 *  @param string $route URL path in plain format
 *  @return string Route in regex format
 */
function cleanRoute( $k, $v, $route ) {
	$route	= str_replace( $k, $v, $route );
	$regex	= str_replace( '.', '\.', $route );
	return '@^/' . $route . '/?$@i';
}

/**
 *  Filter path parameters to get rid of numeric indexes
 */
function filterParams( $params ) {
	\array_shift( $params );
	return \array_filter( 
		$params, 
		function( $k ) {
			return \is_string( $k );
		}, \ARRAY_FILTER_USE_KEY 
	);
}

/**
 *  Route the current path according to the specified callback map
 */
function route( array $routes, array $markers ) {
	// Process request method for valid types
	$verb		= strtolower( $_SERVER['REQUEST_METHOD'] );
	switch( $verb ) {
		// Check cache
		case 'get':
			$data = getCache( fullURI() );
			if ( !empty( $data ) ) {
				send( 200, $data );
			}
			break;
		
		// Will need processing, continue
		case 'post':
			break;
		
		// No content sent
		case 'head':
			send( 200 );
		
		// Nothing else implemented
		default:
			send( 501 );
	}
	
	// Request path
	$path		= $_SERVER['REQUEST_URI'];
	
	$k		= array_keys( $markers );
	$v		= array_values( $markers );
	$found		= false;
	
	foreach ( $routes as $map ) {
		if ( $map[0] != $verb ) {
			continue;
		}
		$rx = cleanRoute( $k, $v, $map[1] );
		if ( \preg_match( $rx, $path, $params ) ) {
			$found	= true;
			if ( \is_callable( $map[2] ) ) {
				$params		= filterParams( $params );
				$params['method']	= $verb;
				\call_user_func( $map[2], $params );
				break;
			}
		}
	}
	
	if ( !$found ) {
		notfound();
	}
	
	die();
}




/**
 *  Routes
 */


/**
 *  Home / Index page / RSS feed route 
 */
function homepage( array $route, bool $feed = false ) {
	$conf		= settings();
	$data		= 
	\filter_var_array( $route, [
		'page'	=> [
			'filter'	=> \FILTER_VALIDATE_INT,
			'options'	=> [ 
				'min_range'	=> 1,
				'max_range'	=> 500,
				'default'	=> 1
			]
		]
	] );
	
	$results	= findPostsByIndex( $data );
	if ( empty( $results ) ) {
		send( 404, MSG_NOTFOUND );
	}
	
	$theme		= getTemplate( $conf, 'home', $feed, false );
	$page		= ( int ) ( $data['page'] ?? 1 );
	
	// First page? Send homepage with cache
	if ( $page == 1 ) {
		send( 200, 
			indexView( $theme, $conf, $results, $page, $feed ), 
			true 
		);
	}
	send( 200, indexView( $theme, $conf, $results, $page, $feed ) );
}

/**
 *  View posts by date archive
 */
function archive( array $route ) {
	$config	= settings();
	$year		= ( int ) \date( 'Y', time() );
	$data		= 
	\filter_var_array(
		$route, 
		[
			'page'	=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> 1,
					'max_range'	=> 500,
					'default'	=> 1
				]
			],
			'year'	=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> YEAR_END,
					'max_range'	=> $year,
					'default'	=> $year
				]
			],
			'month'=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> 1,
					'max_range'	=> 12,
					'default'	=> 0
				]
			],
			'day'=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> 1,
					'max_range'	=> 31,
					'default'	=> 0
				]
			]
		]
	);
	
	$results	= findPostsArchive( $data );
	if ( empty( $results ) ) {
		send( 404, MSG_NOTFOUND );
	}
	
	$theme		= getTemplate( $conf, 'home', $feed, false );
	$page		= ( int ) ( $data['page'] ?? 1 );
	send( 200, indexView( $theme, $conf, $results, $page ) );
}

/**
 *  Syndication feed
 */
function feed( array $route ) {
	homepage( $route, true );
}

/**
 *  Handle showing single page
 */
function viewPage( array $route ) {
	$config	= settings();
	$data		= 
	\filter_var_array(
		$route, 
		[
			'id'	=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> 1,
					'default'	=> 0
				]
			],
			'year'	=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> YEAR_END,
					'default'	=> 0
				]
			],
			'month'=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> 1,
					'max_range'	=> 12,
					'default'	=> 1
				]
			],
			'day'=> [
				'filter'	=> \FILTER_VALIDATE_INT,
				'options'	=> [ 
					'min_range'	=> 1,
					'max_range'	=> 31,
					'default'	=> 0
				]
			],
			'slug'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		]
	);
	
	$dates		= enforceDates( $data );
	if ( empty( $data['id'] ) ) {
		$link		= 
		'/' . \implode( '/', $dates ) . '/' . $data['slug'] ?? '';
		
		$post		= findPostByPermalink( $link );
	} else {
		if ( empty( $data['slug'] ) ) {
			$post	= 
			findPostById( ( int ) $data['id'] );
		} else {
			$post	= 
			findPostByIdSlug( 
				( int ) $data['id'], 
				$data['slug']
			);
		}
	}
	
	if ( empty( $post ) ) {
		send( 404, MSG_NOTFOUND );
	}
	 
	$htpl			= getTemplate( $conf, 'post' );
	$root			= getRoot( $conf );
	
	
	$tpl			= [
		'{site_title}'=> $post['title'] . ' - ' . $conf['title'],
		'{page_title}'=> $conf['title'],
		'{tagline}'	=> $conf['tagline'],
		'{root}'	=> $root,
		'{page_url}'	=> $root,
		'{manage}'	=> $root . 'manage',
		'{theme}'	=> getTheme( $conf ) . '/',
		'{post_edit}' => $root . $post['post_edit']
	];
	
	// Has copyright feature
	if ( tplHas( $htpl, 'copyright' ) ) {
		'{copyright}'	=> html( $conf['copyright'] );
	} 
	
	// Has author feature
	if ( tplHas( $htpl, 'author' ) ) {
		// Apply author template
		$atpl			= getTemplate( $conf, 'authorfrag' );
		$tpl['{author}']	= 
		\strtr( $atpl, [ 
			'{name}'	=> $post['author'],
			'{parmalink}'	=> \rtrim( $root, '/' ) . 
					$post['authorlink']
		] );
	}
	
	// Filter and display content
	if ( tplHas( $htpl, 'body' ) ) {
		$tpl['{body}']	=> html( $post['body'] );
	}
	
	// Has siblings feature
	if ( tplHas( $htpl, 'siblings' ) ) {
		// Find neighboring pages
		$siblings		= 
		findPostSiblings( 
			$post['prev_id'] ?? 0,
			$post['next_id'] ?? 0
		);
		
		// Have neighbors?
		if ( count( $siblings ) ) {
			$post['{siblings}']	= 
				siblingPages( $conf, $siblings );
		} else {
			$post['{siblings}']	= '';
		}
	}
	
	$htpl	= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ), true );
}

/**
 *  TODO: Tag browsing
 */
function viewTag( array $route ) {
	
}

/**
 *  Searching pages
 */
function search( array $route ) {
	$data		= 
	\filter_var_array( $route, [
		'page'	=> [
			'filter'	=> \FILTER_VALIDATE_INT,
			'options'	=> [ 
				'min_range'	=> 1,
				'max_range'	=> 500,
				'default'	=> 1
			]
		],
		'search' => \FILTER_SANITIZE_FULL_SPECIAL_CHARS
	] );
	
	$search	= $data['search'];
	$page		= ( int ) ( $data['page'] ?? 1 );
	$results	= findPostBySearch( $page, $search );
	
	if ( empty( $results ) ) {
		send( 404, MSG_NOTFOUND );
	}
	
	$theme		= getTemplate( $conf, 'home', $feed, false );
	send( 200, indexView( 
		$theme, $conf, $results, $page, false, false, $search
	) );
}

/**
 *  Show new page form
 */
function newPage( array $route ) {
	$user		= authUser();
	
	if ( empty( $user ) ) {
		send( 403, MSG_LOGIN );
	}
	
	$conf			= settings();
	
	// Load post template and get root
	$htpl			= getTemplate( $conf, 'newpost', false, true );
	$root			= getRoot( $conf );
	
	$tpl			= [
		'{theme}'	=> getAdminTheme(),
		'{action}'	=> $root . 'manage',
		'{post_list}'	=> $root,
		'{help}'	=> $root . 'manage/help.html',
		'{settings}'	=> $root . 'manage/settings',
		'{id}'		=> 0,
		'{slug}'	=> '',
		'{published}'	=> '',
		'{body}'	=> ''
	];
	
	$htpl	= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ) );
}

/**
 * Handle new page creation
 */
function doNewPage( array $route ) {
	$user		= authUser();
	if ( empty( $user ) ) {
		send( 403, MSG_LOGIN );
	}
	
	$filter 	= [ 
		'parent'	=> [
			'filter'	=> \FILTER_VALIDATE_INT
			'options'	=> [
				'min_range'	=> 1, 
				'default'	=> 0
			]
		],
		'csrf'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'title'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'title'
		],
		'slug'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'body'		=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'pacify'
		],
		'summary'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		"publish"	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'datetime'
		],
		'preview'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'tags'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'taglist'
		]
	];
	
	postForm( $filter, $user );
}

/**
 *  Show page editing form
 */
function editPage( array $route ) {
	$data		= 
	\filter_var_array( $route,  [
			'id'		=> [
			'filter'	=> \FILTER_VALIDATE_INT
			'options'	=> [
				'min_range'	=> 1, 
				'default'	=> 0
			]
		]
	] );
	
	$id		= ( int ) ( $data['id'] ?? 0 );
	if ( empty( $id ) ) {
		send( 404, MSG_NOTFOUND );
	}
	
	// Check if post exists
	$preview	= findPreviewById( $id );
	if ( empty( $post ) ) {
		send( 404, MSG_NOTFOUND );
	}
	
	// Check authorization
	$user		= authUser();
	$conf		= settings();
	
	if ( empty( $user ) ) {
		sendLogin( $conf, 'manage/edit/' . $post['id'] );
	}
	
	// Load full post details
	$post		= findPostById( $id );
	
	// Load post template and get Root
	$htpl		= getTemplate( $conf, 'editpost', false, true );
	$root		= getRoot( $conf );
	
	// Fill template placeholders
	$tpl			= [
		'{theme}'	=> getAdminTheme(),
		'{action}'	=> $root . 'manage/edit/' . $post['id'],
		'{post_list}'	=> $root,
		'{help}'	=> $root . 'manage/help.html',
		'{settings}'	=> $root . 'manage/settings',
		'{id}'		=> $post['id'],
		'{slug}'	=> $post['slug'],
		'{published}'	=> rfcDate( $post['published'] ),
		'{body}'	=> pacify( $post['body'] ),
		'{delete}'	= 
		getTemplate( $conf, 'deletefrag', false, true )
	];
	
	$htpl	= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ) );
}

/**
 *  Handle page editing
 */
function doEditPage( array $route ) {
	$user		= authUser();
	$conf		= settings();
	if ( empty( $user ) ) {
		sendLogin( $conf, '' );
	}
	
	$filter	= 
	[ 
		'id'		=> [
			'filter'	=> \FILTER_VALIDATE_INT
			'options'	=> [
				'min_range'	=> 1, 
				'default'	=> 0
			]
		],
		'csrf'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'title'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'title'
		],
		'slug'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'body'		=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'pacify'
		],
		'summary'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		"publish"	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'datetime'
		],
		'tags'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'taglist'
		],
		'preview'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'delete'	=> [
			'filter'	=> \FILTER_VALIDATE_BOOLEAN,
			'options'	=> [
				'default'	=> false
			]
		],
		'delconf'	=> [
			'filter'	=> \FILTER_VALIDATE_BOOLEAN,
			'options'	=> [
				'default'	=> false
			]
		]
	];
	
	postForm( $filter, $user );
}

/**
 *  View user profile page
 */
function viewProfile( array $route ) {
	$user		= authUser();
	$conf		= settings();
	
	// User id from route
	$id		= ( int ) $route['id'];
	$name		= $route['user'] ?? '';
	
	// Check if user exists
	if ( empty( $name ) ) {
		$data		= findUserById( $id );
	} else {
		$data		= findUserByUsername( $name )
	}
	
	if ( empty( $data ) ) {
		notfound();
	}
	
	// If viewing another user or this is an editor, send form
	if ( 
		( $id == $user['id'] )	||
		( $user['status'] >= AUTH_EDITOR )
	) {
		$htpl		= getTemplate( $conf, 'bioedit' );
	
	// If not, send public profile
	} else {
		$htpl		= getTemplate( $conf, 'bio' );
	}
	
	$username	= username( $data['username'] );
	$display	= username( $data['display'] );
	
	// Template basics
	$root		= getRoot( $conf );
	$tpl		= [
		'{page_title}'=> $conf['title'],
		'{root}'	=> $root,
		'{username}'	=> $username,
		'{display}'	=> $display,
		'{theme}'	=> getTheme( $conf )
	];
	
	// TODO: User status editor
	if ( $user['status'] >= AUTH_EDITOR ) {
		if ( tplHas( $htpl, 'ustatus' ) ) {
			//
		}
	}
	
	// Form view
	if ( 
		tplHas( $htpl, 'action' )	&& 
		tplHas( $htpl, 'csrf' )
	) {
		$tpl['{csrf}']	= getCsrf( 'profile' );
		$tpl['{bio}']		= $data['bio'];
		$tpl['{action}']	= 
			$root . 'profile/' . $id . '/' . $username;
	// HTML view
	} else {
		$tpl['{bio}']		= html( $data['bio'] );
	}
	
	$htpl	= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ) );
}

/**
 *  Changing user profile page
 */
function doProfile( array $route ) {
	$user		= authUser();
	$conf		= settings();
	if ( empty( $user ) ) {
		sendLogin( $conf, 'profile' );
	}
	
	// User id from route
	$id		= ( int ) $route['id'];
	
	// If editing another user and this isn't an editor
	if ( 
		( $id != $user['id'] )		&&
		( $user['status'] < AUTH_EDITOR )
	) {
		send( 403, MSG_DENIED );
	}
	
	$form		= 
	\filter_input_array( \INPUT_POST, [
		'csrf'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'id'		=> [
			'filter'	=> \FILTER_VALIDATE_INT
			'options'	=> [
				'min_range'	=> 1, 
				'default'	=> 0
			]
		],
		'display'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'username'
		],
		'status'	=> [
			'filter'	=> \FILTER_VALIDATE_INT,
			'options'	=> [
				'min_range'	=> AUTH_BANNED,
				'max_range'	=> AUTH_ADMIN,
				'default'	=> AUTH_USER
			]
		],
		'bio'		=> \FILTER_UNSAFE_RAW
	] );
	
	// Add status to changes if user is an editor
	if ( $user['status'] < AUTH_EDITOR ) {
		unset( $form['status'] );
	}
	
	saveUser( $form );
	sendPage( $conf, '', 202 );
}

/**
 *  Handle logout
 */
function logout( array $route ) {
	endAuth();
	redirect( 205, website() );
}

/**
 *  Show login page
 */
function viewLogin( array $route ) {
	$conf		= settings();
	$htpl		= getTemplate( $conf, 'login' );
	$root		= getRoot( $conf );
	
	$tpl		= [
		'{page_title}'=> $conf['title'],
		'{root}'	=> $root,
		'{theme}'	=> getTheme( $conf ),
		'{csrf}'	=> getCsrf( 'login' ),
		'{action}'	=> $root . 'login'
	];
	
	$htpl	= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ) );
}

/**
 *  Handle login
 */
function doLogin( array $route ) {
	$form		= 
	\filter_input_array( \INPUT_POST, [
		'csrf'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'redir'	=> [
			'fliter'	=> \FILTER_VALIDATE_URL,
			'flags'	=> 
				\FILTER_FLAG_SCHEME_REQUIRED | 
				\FILTER_FLAG_HOST_REQUIRED |
				\FILTER_FLAG_PATH_REQUIRED
		],
		'username'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'username'
		],
		'password'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'password'
		]
	] );
	
	$csrf = checkCsrf( 'login', $form['csrf'] ?? '' );
	if ( !$csrf ) {
		send( 403, MSG_FORMEXP );
	}
	
	if (
		empty( $form['password'] )	|| 
		empty( $form['username'] ) 
	) {
		send( 401, MSG_LOGINERROR );
	}
	
	$user	= findUserByUsername( $form['username'] );
	if ( empty( $user ) ) {
		send( 401, MSG_LOGINERROR );
	}
	
	// Load configuration
	$conf		= settings();
	$root		= getRoot( $conf );
	
	// Password matches?
	if ( verifyPassword( 
		$form['password'], $user['password'] 
	) ) {
		// Re-save password if the hash is obsolete
		if ( passNeedsRehash( $user['password'] ) ) {
			savePassword( $user['id'], $form['password'] );
		}
		
		// Send to previously requested path, if any
		sendPage( $conf, $form['redir'] ?? '', 202 );
	}
	
	// Password didn't match resend login path with redirect
	sendLogin( $conf, $form['redir'] ?? '' );
}

/**
 *  Send registration page
 */
function viewRegister( array $route ) {
	$conf		= settings();
	$reg		= $conf['allow_register'] ?? false;
	if ( !$reg ) {
		send( 403, MSG_REGCLOSED );
	}
	$root		= getRoot( $conf );
	$htpl		= getTemplate( $conf, 'register' );
	$tpl		= [
		'{page_title}'=> $conf['title'],
		'{root}'	=> $root,
		'{theme}'	=> getTheme( $conf ),
		'{csrf}'	=> getCsrf( 'register' ),
		'{action}'	=> $root. 'register'
	];
	
	$htpl		= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ) );
}

/**
 *  TODO: Handle registration
 */
function doRegister( array $route ) {
	$reg		= $config['allow_register'] ?? false;
	if ( !$reg ) {
		send( 403, MSG_REGCLOSED );
	}
	
	$form		= 
	\filter_input_array( \INPUT_POST, [
		'csrf'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'username'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'username'
		],
		'password'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'password'
		],
		'password2'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'password'
		]
	]);
	
	$data		= \filter_input_array( \INPUT_POST, $filter );
	
	// Check for form expiration
	$csrf = checkCsrf( 'register', $form['csrf'] ?? '' );
	if ( !$csrf ) {
		send( 403, MSG_FORMEXP );
	}
	
	// Empty check
	if ( 
		empty( $form['username'] ) || 
		empty( $form['password'] )
	) {
		
	}
	
	// Passwords must match
	if ( 0 !== strcmp( $form['password'], $form['password2'] ) ) {
		send( 401, MSG_PASSMATCH );
	}
	
	$data	= saveUser( [
		'username'	=> $form['username'],
		'password'	=> $form['password'],
		'status'	=> AUTH_USER		// Base status
	] );
	
	// Once registration is complete, send to login with redirect
	sendLogin( $conf, 'profile/' . $data['id'] . '/' . $data['username'] );
}

/**
 *  Show password change page
 */
function viewChPass( array $route ) {
	$user		= authUser();
	$conf		= settings();
	if ( empty( $user ) ) {
		sendLogin( $conf, 'changepass' );
	}
	
	$root		= getRoot( $conf );
	$htpl		= getTemplate( $conf, 'login' );
	$conf		= settings();
	$tpl		= [
		'{page_title}'=> $conf['title'],
		'{root}'	=> $root,
		'{theme}'	=> getTheme( $conf ),
		'{csrf}'	=> getCsrf( 'chpassword' ),
		'{action}'	=> $root . 'changepass'
	];
	
	$htpl		= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ) );
}

/**
 *  Handle password change
 */
function doChPass( array $route ) {
	$user		= authUser();
	$conf		= settings();
	if ( empty( $user ) ) {
		sendLogin( $conf, 'changepass' );
	}
	
	$form		= \filter_input_array( \INPUT_POST, [
		'csrf'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'password'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'password'
		],
		'password2'	=> [
			'filter'	=> \FILTER_CALLBACK,
			'options'	=> 'password'
		]
	] );
	
	// Check for form expiration
	$csrf = checkCsrf( 'chpassword', $form['csrf'] ?? '' );
	if ( !$csrf ) {
		send( 403, MSG_FORMEXP );
	}
	
	// Something was missing
	if (
		empty( $data['password'] ) 	||
		empty( $data['password2'] ) 
	) {
		send( 403, MSG_PASSERROR );
	}
	
	// They can't be the same
	if ( 0 == strcmp( $data['password2'], $data['password'] ) ) {
		send( 403, MSG_PASSERROR );
	}
	
	savePassword( $user['id'], $data['password2'] );
	
	// Reset cookie lookup
	$user['lookup']	= 
	resetLookup( ( int ) $user['id'] );
	
	// Reset authorization
	setAuth( $user );
	sendPage( $conf, '' );
}

/**
 *  Show current configuration
 */
function viewConfig( array $route ) {
	$user		= authUser();
	$conf		= settings();
	if ( empty( $user ) ) {
		sendLogin( $conf, 'manage/settings' );
	}
	
	// Load post template and get Root
	$htpl		= getTemplate( $conf, 'settings', false, true );
	$root		= getRoot( $conf );
	
	$tpl		= [
		'{csrf}'	=> getCsrf( 'settings' ),
		'{theme}'	=> getAdminTheme(),
		'{action}'	=> $root . 'manage/settings',
		'{post_list}'	=> $root,
		'{help}'	=> $root . 'manage/help.html',
		'{settings}'	=> $root . 'manage/settings',
		'{title}'	=> $conf['title'],
		'{tagline}'	=> $conf['tagline'],
		'{timezone}'	=> timezoneSelect( $conf['timezone'] ),
		'{copyright}'	=> $conf['copyright'],
		'{csp}'	=> $conf['csp'],
		'{show_full}'	=> checkedCheckbox( $conf['show_full'] ),
		'{force_tls}'	=> checkedCheckbox( $conf['show_full'] ),
		'{allow_register}'	=> 
			checkedCheckbox( $conf['allow_register'] )
	];
	
	$htpl	= parseLang( $htpl );
	send( 200, \strtr( $htpl, $tpl ) );
}

/**
 *  Save changed configuration
 */
function doConfig( array $route ) {
	$user		= authUser();
	$conf		= settings();
	if ( empty( $user ) ) {
		sendLogin( $conf, 'manage/settings' );
	}
	
	$form		= \filter_input_array( \INPUT_POST, [
		'csrf'		=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'title'	=>  [
			'filter'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
			'options'	=> [
				'default'	=> 'Untitled'
			]
		],
		'tagline'	=> [
			'filter'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
			'options'	=> [
				'default'	=> ''
			]
		],
		'webroot'	=> [
			'filter'	=> \FILTER_SANITIZE_URL,
			'options'	=> [
				'default'	=> '/'
			]
		],
		'theme'	=> [
			'filter'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
			'options'	=> [
				'default'	=> 'goethe'
			]
		],
		'posts'	=>
		[
			'filter'	=> \FILTER_VALIDATE_INT,
			'options'	=> 
			[
				'default'	=> 5,
				'min_range'	=> 1,
				'max_range'	=> 100 
			]
		],
		'show_full'		=>
		[
			'filter'	=> \FILTER_VALIDATE_INT,
			'options'	=> 
			[
				'default'	=> 1,
				'min_range'	=> 0,
				'max_range'	=> 1 
			]
		],
		'allow_register'	=>
		[
			'filter'	=> \FILTER_VALIDATE_INT,
			'options'	=> 
			[
				'default'	=> 1,
				'min_range'	=> 0,
				'max_range'	=> 1 
			]
		],
		'page_limit'		=>
		[
			'filter'	=> \FILTER_VALIDATE_INT,
			'options'	=> 
			[
				'default'	=> 1,
				'min_range'	=> 10,
				'max_range'	=> 500
			]
		],
		'date_format'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'timezone'	=> \FILTER_SANITIZE_FULL_SPECIAL_CHARS,
		'copyright'	=> \FILTER_UNSAFE_RAW
	] );
	
	$csrf = checkCsrf( 'settings', $form['csrf'] ?? '' );
	if ( !$csrf ) {
		send( 403, MSG_FORMEXP );
	}
	
	// Filter HTML in copyright statement
	if ( !empty( $data['copyright'] ) ) {
		 $data['copyright']  = 
		 	html( $data['copyright'] );
	}
	
	// Check timezone
	if ( !in_array(
		$data['timezone'], \DateTimeZone::listIdentifiers() 
	) ) {
		$data['timezone']	= 'America/New_York';
	}
	
	// Try to make sure the datetime format is valid
	try {
		$test			= date( $data['datetime'] );
	} catch( \Exception $e ) {
		$data['datetime']	= 'l, M d, Y';
	}
	
	// Test CSP for JSON compliance or set default
	$csp		= decode( encode( $data['csp'] ) );
	if ( empty( $csp ) ) {
		$data['csp']	= DEFAULT_JCSP;
	}
	
	$showfull	= 
		empty( $data['show_full'] ) ? true : 
			( ( ( int ) $data['show_full'] == 1 ) ? 
				true : false );
	
	$allowreg	= 
		empty( $data['allow_register'] ) ? false : 
			( ( ( int ) $data['show_full'] == 1 ) ? 
				true : false );
	
	$forcetls	= 
		empty( $data['allow_register'] ) ? false : 
			( ( ( int ) $data['show_full'] == 1 ) ? 
				true : false );
	
	
	// Apply relevant parameters
	$params = [
		'site'		=> 
			empty( $data['title'] ) ? 
				'No title' : $data['title'],
		'tagline'		=>
			empty( $data['tagline'] ) ? 
				'No tagline' : $data['tagline'],
		
		'post_limit'		=> $data['posts'],
		'timezone'		=> $data['timezone'],
		'copyright'		=> $data['copyright'],
		'timezone'		=> $data['timezone'],
		'date_format'		=> $data['date_format'],
		'theme'		=> $data['theme'],
		'page_limit'		=> $data['page_limit'],
		'allow_register'	=> $allowreg,
		'show_full'		=> $showfull,
		'force_tls'		=> $forcetls
	];
	
	saveSettings( $params );
	sendPage( 200, 'manage/settings' );
}

/**
 *  Not found page
 */
function notfound() {
	// Load post template and get Root
	$htpl		= getTemplate( $conf, 'notfound' );
	$root		= getRoot( $conf );
	
	$tpl			= [
		'{page_title}'=> $conf['title'],
		'{tagline}'	=> $conf['tagline'],
		'{root}'	=> $root,
		'{manage}'	=> $root . 'manage',
		'{theme}'	=> getTheme( $conf ) . '/',
		'{copyright}'	=> $conf['copyright']
	];
	
	$htpl	= parseLang( $htpl );
	send( 404, \strtr( $htpl, $tpl ) );
}

/**
 *  Pad start
 */
function begin() {
	$conf	= settings();
	
	// Handle shutdown
	\register_shutdown_function( 'shutdown' );

	// Begin routing
	route( $conf['routes'], $conf['markers'] );
}


begin();

// End file
