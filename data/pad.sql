
-- Database presets
PRAGMA encoding = "UTF-8";	-- Default encoding set to UTF-8
PRAGMA auto_vacuum = "2";	-- File size improvement
PRAGMA temp_store = "2";	-- Memory temp storage for performance
PRAGMA journal_mode = "WAL";	-- Performance improvement
PRAGMA secure_delete = "1";	-- Privacy improvement
PRAGMA foreign_keys = "1";	-- Enable foreign key relationships


-- User profiles
CREATE TABLE users (
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	username TEXT NOT NULL COLLATE NOCASE,
	password TEXT NOT NULL,
	display TEXT DEFAULT NULL COLLATE NOCASE,
	bio TEXT DEFAULT NULL,
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	status INTEGER DEFAULT 0
);

CREATE UNIQUE INDEX idx_username ON users( username );


-- Deleted/Banned usernames
CREATE TABLE blocked_names(
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	username TEXT NOT NULL COLLATE NOCASE
);

CREATE UNIQUE INDEX idx_blocked ON blocked_names( username );


-- Cookie based login tokens
CREATE TABLE logins(
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	user_id INTEGER DEFAULT NULL REFERENCES users( id ) 
		ON DELETE CASCADE,
	lookup TEXT NOT NULL NULL COLLATE NOCASE,
	updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	hash TEXT DEFAULT NULL
);

CREATE UNIQUE INDEX idx_login_user ON logins( user_id );
CREATE UNIQUE INDEX idx_login_lookup ON logins( lookup );


-- Visitor/User sessions
CREATE TABLE sessions(
	id INTEGER PRIMARY KEY,
	session_id TEXT DEFAULT NULL COLLATE NOCASE,
	session_data TEXT DEFAULT NULL COLLATE NOCASE,
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_session_id ON sessions( session_id );
CREATE INDEX idx_session_created ON sessions( created ASC );
CREATE INDEX idx_session_updated ON sessions( updated ASC );


CREATE TABLE posts (
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	uuid TEXT DEFAULT NULL COLLATE NOCASE,
	title TEXT NOT NULL COLLATE NOCASE,
	slug TEXT NOT NULL COLLATE NOCASE,
	permalink TEXT NOT NULL COLLATE NOCASE,
	parent_id INTEGER DEFAULT NULL REFERENCES posts( id ) 
		ON DELETE CASCADE,	-- Parent post
	user_id INTEGER NOT NULL REFERENCES users( id ) 
		ON DELETE CASCADE,	-- Creator
	summary TEXT DEFAULT NULL COLLATE NOCASE,
	body TEXT NOT NULL,		-- Content
	created_ TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	published TIMESTAMP DEFAULT NULL,
	status INTEGER DEFAULT 0
);

CREATE INDEX idx_post_created ON posts( created );
CREATE INDEX idx_post_published ON posts( published );
CREATE INDEX idx_post_parent_id ON posts( parent_id );
CREATE INDEX idx_post_user ON posts( user_id );
CREATE INDEX idx_post_slug ON posts( slug );
CREATE UNIQUE INDEX idx_post_permalink ON posts( permalink );

CREATE TABLE post_meta(
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	name TEXT NOT NULL COLLATE NOCASE,
	content TEXT NOT NULL COLLATE NOCASE
);

CREATE INDEX idx_post_meta ON post_meta( name );



-- Family relationships
CREATE TABLE post_family(
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	parent_id INTEGER NOT NULL REFERENCES posts( id ) 
		ON DELETE CASCADE,
	child_id INTEGER NOT NULL REFERENCES posts( id ) 
		ON DELETE CASCADE,
	ordering INTEGER DEFAULT 0
);

CREATE UNIQUE INDEX idx_post_family ON post_family( parent_id, child_id );

-- Taxonomy
CREATE TABLE tags(
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	page_id INTEGER NOT NULL REFERENCES posts( id ) 
		ON DELETE CASCADE,	-- Parent post
	slug TEXT NOT NULL COLLATE NOCASE,
	name TEXT NOT NULL COLLATE NOCASE,
	ordering INTEGER DEFAULT 0
);

CREATE INDEX idx_tags_order ON tags( ordering );
CREATE UNIQUE INDEX idx_tags_slug ON tags( slug );


-- Post tag relationships
CREATE TABLE post_tags(
	post_id INTEGER DEFAULT NULL 
		REFERENCES posts( id ) ON DELETE CASCADE,
	tag_id INTEGER DEFAULT NULL 
		REFERENCES tags( id ) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_post_tags ON post_tags( post_id, tag_id );


-- Searching
CREATE VIRTUAL TABLE post_search USING fts4(body, tokenize=unicode61);


-- User views

-- Public profile view
CREATE VIEW profiles AS 
SELECT id, username, display, bio, created, status FROM users;




-- Content views


-- Tag term and slug view
-- Usage:
-- INSERT INTO tag_view ( name, slug, page_id ) 
--	VALUES ( :name, :slug, :page_id );
CREATE VIEW tag_view AS SELECT
	tags.name AS name,
	tags.slug AS slug,
	post_tags.tag_id AS tag_id,
	post_tags.post_id AS post_id
	
	FROM tags
	LEFT JOIN post_tags ON tags.id = post_tags.tag_id;



-- Family view
CREATE VIEW post_family_view AS 
SELECT parent_id, child_id FROM post_family;


-- Index view
-- Usage (handled in trigger):
-- SELECT * FROM index_view WHERE archive_ymd = :ymd LIMIT 10
-- SELECT * FROM index_view WHERE archive_ym = :ym LIMIT 10
-- SELECT * FROM index_view WHERE archive_y = :y LIMIT 10
CREATE VIEW index_view AS SELECT
	posts.id AS id, 
	posts.title AS title,
	posts.slug AS slug,
	posts.created AS created, 
	posts.updated AS updated, 
	posts.published AS published, 
	posts.summary AS summary, 
	posts.body AS body, 
	posts.status AS status,
	
	-- Timestamps
	strftime( '%Y-%m-%dT%H:%M:%SZ', 
		COALESCE( posts.published, posts.created ) 
	) AS date_utc, 
	strftime( '%Y-%m-%d', 
		COALESCE( posts.published, posts.created )
	) AS date_short, 
	
	-- Archive search
	strftime( '%Y', 
		COALESCE( posts.published, posts.created ) 
	) AS archive_y, 
	strftime( '%Y/%m', 
		COALESCE( posts.published, posts.created ) 
	) AS archive_ym, 
	strftime( '%Y/%m/%d', 
		COALESCE( posts.published, posts.created ) 
	) AS archive_ymd, 
	
	-- Link
	( strftime( '/%Y/%m/%d', 
		COALESCE( posts.published, posts.created )  ) || 
		'/' || posts.slug 
	) AS permalink,
	
	-- Edit link
	( '/manage/edit/' || posts.id ) AS post_edit,
	
	-- Author
	COALESCE( users.display, users.username ) AS author,
	( '/users/' || users.id || '/' || users.username ) AS authorlink, 
	users.id AS author_id,
	
	-- Taxonomy
	group_concat(
		'id='		|| tags.id	|| '&' || 
		'name='	|| tags.name	|| '&' || 
		'slug='	|| tags.slug
	) AS taxonomy
	
	
	FROM posts
	
	-- Metadata
	LEFT JOIN users ON posts.user_id = users.id
	LEFT JOIN post_tags ON posts.id = post_tags.post_id
	LEFT JOIN tags ON post_tags.tag_id = tags.id;


-- Single page
-- Usage:
-- SELECT * FROM page_view WHERE id = :id
-- SELECT * FROM page_view WHERE permalink = :permalink
-- SELECT * FROM page_view WHERE permalink = :permalink AND published IS NOT NULL
CREATE VIEW page_view AS SELECT
	posts.id AS id, 
	posts.title AS title,
	posts.slug AS slug,
	posts.created AS created, 
	posts.updated AS updated, 
	posts.published AS published, 
	posts.summary AS summary, 
	posts.body AS body, 
	posts.status AS status,
	
	-- Timestamps
	strftime( '%Y-%m-%dT%H:%M:%SZ', 
		COALESCE( posts.published, posts.created ) 
	) AS date_utc, 
	strftime( '%Y-%m-%d', 
		COALESCE( posts.published, posts.created )
	) AS date_short, 
	
	-- Archive search
	strftime( '%Y', 
		COALESCE( posts.published, posts.created ) 
	) AS archive_y, 
	strftime( '%Y/%m', 
		COALESCE( posts.published, posts.created ) 
	) AS archive_ym, 
	strftime( '%Y/%m/%d', 
		COALESCE( posts.published, posts.created ) 
	) AS archive_ymd, 
	
	
	-- Link
	( strftime( '/%Y/%m/%d', 
		COALESCE( posts.published, posts.created ) ) || 
		'/' || posts.slug 
	) AS permalink,
	
	-- Edit link
	( '/manage/edit/' || posts.id ) AS post_edit,
	
	-- Previously published sibling
	( SELECT id FROM posts prev
		WHERE prev.id < posts.id 
			AND prev.published IS NOT NULL
			ORDER BY prev.id DESC LIMIT 1 
	) AS prev_id, 
	
	-- Next published sibling
	( SELECT id FROM posts nxt 
		WHERE nxt.id > posts.id
			AND nxt.published IS NOT NULL
			ORDER BY nxt.id ASC LIMIT 1 
	) AS next_id, 
	
	-- Author
	COALESCE( users.display, users.username ) AS author,
	( '/users/' || users.id || '/' || users.username ) AS authorlink,  
	users.id AS author_id,
	
	-- Taxonomy
	group_concat(
		'id='		|| tags.id	|| '&' || 
		'name='	|| tags.name	|| '&' || 
		'slug='	|| tags.slug
	) AS taxonomy
	
	FROM posts
	
	-- Metadata
	LEFT JOIN users ON posts.user_id = users.id
	LEFT JOIN post_tags ON posts.id = post_tags.post_id
	LEFT JOIN tags ON post_tags.tag_id = tags.id;


-- Post preview (for sibling details)
CREATE VIEW post_preview AS SELECT 
	id, title, slug, status,
	( strftime( '/%Y/%m/%d', 
		COALESCE( published, created ) ) || 
		'/' || slug 
	) AS permalink
	
	FROM posts;



-- Secrity views

-- Login view
-- Usage:
-- SELECT * FROM login_view WHERE lookup = :lookup;
CREATE VIEW login_view AS SELECT 
	users.id AS id, 
	users.username AS name,
	logins.lookup AS lookup,
	logins.hash AS hash, 
	logins.updated AS updated, 
	users.status AS status
	
	FROM logins
	JOIN users ON logins.user_id = users.id;


-- Login regenerate. Not intended for SELECT
-- Usage:
-- UPDATE logout_view SET lookup = '' WHERE user_id = :user_id;
CREATE VIEW logout_view AS 
SELECT user_id, lookup FROM logins;

-- Password based login view
-- Usage:
-- SELECT * FROM login_view WHERE username = :username;
CREATE VIEW login_pass AS 
SELECT id, username, display, password, status FROM users;


-- Generate a random unique string
-- Usage:
-- SELECT string FROM rnd;
CREATE VIEW rnd AS 
SELECT lower( hex( randomblob( 16 ) ) ) AS string;


-- GUID/UUID generator helper
-- Usage:
-- SELECT id FROM uuid;
CREATE VIEW uuid AS SELECT lower(
	hex( randomblob( 4 ) ) || '-' || 
	hex( randomblob( 2 ) ) || '-' || 
	'4' || substr( hex( randomblob( 2 ) ), 2 ) || '-' || 
	substr( 'AB89', 1 + ( abs( random() ) % 4 ) , 1 )  ||
	substr( hex( randomblob( 2 ) ), 2 ) || '-' || 
	hex( randomblob( 6 ) )
) AS id;


-- User triggers
CREATE TRIGGER user_insert AFTER INSERT ON users FOR EACH ROW
BEGIN
	INSERT INTO logins ( user_id, lookup ) 
		VALUES ( NEW.rowid, ( SELECT string FROM rnd ) );
END;

CREATE TRIGGER user_update AFTER UPDATE ON users FOR EACH ROW 
WHEN NEW.updated < OLD.updated
BEGIN
	UPDATE users SET updated = CURRENT_TIMESTAMP
		WHERE id = NEW.rowid;
END;

CREATE TRIGGER user_display_insert AFTER INSERT ON users FOR EACH ROW
WHEN NEW.display_name IS NULL
BEGIN
	UPDATE users SET display_name = username 
		WHERE users.id = NEW.rowid;
END;

CREATE TRIGGER user_display_update AFTER UPDATE ON users FOR EACH ROW
WHEN NEW.display_name IS NULL
BEGIN
	UPDATE users SET display_name = username 
		WHERE users.id = NEW.rowid;
END;

CREATE TRIGGER login_update AFTER UPDATE ON logins FOR EACH ROW 
WHEN NEW.updated < OLD.updated
BEGIN
	UPDATE logins SET updated = CURRENT_TIMESTAMP, 
		lookup = ( SELECT string FROM rnd )  
		WHERE id = OLD.rowid;
END;




-- Post UUID and permalink
CREATE TRIGGER post_insert AFTER INSERT ON posts FOR EACH ROW
BEGIN
	UPDATE posts SET 
		uuid = ( SELECT id FROM uuid ), 
		permalink = ( strftime( '/%Y/%m/%d/', 
			COALESCE( posts.published, posts.created ) ) || 
			posts.slug 
		)
		
		WHERE id = NEW.rowid;
END;

-- Post update
CREATE TRIGGER post_update AFTER UPDATE ON posts FOR EACH ROW
BEGIN
	UPDATE posts SET 
		updated = CURRENT_TIMESTAMP,
		permalink = ( strftime( '/%Y/%m/%d/', 
			COALESCE( posts.published, posts.created ) ) || 
			posts.slug 
		)
		
		WHERE id = NEW.rowid;
END;

-- Page relationships
CREATE TRIGGER posts_parent_insert AFTER INSERT ON posts FOR EACH ROW 
WHEN NEW.parent_id = 0
BEGIN
	UPDATE posts SET parent_id = NEW.rowid WHERE id = NEW.rowid;
	
	INSERT OR IGNORE INTO post_family( parent_id, child_id ) 
		VALUES ( NEW.rowid, NEW.rowid );
END;

CREATE TRIGGER posts_family_insert INSTEAD OF INSERT ON post_family_view
BEGIN
	INSERT OR IGNORE INTO post_family( parent_id, child_id ) 
		VALUES ( NEW.parent_id, NEW.child_id );
END;




-- Add content to search
CREATE TRIGGER post_search_insert AFTER INSERT ON posts FOR EACH ROW 
WHEN NEW.title IS NOT NULL AND NEW.body IS NOT NULL
BEGIN
	INSERT INTO post_search ( docid, body ) 
		VALUES ( NEW.rowid, NEW.title || ' ' || NEW.body );
END;


-- Modify search content
CREATE TRIGGER post_search_update AFTER UPDATE ON posts FOR EACH ROW 
WHEN NEW.title IS NOT NULL AND NEW.body IS NOT NULL
BEGIN	
	UPDATE post_search SET body = NEW.title || ' ' || NEW.body
		WHERE docid = NEW.rowid;
END;

CREATE TRIGGER post_delete BEFORE DELETE ON posts FOR EACH ROW
BEGIN
	DELETE FROM post_search WHERE docid = OLD.rowid;
END;

CREATE TRIGGER session_update AFTER UPDATE ON sessions FOR EACH ROW 
BEGIN
	UPDATE sessions SET updated = CURRENT_TIMESTAMP
		WHERE id = NEW.id;
END;


-- Adding a new taxonomy term to the post
CREATE TRIGGER tag_add INSTEAD OF INSERT ON tag_view
BEGIN
	INSERT OR IGNORE INTO tags ( name, slug )
		VALUES( NEW.name, NEW.slug );
	
	INSERT OR IGNORE INTO post_tags ( post_id, tag_id ) 
		VALUES( 
			NEW.post_id, ( 
				SELECT tags.id AS id FROM tags 
				WHERE tags.slug = NEW.slug LIMIT 1 
			) 
		);
END;

