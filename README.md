# Pad
An ultra-minimal blog for quickly writing thoughts.

Pad has no comments, no file uploading or thumbnail creation, no plugins  
or other features that aren't directly related to writing. Pad is a much  
simpler iteration of the traditional weblog.

(This is a work in progress)

## Requirements

Pad is written in PHP and requires version 7.0.28 or greater.  
The database is SQLite, which comes with PHP on most platforms.  
Pad requires SQLite version 3.7.0 or greater.

Upload the following to your web root:
* .htaccess - Required if using the Apache web server
* index.php - Your homepage
* setup.php - The setup script to be run following upload
* config.php - Basic settings (see below if you need to edit this)
* /themes folder - Contains all of the display templates
* /data folder - Contains the database and settings support files

The /data subdirectory contains the following optional files which may  
be excluded from installation
* /data/backup.sh - On \*nix platforms, this is a backup helper script
* /data/create.sh - Can be used to create the database from scratch
* /data/pad.sql - The complete database schema

## Installation

Once the required files are uploaded, edit *config.php* to the location  
of the *site.db* and *site.json* files if they are to be stored in a  
different location than is typical.

Run *setup.php* after all files are uploaded and make a note of the  
created account credentials.

Delete *setup.php*.

## Permissions, backups etc...

On \*nix systems, you can create the database from scratch by running  
*bash create.sh* or equivalent shell command, however it is already  
included in this package as */data/site.db*.

Also on \*nix systems, you may need to enable write permissions to the  
*/data/site.db* file and the */data/backup* folder which can be used to  
store backups of your database. The */data/cache* folder will also need  
write permissions.

To backup your database, run *bash backup.sh*. The backup script can  
also be added to cron for automatic backups.

Set write permissions by running:
```
chmod -R 755 /your-web-root/data
```

## Content formatting

HTML is filtered of potentially harmful tags, however embedding videos  
to YouTube, Vimeo or PeerTube is supported via shortcodes.
```
E.G. For Youtube: 

[youtube https://www.youtube.com/watch?v=RJ0ULhVKwEI]
or
[youtube https://youtu.be/RJ0ULhVKwEI]
or
[youtube RJ0ULhVKwEI]

For Vimeo:

[vimeo https://vimeo.com/113315619]
or
[vimeo 113315619]


For PeerTube (any instance):
[peertube https://peertube.mastodon.host/videos/watch/56047136-00eb-4296-afc3-dd213fd6bab0]
``` 



A simple subset of [Markdown](https://daringfireball.net/projects/markdown/) syntax is also supported.

E.G. To embed a previously uploaded image file, use markdown syntax:
```
![alt text](http://example.com/filename.jpg)
``` 

## Security

For additional security, the /data subfolder can be relocated outside  
the web root. Simply edit *config.php* to the new location. This will  
prevent a casual user from directly accessing the database in the event  
the .htaccess limits are inactive.


## Themes and styles

The default theme is *goethe*. Themes are stored in the */themes*  
folder.

Regular themes should have the following files:  
* home.html - Index page and archive listings
* post.html - Individual post entry template
* postfrag.html - An excerpt used for each post in the listings
* authorfrag.html - Formatting for author details on each post
* login.html - The main login/access template
* changepass.html - A form for changing the current user's password
* bio.html - Displaying an author's profile page
* bioedit.html - A form for editing a an author's profile
* register.html - New user registration form (recommended)
* notfound.html - A page to display when the requested page is not found
* error.html - A general error message display page

Themes are basic HTML files with placeholders for where your content  
will appear. CSS and JavaScript are included for some basic functions  
however they are not absolutely required for operation.

The *manage* and *feed* folders are special themes used by Pad for the  
admin panel and RSS feed respectively.

## Installing on other web servers

### Nginx

The Nginx web server supports URL rewriting and file filtering. The  
following is a simple configuration for site named example.com.  
Note: The pound sign(#) denotes comments.
```
server {
	server_name example.com;
	
	# Change this to your web root, if it's different
	root /var/www/htdocs;
	
	# Set directory index
	index index.php;
	
	# Prevent access to special files
	location ~\.(ht|conf|db|sql|json|sh)\$ {
		deny all;
	}
	
	# Prevent access to data folder
	location /data {
		deny all;
	}
	
	# Prevent direct access to theme html files
	location ~ ^/themes/.*\.html$ {
		deny all;
	}
	
	# Send all requests (that aren't static files) to index.php
	location / {
		try_files $uri $uri/ index.php?$args;
	}
	
	# Handle php
	location ~ \.php$ {
		include fastcgi_params;
		fastcgi_intercept_errors on;
		fastcgi_pass php;
        }
}
``` 

### OpenBSD's httpd(8) web server

The OpenBSD operating system comes with its own web server in the base  
installation. Previously, this was the Apache web server and then Nginx.

OpenBSD does not come with PHP and needs to be installed separately:
```
doas pkg_add php_fpm
```

The following configuration can be used if Pad is installed as the  
"example.com" website.  

Note: Although it shares the same comment system, httpd(8) configuration  
directives *do not* end in a semicolon(;) unlike Nginx settings.
```
# listening on external addresses
ext_addr="*"

# A site called "example.com" 
server "www.example.com" {
	listen on $ext_addr port 80
	alias "example.com"
	
	# Default directory index is set to "index.php"
	directory {
		index "index.php"
	}
	
	# Prevent access to special files
	location "/.ht*"		{ block }
	location "/*.conf*"		{ block }
	location "/*.db*"		{ block }
	location "/*.sql*"		{ block }
	location "/*.json"		{ block }
	location "/*.sh"		{ block }
	
	# Allow robots (follow the same convention if using favicons)
	location "/robots.txt" {
		# Change this to your web root, if it's different
		root { "/htdocs/robots.txt" }
	}
	
	# Prevent access to data folder
	location "/data/*"		{ block }
	
	# Prevent direct access to theme html files
	location "/themes/*.html"	{ block }
	
	# Let through /themes folder requests (I.E. .css, .js etc...)
	location "/themes/*" {
		# Change this to your web root, if it's different
		root { "/htdocs/themes" }
	}
	
	# Due to the way httpd(8) handles rewrites, you may create a 
	# separate folder for uploads in the future and use the above 
	# configuration in a similar way
	
	# Let index.php handle all other requests
	location "/*" {
		# Change this to your web root, if it's different
		root { "/htdocs/index.php" }
		
		# Enable FastCGI handling of PHP
		fastcgi socket "/run/php-fpm.sock"
	}
}

``` 

