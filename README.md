# Pad
An ultra-minimal blog for quickly writing thoughts.

Pad has no comments, no file uploading or thumbnail creation, no plugins  
or other features that aren't directly related to writing. Pad is not a  
"distraction free" application. It is a much simpler iteration of the  
traditional weblog.

(This is a work in progress)

## Installation and requirements

Pad is written in PHP and requires version 7.0.28 or greater.  
The database is SQLite, which comes with PHP and on most platforms.  
Pad requires SQLite version 3.7.0 or greater.

Edit *config.php* to the location of the *site.db* and *site.json* files  
if they are to be stored in a different location than is typical.

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

Themes are basic HTML files with placeholders for where your content  
will appear. CSS and JavaScript are included for some basic functions  
however they are not absolutely required for operation.

The *manage* and *feed* folders are special themes used by Pad for the  
admin panel and RSS feed respectively.
