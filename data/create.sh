#!/bin/bash

# Create the SQLite database from schema file

# Timestamp
DATE=`date +%Y-%m-%d-%H-%M-%S`

# Make a backup if it exists, instead of overwriting
mv site.db site-$DATE.db

sqlite3 site.db < scratch.sql

exit
