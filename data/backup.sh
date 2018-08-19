#!/bin/bash

# Make a backup of the database
# Suitable for cron

DATE=`date +%Y-%m-%d-%H-%M-%S`

sqlite3 site.db .dump > backup/$DATE.sql

exit
