#!/bin/sh
# Entry point of the lsqlited image. It hands the daemon the initialization
# directory and then gets out of the way, so that everything else -- the
# configuration, the databases, the flags -- stays where it was.
#
# Scripts under /docker-entrypoint-initdb.d seed the databases the daemon
# creates on this start: a *.sql or *.sql.gz file applies to every configured
# database, and one in a subdirectory named after a database applies to that
# database alone. Set LSQLITED_INITDB_DIR to move the directory, or to the
# empty string to skip initialization entirely.
set -e

: "${LSQLITED_INITDB_DIR=/docker-entrypoint-initdb.d}"

# `docker run lsqlited -config /etc/lsqlited/config.yaml` passes flags, not a
# command, so the daemon is what they belong to. Anything else is run as given,
# which keeps `docker run lsqlited sh` and the like working.
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
	set -- lsqlited "$@"
fi

case "$1" in
lsqlited | /usr/local/bin/lsqlited)
	if [ -n "$LSQLITED_INITDB_DIR" ] && [ -d "$LSQLITED_INITDB_DIR" ]; then
		# Prepended rather than appended, so that a -initdb given on the command
		# line is parsed last and wins.
		daemon=$1
		shift
		set -- "$daemon" -initdb "$LSQLITED_INITDB_DIR" "$@"
	fi
	;;
esac

exec "$@"
