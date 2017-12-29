#!/usr/bin/env bash

### BEGIN INIT INFO
# Provides:          milter_env_addr_mangle
# Required-Start:    $syslog $remote_fs
# Required-Stop:     $syslog $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Envelope addresses mangler (milter)
### END INIT INFO

APP_NAME="milter_env_addr_mangle.py"
APP_FILE=/opt/milters/$APP_NAME
APP_PIDFILE=/var/run/${APP_NAME}.pid
APP_ARGS="-c /etc/postfix/milter_env_addr_mangle.yml"
APP_USER="postfix"
VARS_FILE=/opt/milters/${APP_NAME}.vars

if [ -f $VARS_FILE ]
then
    . $VARS_FILE
fi

. /lib/lsb/init-functions

do_start()
    {
    log_daemon_msg "Starting $APP_NAME"
    start-stop-daemon --start --background --pidfile $APP_PIDFILE --make-pidfile --user $APP_USER --chuid $APP_USER --startas $APP_FILE -- $APP_ARGS
    log_end_msg $?
    }

do_stop()
    {
    log_daemon_msg "Stopping $APP_NAME"
    start-stop-daemon --stop --pidfile $APP_PIDFILE --user $APP_USER --retry 10
    log_end_msg $?
    }

case $1 in
    start|stop )
        do_${1}
    ;;
    restart|reload|force-reload )
        do_stop
        do_start
    ;;
    status )
        status_of_proc "$APP_FILE" "$APP_NAME" && exit 0 || exit $?
    ;;
    * )
        echo "Usage: $0 {start|stop|restart|status}"
    ;;
esac
