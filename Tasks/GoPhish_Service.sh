#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#REF: https://github.com/gophish/gophish/issues/586
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/goapps/src/github.com/gophish/gophish/config.json
#REF:https://github.com/gophish/gophish/issues/586
# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/goapps/src/github.com/gophish/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
    echo 'Starting '${processName}'...'
    cd ${appDirectory}
    nohup ./$process >>$logfile 2>>$errfile &
    sleep 1
}

stop() {
    echo 'Stopping '${processName}'...'
    pid=$(/usr/sbin/pidof ${process})
    kill ${pid}
    sleep 1 
}

status() {
    pid=$(/usr/sbin/pidof ${process})
    if [[ "$pid" != "" ]]; then
        echo ${processName}' is running...'
    else
        echo ${processName}' is not running...'
    fi
}

case $1 in
    start|stop|status) "$1" ;;
esac
