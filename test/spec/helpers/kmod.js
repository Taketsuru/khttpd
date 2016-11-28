'use strict';

var target = require('../lib/target');

function onExit(exit, error) {
    target.run('kldstat -q -n khttpd.ko && kldunload -f khttpd.ko');

    if (error) {
        console.log(error.stack);
    }

    if (exit) {
        process.exit();
    }
}

process.on('exit', onExit.bind(null, false));
process.on('SIGINT', onExit.bind(null, true));
process.on('uncaughtException', onExit.bind(null, true));

if (target.run('( kldstat -q -n khttpd.ko && kldunload -f khttpd.ko) || ' +
               'exit 0').status !== 0) {
    console.log('kldunload failed');
    process.exit();
}

if (target.run('kldload modules/khttpd/khttpd.ko').status !== 0) {
    console.log('kldload failed');
    process.exit();
}

if (target.run('usr.sbin/khttpdctl/khttpdctl ' +
	       'load test/khttpd.conf').status !== 0) {
    console.log('khttpdctl failed');
    process.exit();
}
