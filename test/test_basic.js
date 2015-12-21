'use strict';

var net = require('net');
var target = require('./target');

function force_close () {
    if (chan) {
	chan.end();
    }
}

process.on('SIGINT', force_close);
process.on('SIGTERM', force_close);

target.run('kldload modules/khttpd/khttpd.ko');
target.run('usr.sbin/khttpdcontrol/khttpdcontrol');

var chan = new net.createConnection(target.port, target.name);

var connection = {
    connect: function () {
	console.log('connect');
	chan.write('OPTIONS * HTTP/1.1\r\nConnection: close\r\n\r\n');
    },

    drain: function () {
	console.log('drain');
    },

    data: function (data) {
	console.log('data: ' + data.toString());
    },

    end: function () {
	console.log('end');
	chan.end();
    },

    error: function (error) {
	console.log(error);
    },

    close: function (hadError) {
	console.log('close');
	target.run('kldunload khttpd.ko');
    }
};

chan.on('connect', function () { connection.connect(); })
    .on('drain', function () { connection.drain(); })
    .on('data', function (data) { connection.data(data); })
    .on('end', function () { connection.end(); })
    .on('error', function (error) { connection.error(error); })
    .on('close', function (hadError) { connection.close(hadError); });
