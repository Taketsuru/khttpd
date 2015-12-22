'use strict';

var net = require('net');
var target = require('../lib/target');

var messageSizeMax = 16384;
var statusLinePattern = /^HTTP\/1\.[01] ([1-9][0-9][0-9]) [^ ]+$/;
var headerFieldPattern = /^([^: ]+):(.*)$/i;

function connect(session, done) {
    var chan = net.createConnection(target.port, target.name);

    session.chan = chan;
    session.connect = 0;
    session.drain = 0;
    session.data = [];
    session.end = 0;
    session.error = [];
    session.close = null;

    chan.on('connect', function () { ++session.connect; })
	.on('drain', function () { ++session.drain; })
	.on('data', function (data) { session.data.push(data); })
	.on('end', function () { ++session.end; })
	.on('error', function (error) { done.fail(error); })
	.on('close', function (hadError) { session.close = hadError; });

    chan.once('connect', done);
};

function parseMessage (message) {
    var end;
    var i;
    var buffer = Buffer.concat(message);
    var lines = buffer.toString().split(/\r\n/);
    var match;
    var name;
    var value;
    var result = {};

    result.statusLine = lines[0];
    expect(result.statusLine).toMatch(statusLinePattern);
    result.statusCode = statusLinePattern.exec(lines[0])[1];

    result.header = {};
    for (i = 1; lines[i] !== ''; ++i) {
	expect(lines[i]).toMatch(headerFieldPattern);

	match = headerFieldPattern.exec(lines[i]);
	name = match[1].toLowerCase();
	value = match[2].trim();

	if (result.header[name] === undefined) {
	    result.header[name] = value;
	} else {
	    result.header[name] += ', ' + value;
	}
    }

    end = buffer.indexOf('\r\n\r\n');
    expect(end).not.toBe(-1);

    result.rest = message.slice(end + 4);

    return result;
}

function expectSuccessfulOptionsResponse (response) {
    expect(response.statusCode).toBe('200');
    expect(response.header['content-length']).toBe('0');
    expect(response.header['allow']).not.toBeUndefined();
}

function expectBadRequestResponse (response) {
    expect(response.statusCode).toBe('400');
    expect(response.header['content-length']).not.toBeUndefined();
    expect(response.header['content-length']).not.toBe('0');
}

function expectNotFoundResponse (response) {
    expect(response.statusCode).toBe('404');
    expect(response.header['content-length']).not.toBeUndefined();
    expect(response.header['content-length']).not.toBe('0');
}

exports.messageSizeMax = messageSizeMax;
exports.connect = connect;
exports.parseMessage = parseMessage;
exports.expectSuccessfulOptionsResponse = expectSuccessfulOptionsResponse;
exports.expectBadRequestResponse = expectBadRequestResponse;
exports.expectNotFoundResponse = expectNotFoundResponse;
