'use strict';

var net = require('net');
var target = require('../lib/target');
var http_test = require('../lib/http_test');

describe('khttpd', function () {

    describe('receiving a request w/ "Connection: close"', function () {
	var session = {};

	it('accepts a connection request', function (done) {
	    http_test.connect(session, done);
	});

	it('closes if the client closes', function (done) {
	    session.chan.write('OPTIONS * HTTP/1.1\r\n\r\n');
	    session.chan.end();
	    session.chan.once('end', done);
	});

	it('sends a valid response', function (done) {
	    session.response = http_test.parseMessage(session.data);
	    http_test.expectSuccessfulOptionsResponse(session.response);
	    done();
	});
    });

    describe('receiving a request with "Connection: close"', function () {
	function test (garbage) {
	    var session = {};

	    it('accepts a connection request', function (done) {
		http_test.connect(session, done);
	    });

	    it('half-closes after sending a response', function (done) {
		session.chan.write('OPTIONS * HTTP/1.1\r\n' +
				'Connection: close\r\n\r\n' + garbage);
		session.chan.once('end', done);
	    });

	    it('sends a valid response', function (done) {
		session.chan.end();
		session.chan.once('close', done);
		session.response = http_test.parseMessage(session.data);
		http_test.expectSuccessfulOptionsResponse(session.response);
		expect(session.response.header['connection']).toBe('close');
	    });

	    it('ignores garbage following the request', function (done) {
		expect(session.response.rest.length).toBe(0);
		done();
	    });
	}

	describe('followed by EOF', function () {
	    test('');
	});

	describe('followed by garbage', function () {
	    test('GET / HTTP/1.1\r\n\r\n');
	});
    });

    describe('receiving a partial header field line', function () {
	var session = {};

	it('accepts a connection request', function (done) {
	    http_test.connect(session, done);
	});

	it('half-closes after sending a response to the request',
	   function (done) {
	       session.chan.write('OPTIONS * HTTP/1.1\r\nX-Header: test');
	       session.chan.once('close', done);
	       session.chan.end();
	   });

	it('has sent a bad request response', function (done) {
	    session.response = http_test.parseMessage(session.data);
	    http_test.expectBadRequestResponse(session.response);
	    expect(session.response.header['connection']).toBe('close');
	    done();
	});
    });
});
