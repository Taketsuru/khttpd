'use strict';

var net = require('net');
var target = require('../lib/target');
var http_test = require('../lib/http_test');

describe('khttpd', function () {

    describe('disconnected w/ requests', function () {
	var session = {};

	it('accepts a connection request', function (done) {
	    http_test.connect(session, done);
	});

	it('closes if the client closes', function (done) {
	    session.chan.once('end', done);
	    session.chan.end();
	});

	it('doesn\'t send any data', function (done) {
	    expect(session.data.length).toBe(0);
	    done();
	});
    });

    describe('receiving a partial request line', function () {
	var session = {};

	it('accepts a connection request', function (done) {
	    http_test.connect(session, done);
	});

	it('half-closes after sending a response to the request',
	   function (done) {
	       session.chan.write('OPTIONS * HTTP/1.1');
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

    describe('receiving an invalid request target', function () {
	var session = {};
	var invalid_urls = [ 'http://localhost/sys/ui', 'sys/ui'];
	var url;

	var testWithConnectionClose = function (url) {
	    it('accepts a connection request', function (done) {
		http_test.connect(session, done);
	    });

	    it('receives a request line with an invalid request target',
	       function (done) {
		   session.chan.write('GET ' + url + ' HTTP/1.1\r\n' +
			      'Connection: close\r\n\r\n');
		   session.chan.once('end', done);
	       });

	    it('has sent a "Not Found" response', function (done) {
		session.response = http_test.parseMessage(session.data);
		http_test.expectNotFoundResponse(session.response);
		expect(session.response.header['connection']).toBe('close');
		done();
	    });
	}

	var testWithoutConnectionClose = function (url) {
	    var session = {};

	    it('accepts a connection request', function (done) {
		http_test.connect(session, done);
	    });

	    it('receives a request line with an invalid request target',
	       function (done) {
		   session.chan.write('GET ' + url + ' HTTP/1.1\r\n\r\n');
		   session.chan.end();
		   session.chan.once('end', done);
	       });

	    it('has sent a "Not Found" response', function (done) {
		session.response = http_test.parseMessage(session.data);
		http_test.expectNotFoundResponse(session.response);
		expect(session.response.header['connection']).toBeUndefined();
		done();
	    });
	}

	invalid_urls.forEach(function (url) {
	    describe('with Connection: close', function () {
		testWithConnectionClose(url);
	    });
	    describe('without Connection: close', function () {
		testWithoutConnectionClose(url);
	    });
	});

    });

});
