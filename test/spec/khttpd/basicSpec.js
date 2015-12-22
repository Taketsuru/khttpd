'use strict';

var net = require('net');
var target = require('../../lib/target');

var statusLinePattern = /^HTTP\/1\.[01] ([1-9][0-9][0-9]) [^ ]+$/;
var headerFieldPattern = /^([^: ]+):(.*)$/i;

function TestState (chan) {
    var state = this;

    this.connect = 0;
    this.drain = 0;
    this.data = [];
    this.end = 0;
    this.error = [];
    this.close = null;

    chan.on('connect', function () { ++state.connect; })
	.on('drain', function () { ++state.drain; })
	.on('data', function (data) { state.data.push(data); })
	.on('end', function () { ++state.end; })
	.on('error', function (error) { state.error.push(error); })
	.on('close', function (hadError) { state.close = hadError; });

    return this;
}

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

describe('khttpd', function () {
    var chan;
    var state;

    var connectTest = function (done) {
	chan = net.createConnection(target.port, target.name, done);
	state = new TestState(chan);
    };

    beforeAll(function () {
	target.run('kldunload khttpd.ko');
	target.run('kldload modules/khttpd/khttpd.ko')
	    || fail('kldload failed');
	target.run('usr.sbin/khttpdcontrol/khttpdcontrol')
	    || fail('khttpdcontrol failed');
    });

    afterAll(function () {
	target.run('kldunload khttpd.ko');
    });

    describe('disconnected w/ requests', function () {
	it('accepts a connection request', connectTest);

	it('closes if the client closes', function (done) {
	    chan.once('end', done);
	    chan.end();
	});

	it('doesn\'t send any data', function (done) {
	    expect(state.data.length).toBe(0);
	    done();
	});
    });

    describe('receiving a request w/ "Connection: close"', function () {
	it('accepts a connection request', connectTest);

	it('closes if the client closes', function (done) {
	    chan.write('OPTIONS * HTTP/1.1\r\n\r\n');
	    chan.end();
	    chan.once('end', done);
	});

	it('sends a valid response', function (done) {
	    state.response = parseMessage(state.data);
	    expectSuccessfulOptionsResponse(state.response);
	    done();
	});
    });

    describe('receiving a request with "Connection: close"', function () {
	function test (garbage) {
	    it('accepts a connection request', connectTest);

	    it('half-closes after sending a response', function (done) {
		chan.write('OPTIONS * HTTP/1.1\r\nConnection: close\r\n\r\n' +
			   garbage);
		chan.once('end', done);
	    });

	    it('sends a valid response', function (done) {
		chan.end();
		chan.once('close', done);
		state.response = parseMessage(state.data);
		expectSuccessfulOptionsResponse(state.response);
		expect(state.response.header['connection']).toBe('close');
	    });
	    
	    it('ignores garbage following the request', function (done) {
		expect(state.response.rest.length).toBe(0);
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

    describe('receiving a partial request line', function () {
	it('accepts a connection request', connectTest);

	it('half-closes after sending a response to the request',
	   function (done) {
	       chan.write('OPTIONS * HTTP/1.1');
	       chan.once('close', done);
	       chan.end();
	   });

	it('has sent a bad request response', function (done) {
	    state.response = parseMessage(state.data);
	    expectBadRequestResponse(state.response);
	    expect(state.response.header['connection']).toBe('close');
	    done();
	});
    });

    describe('receiving a partial header field line', function () {
	it('accepts a connection request', connectTest);

	it('half-closes after sending a response to the request',
	   function (done) {
	       chan.write('OPTIONS * HTTP/1.1\r\nX-Header: test');
	       chan.once('close', done);
	       chan.end();
	   });

	it('has sent a bad request response', function (done) {
	    state.response = parseMessage(state.data);
	    expectBadRequestResponse(state.response);
	    expect(state.response.header['connection']).toBe('close');
	    done();
	});
    });

});
