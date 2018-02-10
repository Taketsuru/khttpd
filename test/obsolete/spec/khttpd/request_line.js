'use strict';

var net = require('net'),
    target = require('../lib/target'),
    httpTest = require('../lib/http_test');

describe('khttpd', function () {

    describe('disconnected w/ requests', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('closes if the client closes', function (done) {
            session.chan.once('close', done);
            session.chan.end();
        });

        it('doesn\'t send any data', function (done) {
            expect(session.data.length).toBe(0);
            done();
        });
    });

    describe('receiving CRLFs followed by EOF', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('closes if the client closes', function (done) {
            var crlfs, i, n;
            crlfs = '';
            n = 512;
            for (i = 0; i + 2 <= n; i += 2) {
                crlfs += '\r\n';
            }
            session.chan.once('close', done);
            session.chan.write(crlfs);
            session.chan.end();
        });

        it('doesn\'t send any data', function (done) {
            expect(session.data.length).toBe(0);
            done();
        });
    });

    describe('receiving CRLFs preceding a request', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('accepts as many as the message size limit',
           function (done) {
               var i, n, message, crlfs;

               message = 'OPTIONS * HTTP/1.1\r\n' +
		   'Host: ' + target.name + '\r\n' +
		   'Connection: close\r\n\r\n';
               crlfs = '';
               n = httpTest.messageSizeMax - message.length;
               for (i = 0; i + 2 <= n; i += 2) {
                   crlfs += '\r\n';
               }
               session.chan.write(crlfs + message);
               session.chan.once('close', done);
           });

        it('sends a valid response', function (done) {
            session.response = httpTest.parseMessage(session.data);
            httpTest.expectSuccessfulOptionsResponse(session.response);
            expect(session.response.header.connection).toBe('close');
	    done();
        });
    });

    describe('receiving a fragmented request line', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('receives a partial request line', function (done) {
            session.chan.write('OPTIONS *');
            setTimeout(function () { done(); }, 1000);
        });

        it('receives the rest of the request line', function (done) {
            session.chan.write(' HTTP/1.1\r\nHost: ' + target.name +
			       '\r\n\r\n');
            session.chan.once('close', done);
            session.chan.end();
        });

        it('sends a successful response', function (done) {
            session.response = httpTest.parseMessage(session.data);
            httpTest.expectSuccessfulOptionsResponse(session.response);
            done();
        });
    });

    describe('receiving a request line whose size < limit', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('half-closes after sending a response to the request',
           function (done) {
               var head = 'GET ',
                   tail = ' HTTP/1.1\r\nHost: ' + target.name + '\r\n\r\n',
                   targetUri = '/',
                   i, n;

               n = httpTest.messageSizeMax - head.length - tail.length;
               for (i = 1; i < n; ++i) {
                   targetUri += 'a';
               }
               session.chan.write(head + targetUri + tail);
               session.chan.once('close', done);
               session.chan.end();
           });

        it('sends a "Not Found" response', function (done) {
            session.response = httpTest.parseMessage(session.data);
            httpTest.expectNotFoundResponse(session.response);
            done();
        });
    });

    describe('receiving a request line whose size < limit', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('half-closes after sending a response to the request',
           function (done) {
               var head = 'GET ',
                   tail = ' HTTP/1.1\r\nHost: ' + target.name + '\r\n\r\n',
                   targetUri = '/',
                   i, n;

               n = httpTest.messageSizeMax - head.length - tail.length;
               for (i = 1; i < n; ++i) {
                   targetUri += 'a';
               }
               session.chan.write(head + targetUri + tail);
               session.chan.once('close', done);
               session.chan.end();
           });

        it('sends a "Not Found" response', function (done) {
            session.response = httpTest.parseMessage(session.data);
            httpTest.expectNotFoundResponse(session.response);
            done();
        });
    });

    describe('receiving a request line whose size == limit', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('half-closes after sending a response to the request',
           function (done) {
               var head = 'GET ',
                   tail = ' HTTP/1.1\r\n',
                   targetUri = '/',
                   i, n;

               n = httpTest.messageSizeMax - head.length - tail.length;
               for (i = 1; i < n; ++i) {
                   targetUri += 'a';
               }
               session.chan.write(head + targetUri + tail +
				  'Host: ' + target.name + '\r\n\r\n');
               session.chan.once('close', done);
               session.chan.end();
           });

        it('sends a "Request header field too large" response',
           function (done) {
               session.response = httpTest.parseMessage(session.data);
               httpTest.
                   expectRequestHeaderFieldTooLargeResponse(session.response);
               done();
           });
    });

    describe('receiving a request line whose size > limit', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('half-closes after sending a response to the request',
           function (done) {
               var head = 'GET ',
                   tail = ' HTTP/1.1\r\n',
                   path = '/',
                   i, n;

               n = httpTest.messageSizeMax - head.length - tail.length + 1;
               for (i = 1; i < n; ++i) {
                   path += 'a';
               }
               session.chan.write(head + path + tail +
				  'Host: ' + target.name + '\r\n\r\n');
               session.chan.once('close', done);
               session.chan.end();
           });

        it('sends a "Bad Request" response', function (done) {
            session.response = httpTest.parseMessage(session.data);
            httpTest.expectBadRequestResponse(session.response);
            done();
        });
    });

    describe('receiving a partial request line', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('half-closes after sending a response to the request',
           function (done) {
               session.chan.write('OPTIONS * HTTP/1.1');
               session.chan.once('close', done);
               session.chan.end();
           });

        it('has sent a bad request response', function (done) {
            session.response = httpTest.parseMessage(session.data);
            httpTest.expectBadRequestResponse(session.response);
            expect(session.response.header.connection).toBe('close');
            done();
        });
    });

    describe('receiving an invalid request target', function () {
        var session = {},
            invalidURLs = ['/nowhere'],
            url;

        function testWithConnectionClose(url) {
            it('accepts a connection request', function (done) {
                httpTest.connect(session, done);
            });

            it('receives a request line with an invalid request target',
               function (done) {
                   session.chan.write('GET ' + url + ' HTTP/1.1\r\n' +
				      'Host: ' + target.name + '\r\n' +
                                      'Connection: close\r\n\r\n');
                   session.chan.once('close', done);
               });

            it('has sent a "Not Found" response', function (done) {
                session.response = httpTest.parseMessage(session.data);
                httpTest.expectNotFoundResponse(session.response);
                expect(session.response.header.connection).toBe('close');
                done();
            });
        }

        function testWithoutConnectionClose(url) {
            var session = {};

            it('accepts a connection request', function (done) {
                httpTest.connect(session, done);
            });

            it('receives a request line with an invalid request target',
               function (done) {
                   session.chan.write('GET ' + url + ' HTTP/1.1\r\n' +
				      'Host: ' + target.name + '\r\n\r\n');
                   session.chan.end();
                   session.chan.once('close', done);
               });

            it('has sent a "Not Found" response', function (done) {
                session.response = httpTest.parseMessage(session.data);
                httpTest.expectNotFoundResponse(session.response);
                expect(session.response.header.connection).toBeUndefined();
                done();
            });
        }

        invalidURLs.forEach(function (url) {
            describe('with Connection: close', function () {
                testWithConnectionClose(url);
            });
            describe('without Connection: close', function () {
                testWithoutConnectionClose(url);
            });
        });

    });

    describe('receiving an invalid version', function () {
        var invalidVersions = ['HTTP/0.0', 'http/1.1', 'PTTH/1.1',
                               'HTTP/0.9', 'veryyyyyyyyyyyyyyloooooong/1.1',
			       'sht/1.1'];

        function test(version) {
            var session = {};

            it('accepts a connection request', function (done) {
                httpTest.connect(session, done);
            });

            it('half-closes after sending a response to the request',
               function (done) {
                   session.chan.write('OPTIONS * ' + version + '\r\n' +
				     'Host: ' + target.name + '\r\n\r\n');
                   session.chan.once('close', done);
                   session.chan.end();
               });

            it('has sent a bad request response', function (done) {
                session.response = httpTest.parseMessage(session.data);
                httpTest.expectBadRequestResponse(session.response);
                expect(session.response.header.connection).toBe('close');
                done();
            });
        }

        invalidVersions.forEach(test);
    });

});
