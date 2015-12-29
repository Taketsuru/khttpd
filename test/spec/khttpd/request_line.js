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
            session.chan.once('end', done);
            session.chan.end();
        });

        it('doesn\'t send any data', function (done) {
            expect(session.data.length).toBe(0);
            done();
        });
    });

    xdescribe('receiving CRLFs preceding a request', function () {
        var session = {};

        it('accepts a connection request', function (done) {
            httpTest.connect(session, done);
        });

        it('accepts as many as the message size limit',
           function (done) {
               var i, n, message, crlfs;

               message = 'OPTIONS * HTTP/1.1\r\nConnection: close\r\n\r\n';
               crlfs = '';
               n = httpTest.messageSizeMax - message.length;
               for (i = 0; i + 2 <= n; i += 2) {
                   crlfs += '\r\n';
               }
               session.chan.write(crlfs + message);
               session.chan.once('end', done);
           });

        it('sends a valid response', function (done) {
            session.chan.end();
            session.chan.once('close', done);
            session.response = httpTest.parseMessage(session.data);
            httpTest.expectSuccessfulOptionsResponse(session.response);
            expect(session.response.header.connection).toBe('close');
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
                   tail = ' HTTP/1.1\r\n\r\n',
                   target = '/',
                   i, n;

               n = httpTest.messageSizeMax - head.length - tail.length;
               for (i = 1; i < n; ++i) {
                   target += 'a';
               }
               session.chan.write(head + target + tail);
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
                   target = '/',
                   i, n;

               n = httpTest.messageSizeMax - head.length - tail.length;
               for (i = 1; i < n; ++i) {
                   target += 'a';
               }
               session.chan.write(head + target + tail + '\r\n');
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
                   target = '/',
                   i, n;

               n = httpTest.messageSizeMax - head.length - tail.length + 1;
               for (i = 1; i < n; ++i) {
                   target += 'a';
               }
               session.chan.write(head + target + tail + '\r\n');
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
            invalidURLs = ['http://localhost/sys/ui', 'sys/ui'],
            url;

        function testWithConnectionClose(url) {
            it('accepts a connection request', function (done) {
                httpTest.connect(session, done);
            });

            it('receives a request line with an invalid request target',
               function (done) {
                   session.chan.write('GET ' + url + ' HTTP/1.1\r\n' +
                                      'Connection: close\r\n\r\n');
                   session.chan.once('end', done);
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
                   session.chan.write('GET ' + url + ' HTTP/1.1\r\n\r\n');
                   session.chan.end();
                   session.chan.once('end', done);
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
                               'HTTP/0.9', 'veryyyyyyyyyyyyyyloooooong/1.1'];

        function test(version) {
            var session = {};

            it('accepts a connection request', function (done) {
                httpTest.connect(session, done);
            });

            it('half-closes after sending a response to the request',
               function (done) {
                   session.chan.write('OPTIONS * ' + version);
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
