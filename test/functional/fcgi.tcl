# -*- mode: tcl -*-
#
# Copyright (c) 2018 Taketsuru <taketsuru11@gmail.com>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

test::define fcgi_get_basic test::fastcgi::get_basic_testcase {
    variable _script_name
    variable _resp_body

    set khttpd [my khttpd]

    # Create a script file
    set script_fs_path \
	[test::local_file [file join [my fs_path] "test.fcgi"]]
    set script_file [open $script_fs_path w]
    close $script_file

    set req "GET $_script_name/x/hogehoge HTTP/1.1\r\n"
    append req "Host: [$khttpd host]\r\n"
    append req "X-Test: foobar\r\n\r\n"

    my with_connection {sock} {
	for {set i 0} {$i < 3} {incr i} {
	    # The client sends a GET request for the script.
	    puts -nonewline $sock $req

	    # The server relays the response to the client.
	    set response [my receive_response $sock $req]
	    test::assert {[$response status] == 200}
	    test::assert {[$response field Content-Type] eq "text/html"}
	    test::assert {[$response field Content-Length] ==
		[string length $_resp_body]}
	    test::assert {[$response field X-Test-Response] eq "foobar"}
	    test::assert {[$response body] eq $_resp_body}
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define fcgi_get_splay test::fastcgi::get_basic_testcase {
    variable _script_name
    variable _resp_body

    set khttpd [my khttpd]

    # Create a script file
    set script_fs_path \
	[test::local_file [file join [my fs_path] "test.fcgi"]]
    set script_file [open $script_fs_path w]
    close $script_file

    for {set i 0} {$i < 64} {incr i} {
	set req "GET $_script_name/x/hogehoge HTTP/1.1\r\n"
	append req "Host: [$khttpd host]\r\n"
	append req "X-Test: $i\r\n\r\n"

	my with_connection {sock} {
	    # The client sends a GET request for the script.
	    puts -nonewline $sock $req

	    # The server relays the response to the client.
	    set response [my receive_response $sock $req]
	    test::assert {[$response status] == 200}
	    test::assert {[$response field Content-Type] eq "text/html"}
	    test::assert {[$response field Content-Length] ==
		[string length $_resp_body]}
	    test::assert {[$response field X-Test-Response] eq "$i"}
	    test::assert {[$response body] eq $_resp_body}
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define fcgi_get_splay_ignoring_response \
    test::fastcgi::get_basic_testcase \
{
    variable _script_name

    set khttpd [my khttpd]

    # Create a script file
    set script_fs_path \
	[test::local_file [file join [my fs_path] "test.fcgi"]]
    set script_file [open $script_fs_path w]
    close $script_file

    for {set i 0} {$i < 64} {incr i} {
	set req "GET $_script_name/x/hogehoge HTTP/1.1\r\n"
	append req "Host: [$khttpd host]\r\n"
	append req "X-Test: $i\r\n\r\n"

	my with_connection {sock} {
	    # The client sends a GET request for the script.
	    puts -nonewline $sock $req
	}
    }

    test::assert_error_log_is_empty $khttpd
}

test::define fcgi_get_segmented_upstream_response test::fastcgi::testcase \
-setup {
    variable _client_factory
    variable _script_name
    variable _resp_body
    variable _resp_hdr

    set _script_name [my script_location_path]/test.fcgi

    set _resp_body {<!DOCTYPE html><html><head><meta charset="utf-8">}
    append _resp_body {<title>The document root</title></head>}
    append _resp_body {<body>Hello World!</body></html>}

    set _resp_hdr "Content-Type: text/html\n"
    append _resp_hdr "Content-Length: [string length $_resp_body]\n"

    set _client_factory [test::fastcgi::timed_client_factory new \
			     $_script_name [my fs_path] \
			     $_resp_hdr $_resp_body \
			     "::test::fastcgi::pause_client"]

    set upstream [test::fastcgi::upstream new \
		      "$_client_factory create" "" 10000]
    my add_upstream $upstream
    $upstream open

    next
} {
    variable _script_name
    variable _resp_body
    variable _client_factory

    set khttpd [my khttpd]

    # Create a script file
    set script_fs_path \
	[test::local_file [file join [my fs_path] "test.fcgi"]]
    set script_file [open $script_fs_path w]
    close $script_file

    for {set i 1} {1} {incr i} {
	$_client_factory set_counter $i

	set req "GET $_script_name/x/hogehoge HTTP/1.1\r\n"
	append req "Host: [$khttpd host]\r\n"
	append req "X-Test: $i\r\n\r\n"

	my with_connection {sock} {
	    # The client sends a GET request for the script.
	    puts -nonewline $sock $req

	    # The server relays the response to the client.
	    set response [my receive_response $sock $req]

	    test::assert {[$response status] == 200}
	    test::assert {[$response field Content-Type] eq "text/html"}
	    test::assert {[$response field Content-Length] ==
		[string length $_resp_body]}
	    test::assert {[$response field X-Test-Response] eq "$i"}
	    test::assert {[$response body] eq $_resp_body}
	}

	set client [$_client_factory last_client]
	if {![$client has_expired]} {
	    break
	}
	$client close
    }

    my check_access_log
}

test::define fcgi_premature_upstream_close test::fastcgi::testcase -setup {
    variable _client_factory
    variable _script_name
    variable _resp_body
    variable _resp_hdr

    set _script_name [my script_location_path]/test.fcgi

    set _resp_body {<!DOCTYPE html><html><head><meta charset="utf-8">}
    append _resp_body {<title>The document root</title></head>}
    append _resp_body {<body>Hello World!</body></html>}

    set _resp_hdr "Content-Type: text/html\n"
    append _resp_hdr "Content-Length: [string length $_resp_body]\n"

    set _client_factory [test::fastcgi::timed_client_factory new \
			     $_script_name [my fs_path] $_resp_hdr $_resp_body]

    set upstream [test::fastcgi::upstream new \
		      "$_client_factory create" "" 10000]
    my add_upstream $upstream
    $upstream open

    next
} {
    variable _script_name
    variable _resp_body
    variable _client_factory

    set khttpd [my khttpd]

    # Create a script file
    set script_fs_path \
	[test::local_file [file join [my fs_path] "test.fcgi"]]
    set script_file [open $script_fs_path w]
    close $script_file

    set expired 1
    for {set i 1} {$expired} {incr i} {
	$_client_factory set_counter $i

	set req "GET $_script_name/x/hogehoge HTTP/1.1\r\n"
	append req "Host: [$khttpd host]\r\n"
	append req "X-Test: $i\r\n\r\n"

	my with_connection {sock} {
	    # The client sends a GET request for the script.
	    puts -nonewline $sock $req

	    # The server relays the response to the client.
	    set response [my receive_response $sock $req]
	    set expired [[$_client_factory last_client] has_expired]

	    if {[$response status] == 500} {
		test::assert_it_is_default_error_response $response

	    } else {
		test::assert {[$response status] == 200}
		test::assert {[$response field Content-Type] eq "text/html"}
		test::assert {[$response field Content-Length] ==
		    [string length $_resp_body]}
		test::assert {[$response field X-Test-Response] eq "$i"}
		test::assert {[$response body] eq $_resp_body}
	    }
	    [$_client_factory last_client] destroy

	    # Don't let FastCGI server fail to respond.
	    $_client_factory set_counter 0

	    # The client sends a GET request for the script.
	    puts -nonewline $sock $req

	    # The server relays the response to the client.
	    set response [my receive_response $sock $req]

	    # Succeeds this time.
	    test::assert {[$response status] == 200}
	    test::assert {[$response field Content-Type] eq "text/html"}
	    test::assert {[$response field Content-Length] ==
		[string length $_resp_body]}
	    test::assert {[$response field X-Test-Response] eq "$i"}
	    test::assert {[$response body] eq $_resp_body}

	    [$_client_factory last_client] destroy
	}
    }

    my check_access_log
}

# TODO

# HEAD method

# property 'scriptSuffix'

# property 'fsPath'

# property 'upstreams'

# property 'upstreams.address'

# Send a partial request (with a request payload) to a khttpd_fcgi location and
# make the server reject because of a port.busyTimeout.
