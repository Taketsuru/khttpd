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

package require json
package require json::write
package require tcl::chan::random

test::define file_basic test::khttpd_file_testcase {
    set khttpd [my khttpd]

    foreach filesize {0 1 40 4095 4096 4097 4608 5120 5632 6144 6656 7168
	7680 16384 65536} {
	set uri_path test-$filesize
	set filename [test::local_file [file join [my fs_path] $uri_path]]
	set file [open $filename w]
	set contents [my random $filesize]
	puts -nonewline $file $contents
	close $file

	my log "size $filesize, filename $filename"

	my with_connection {sock} {
	    # The client sends a request 'GET /testfile HTTP/1.1'.
	    set req "GET /$uri_path HTTP/1.1\r\nHost: [$khttpd host]\r\n\r\n"
	    puts -nonewline $sock $req

	    # The server sends a successful response to the GET method.
	    set response [my receive_response $sock $req]
	    test::assert {[$response status] == 200}

	    # The server sends 'Content-Length' field.
	    test::assert {[$response field Content-Length] ==
		[string length $contents]}

	    # The server sends the contents of the file
	    test::assert {[$response body] eq $contents}
	    test::assert {[$response rest] == ""}

	    # The client sends a request 'OPTIONS * HTTP/1.1'.
	    set req [test::create_options_asterisc_request $khttpd]
	    puts -nonewline $sock $req

	    # The server sends a successful response to the OPTIONS method.
	    set response [my receive_response $sock $req]
	    test::assert {[$response rest] == ""}
	    test::assert_it_is_options_asterisc_response $response

	    # The client shuts down the socket.
	    close $sock write

	    # The server close the connection without sending any data.
	    test::assert_eof $sock
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define file_name_too_long test::khttpd_file_testcase {
    set khttpd [my khttpd]

    set uri /
    append uri [string repeat [string repeat x 15]/ 63]
    append uri [string repeat x 16]
    set path_max 1024
    test::assume {$path_max < [string length $uri]}

    my with_connection {sock} {
	# The client sends a request 'GET /xxxxxxxxxxxxxxxx/... HTTP/1.1'.
	set req "GET $uri HTTP/1.1\r\nHost: [$khttpd host]\r\n\r\n"
	puts -nonewline $sock $req

	# The server sends a 'Not Found' response to the GET method.
	set response [my receive_response $sock $req]
	test::assert {[$response status] == 404}
	test::assert_it_is_default_error_response $response
	test::assert {[$response rest] == ""}

	# The client sends a request 'OPTIONS * HTTP/1.1'.
	set req [test::create_options_asterisc_request $khttpd]
	puts -nonewline $sock $req

	# The server sends a successful response to the OPTIONS method.
	set response [my receive_response $sock $req]
	test::assert {[$response rest] == ""}
	test::assert_it_is_options_asterisc_response $response

	# The client shuts down the socket.
	close $sock write

	# The server close the connection without sending any data.
	test::assert_eof $sock
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define file_dot_segments test::khttpd_file_testcase {
    set khttpd [my khttpd]

    set uris {
	/../test-1
	/./test-2
	/test-3/../test-3
	/test-4/./test-4
	/test-5/test-5
	/test-6/test-6/..
	/test-7/test-7/.
	/../../test-8
    }

    my with_connection {sock} {
	foreach uri $uris {
	    set norm [test::remove_dot_segments $uri]
	    my log "uri=$uri normalized=$norm"

	    set localname [test::local_file [my fs_path]]
	    foreach comp [file split [string range $norm 1 end]] {
		file mkdir $localname
		set localname [file join $localname $comp]
	    }

	    set file [open $localname w]
	    set contents [my random 512]
	    puts -nonewline $file $contents
	    close $file

	    # The client sends a request 'GET /testfile HTTP/1.1'.
	    set req "GET /$uri HTTP/1.1\r\nHost: [$khttpd host]\r\n\r\n"
	    puts -nonewline $sock $req

	    # The server sends a successful response to the GET method if the
	    # normalized target doesn't end with '/'.
	    set response [my receive_response $sock $req]
	    if {[string match */ $norm]} {
		test::assert {[$response status] == 404}
	    } else {
		test::assert {[$response status] == 200}

		# The server sends 'Content-Length' field.
		test::assert {[$response field Content-Length] ==
		    [string length $contents]}

		# The server sends the contents of the file
		test::assert {[$response body] eq $contents}
		test::assert {[$response rest] == ""}
	    }
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

# TODO

# HEAD method

# If the target ends with /, the resource should be a directory.
# Otherwise, the server should reply with 'Not Found' response.

# charsetRules:
# mimeTypeRules:
# fsPath:
#     Test the normalization
# bypassFileCache: <size>
# etag: true/false
# logNotFound: true/false
#
