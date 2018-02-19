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
package require test
package require test_http
package require test_khttpd

# The server closes the connection with no reply if the client closes a
# connection without sending any data.

test::define http_immediate_eof test::khttpd_1conn_testcase {
    set sock [my socket]
    close $sock write
    test::assert_eof $sock
}

# The server closes the connection with no reply if the client sends only
# CRLF sequences and closes the connection.

test::define http_crlf_only test::khttpd_1conn_testcase {
    set sock [my socket]
    puts -nonewline $sock [string repeat "\r\n" 4]
    close $sock write
    test::assert_eof $sock
}

# The server sends a successful OPTIONS response if the client sends
# 'OPTIONS * HTTP/1.1 request'.

test::define http_options_asterisc test::khttpd_1conn_testcase {
    set sock [my socket]
    set khttpd [my khttpd]

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

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_crlfs_followed_by_request test::khttpd_1conn_testcase {
    variable ::test::message_size_max

    set sock [my socket]
    set khttpd [my khttpd]

    # The client sends a request 'OPTIONS * HTTP/1.1'.
    set msg "\r\n\r\n\r\n"
    set req [test::create_options_asterisc_request $khttpd]
    append msg $req
    puts -nonewline $sock $msg

    # The server sends a successful response to the OPTIONS method.
    set response [my receive_response $sock $req]
    test::assert {[$response rest] == ""}
    test::assert_it_is_options_asterisc_response $response

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    test::assert_eof $sock

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_request_to_close_connection test::khttpd_1conn_testcase {
    set sock [my socket]
    set khttpd [my khttpd]

    # The client sends a request 'OPTIONS * HTTP/1.1' with 'Connection:
    # close' field.
    set req "OPTIONS * HTTP/1.1\r\n"
    append req "Host: [$khttpd host]\r\n"
    append req "Connection: close\r\n\r\n"
    puts -nonewline $sock $req

    # The server sends a successful response to the OPTIONS method.
    set response [my receive_response $sock $req]
    test::assert {[$response rest] == ""}
    test::assert_it_is_the_last_response $sock $response
    test::assert_it_is_options_asterisc_response $response

    # The client sends a request but there is no access log entry for the
    # request.
    set req [test::create_options_asterisc_request $khttpd]
    puts -nonewline $sock $req

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_invalid_protocol_version test::khttpd_testcase {
    set khttpd [my khttpd]

    foreach version {HTTP/0.0 http/1.1
	PTTH/1.1 HTTP/0.9 veryyyyyyyyyyyyyyloooooong/1.1 sht/1.1
	" HTTP/1.1" "HTTP/1.1 " HTTP/1.a HTTP/a.0 HTTP/2.0} {
	my with_connection sock {
	    # The client sends a request 'OPTIONS * <version>'
	    set req "OPTIONS * $version\r\nHost: [$khttpd host]\r\n\r\n"
	    puts -nonewline $sock $req

	    # The server sends 'Http Version Not Supported' or 'Bad Request'
	    # error response
	    set response [my receive_response $sock $req]
	    test::assert_it_is_default_error_response $response
	    test::assert_it_is_the_last_response $sock $response
	    if {[string match {HTTP/[0-9].[0-9]} $version]} {
		test::assert {[$response status] == 505}
	    } else {
		test::assert {[$response status] == 400}
	    }
	    test::assert {[$response rest] == ""}
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_fragmented_request test::khttpd_1conn_testcase {
    set sock [my socket]
    set khttpd [my khttpd]
    set req [test::create_options_asterisc_request $khttpd]

    for {set splitpoint 1} {$splitpoint < [string length $req]} \
	{incr splitpoint} \
    {
	# The client sends a request 'OPTIONS * HTTP/1.1' splitted
	# into 2 segments.
	set arrival_time [expr {[clock milliseconds] / 1000.0}]
	set first_half [string range $req 0 [expr {$splitpoint - 1}]]
	set second_half [string range $req $splitpoint end]
	puts -nonewline $sock $first_half
	after 100
	update
	puts -nonewline $sock $second_half

	# The server sends a successful response to the OPTIONS request.
	set response [my receive_response $sock $req $arrival_time]
	test::assert {[$response rest] == ""}
	test::assert_it_is_options_asterisc_response $response
    }

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    test::assert_eof $sock

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_request_too_long test::khttpd_testcase {
    variable ::test::message_size_max

    set khttpd [my khttpd]
    set reqline_head "OPTIONS "
    set reqline_tail " HTTP/1.1\r\n"
    set fields "Host: [$khttpd host]\r\n\r\n"

    set reqline_wo_tgt_len \
	[expr {[string length $reqline_head] + [string length $reqline_tail]}]
    set req_wo_tgt_len \
	[expr {$reqline_wo_tgt_len + [string length $fields]}]

    set tgtlen_list {}

    # limit just after the request line
    lappend tgtlen_list [expr {$message_size_max - $reqline_wo_tgt_len}]

    # limit in the CRLF sequence of the request line
    lappend tgtlen_list [expr {$message_size_max - $reqline_wo_tgt_len + 1}]
    lappend tgtlen_list [expr {$message_size_max - $reqline_wo_tgt_len + 2}]

    # limit just after the first character of the first header field.
    lappend tgtlen_list [expr {$message_size_max - $reqline_wo_tgt_len - 1}]

    # limit in the 2 CRLFs sequence at the end of the request.
    for {set i 0} {$i <= 4} {incr i} {
	lappend tgtlen_list [expr {$message_size_max - $req_wo_tgt_len + $i}]
    }

    set reqline_wo_tgt_len \
	[expr {[string length $reqline_head] + [string length $reqline_tail]}]

    foreach tgtlen $tgtlen_list {
	puts [[test::test_driver instance] log_chan] "target_len: $tgtlen"

	my with_connection sock {
	    set target "/[string repeat x [expr {$tgtlen - 1}]]"
	    set req $reqline_head$target$reqline_tail$fields
	    set reqlen [string length $req]
	    puts [[test::test_driver instance] log_chan] \
		"reqlen: [string length $req]"
	    puts -nonewline $sock $req

	    set response [my receive_response $sock $req]
	    test::assert {[$response rest] == ""}
	    test::assert_it_is_default_error_response $response

	    if {$message_size_max < $reqline_wo_tgt_len + $tgtlen} {
		# The request line is too large

		# The server sends Bad Request response.
		test::assert {[$response status] == 400}

		test::assert_it_is_the_last_response $sock $response

	    } elseif {$message_size_max < $reqlen} {
		# The request header field is too large

		# The server sends Request header field too large response.
		test::assert {[$response status] == 431}

		test::assert_it_is_the_last_response $sock $response

	    } else {
		# The request is small enough but the request target
		# xxx... is not found.

		# The server sends Not Found response.
		test::assert {[$response status] == 404}

		# The server doesn't close the connection
		test::assert {[llength [$response field Connection]] == 0}
		test::assert {![eof $sock]}

		# The client shuts down the socket.
		close $sock write

		# The server closes the connection without sending any
		# data.
		test::assert_eof $sock
	    }
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_partial_request test::khttpd_testcase {
    set khttpd [my khttpd]
    set req [test::create_options_asterisc_request $khttpd]
    set len [string length $req]

    for {set i 0} {$i < $len - 1} {incr i} {
	my with_connection {sock} {
	    set preq [string range $req 0 $i]
	    puts -nonewline $sock $preq

	    # The client shuts down the socket.
	    close $sock write

	    set response [my receive_response $sock $preq]

	    # The server sends Bad Request response.
	    test::assert {[$response status] == 400}
	    test::assert_it_is_default_error_response $response
	    test::assert_it_is_the_last_response $sock $response
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_nonchunked_request_body test::khttpd_1conn_testcase {
    set sock [my socket]
    set khttpd [my khttpd]
    set hdr "OPTIONS * HTTP/1.1\r\n"
    append hdr "Host: [$khttpd host]\r\n"

    set optreq [test::create_options_asterisc_request $khttpd]

    foreach content_length {0 1 2 20 16384} {
	set body [string repeat x $content_length]
	set req "${hdr}Content-Length: $content_length\r\n\r\n$body"

	puts -nonewline $sock $req

	set response [my receive_response $sock $req]

	# The server ignores the request body and sends a OPTIONS response.
	test::assert {[$response rest] == ""}
	test::assert_it_is_options_asterisc_response $response

	# The client sends an OPTIONS request and the server sends a reply as
	# usual.
	puts -nonewline $sock $optreq
	set response [my receive_response $sock $optreq]
	test::assert {[$response rest] == ""}
	test::assert_it_is_options_asterisc_response $response
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

proc test_request_chunk {obj chunk_size chunk_ext trailer partial} {
    set khttpd [$obj khttpd]
    set req "OPTIONS * HTTP/1.1\r\n"
    append req "Host: [$khttpd host]\r\n"
    append req "Transfer-Encoding: chunked\r\n\r\n"
    set hdrlen [string length $req]
    set optreq [test::create_options_asterisc_request $khttpd]

    if {0 < $chunk_size} {
	append req "[format {%x} $chunk_size]$chunk_ext\r\n"
	set chunk_end [string length $req]
	append req [string repeat x $chunk_size]
	append req "\r\n"
    }

    set last_chunk_pos [string length $req]
    append req "0\r\n$trailer\r\n"
    set reqlen [string length $req]

    if {0 < $chunk_size} {
	for {set i $hdrlen} {$i <= $chunk_end} {incr i} {
	    lappend split_points $i
	}
	for {set i [expr {$last_chunk_pos - 2}]} {$i < $reqlen} {incr i} {
	    lappend split_points $i
	}
    } else {
	for {set i $last_chunk_pos} {$i <= $reqlen} {incr i} {
	    lappend split_points $i
	}
    }

    foreach split_pos $split_points {
	$obj with_connection {sock} {
	    set first_half [string range $req 0 $split_pos-1]
	    set second_half [string range $req $split_pos end]
	    puts -nonewline $sock $first_half

	    if {$partial && $split_pos < $reqlen} {
		close $sock write

	    } elseif {$second_half ne ""} {
		after 100
		update
		puts -nonewline $sock $second_half
	    }

	    set response [$obj receive_response $sock $req]

	    if {$partial && $split_pos < $reqlen} {
		# The server ignores the request body and sends a OPTIONS
		# response.
		test::assert {[$response rest] == ""}
		test::assert {[$response status] == 400}
		test::assert_it_is_default_error_response $response
		test::assert_it_is_the_last_response $sock $response

	    } else {
		# The server ignores the request body and sends a OPTIONS
		# response.
		test::assert {[$response rest] == ""}
		test::assert_it_is_options_asterisc_response $response

		# The client sends an OPTIONS request and the server sends a
		# reply as usual.
		puts -nonewline $sock $optreq
		set response [$obj receive_response $sock $optreq]
		test::assert {[$response rest] == ""}
		test::assert_it_is_options_asterisc_response $response
	    }
	}
    }
}

test::define http_request_chunk test::khttpd_testcase {
    set khttpd [my khttpd]

    foreach chunk_size {0 1 2 20 16384} {
	test_request_chunk [self] $chunk_size "" "" 0
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_partial_request_chunk test::khttpd_testcase {
    set khttpd [my khttpd]

    foreach chunk_size {0 1 2 20 16384} {
	test_request_chunk [self] $chunk_size "" "" 1
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_request_chunk_and_trailer test::khttpd_testcase {
    set khttpd [my khttpd]

    foreach chunk_size {0 1 2 20 16384} {
	test_request_chunk [self] $chunk_size \
	    "" "X-Trailer: hoge\r\n" 0
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define http_partial_request_chunk_and_trailer test::khttpd_testcase {
    set khttpd [my khttpd]

    foreach chunk_size {0 1 2 20 16384} {
	test_request_chunk [self] $chunk_size \
	    "" "X-Trailer: hoge\r\n" 1
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

# testcase: Bad Request response is sent while the server is parsing
# Content-Type field.

# testcase: Multiple 'Bad Request' cases.

# Test URI escape/unescape is done correctly.

# Query string part of target URI is also normalized.  Test this.
# - Is the query string is escaped/unescaped correctly?
# - The dot segment removal must not be applied to query parts.  Test this.

# Is the dot segment just before the query string normalized correctly?
