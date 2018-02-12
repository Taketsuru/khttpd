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

test::define immediate_eof test::khttpd_1conn_testcase {
    set sock [my socket]
    close $sock write
    test::assert_eof $sock
}

# The server closes the connection with no reply if the client sends only
# CRLF sequences and closes the connection.

test::define crlf_only test::khttpd_1conn_testcase {
    set sock [my socket]
    puts -nonewline $sock [string repeat "\r\n" 4]
    close $sock write
    test::assert_eof $sock
}

# The server sends a successful OPTIONS response if the client sends
# 'OPTIONS * HTTP/1.1 request'.

test::define options_asterisc test::khttpd_1conn_testcase {
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

test::define crlfs_followed_by_request test::khttpd_1conn_testcase {
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

test::define request_to_close_connection test::khttpd_1conn_testcase {
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

test::define invalid_protocol_version test::khttpd_testcase {
    set khttpd [my khttpd]

    foreach version {HTTP/0.0 http/1.1
	PTTH/1.1 HTTP/0.9 veryyyyyyyyyyyyyyloooooong/1.1 sht/1.1} \
    {
	my with_connection sock {
	    # The client sends a request 'OPTIONS * <version>'
	    set req "OPTIONS * $version\r\nHost: [$khttpd host]\r\n\r\n"
	    puts -nonewline $sock $req

	    # The server sends Bad Request error response
	    set response [my receive_response $sock $req]
	    test::assert_it_is_default_error_response $response
	    test::assert_it_is_the_last_response $sock $response
	    test::assert {[$response status] == 400}
	    test::assert {[$response rest] == ""}
	}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

test::define fragmented_request test::khttpd_1conn_testcase {
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

test::define size_limit_in_the_midst_of_request test::khttpd_testcase {
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
	my with_connection sock {
	    set target [string repeat x $tgtlen]
	    set req $reqline_head$target$reqline_tail$fields
	    set reqlen [string length $req]
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

test::define partial_request test::khttpd_testcase {
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
