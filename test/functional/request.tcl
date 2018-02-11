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

set message_size_max 16384
set time_fudge 1.0

test::define khttpd_request_empty test::khttpd_1conn_testcase {
    set sock [my socket]

    # The client shuts down the socket without sending any data.
    close $sock write

    # The server close the connection without sending any data.
    test::assert_eof $sock
}

test::define khttpd_request_crlf_only test::khttpd_1conn_testcase {
    set sock [my socket]

    # The client sends CRLFs.
    puts -nonewline $sock [string repeat "\r\n" 4]

    # The client shuts down the socket.
    close $sock write

    # The server closes the connection without sending any data.
    test::assert_eof $sock
}

test::define khttpd_request_options_asterisc test::khttpd_1conn_testcase {
    set sock [my socket]
    set khttpd [my khttpd]

    set reqs {}

    # The client sends a request 'OPTIONS * HTTP/1.1'.
    set req [test::create_options_asterisc_request $khttpd]
    set arrival_time [clock milliseconds]
    puts -nonewline $sock $req

    # The server sends a successful response to the OPTIONS method.
    test::assert_receiving_options_asterisc_response $sock
    lappend reqs [list message $req status 200 peer $sock \
		      arrival_time $arrival_time \
		      completion_time [clock milliseconds]]

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    test::assert_eof $sock

    # The server writes an entry for the request
    test::check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    test::assert_error_log_is_empty $khttpd
}

test::define khttpd_request_crlfs_followed_by_options_asterisc \
    test::khttpd_1conn_testcase \
{
    global message_size_max

    set sock [my socket]
    set khttpd [my khttpd]

    set reqs {}

    # The client sends a request 'OPTIONS * HTTP/1.1'.
    set msg "\r\n\r\n\r\n"
    set req [test::create_options_asterisc_request $khttpd]
    append msg $req
    set arrival_time [clock milliseconds]
    puts -nonewline $sock $msg

    # The server sends a successful response to the OPTIONS method.
    test::assert_receiving_options_asterisc_response $sock
    lappend reqs [list message $req status 200 peer $sock \
		      arrival_time $arrival_time \
		      completion_time [clock milliseconds]]

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    test::assert_eof $sock

    # The server writes an entry for the request
    test::check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    test::assert_error_log_is_empty $khttpd
}

test::define khttpd_request_fragmented_options_asterisc \
    test::khttpd_1conn_testcase \
{
    set sock [my socket]
    set khttpd [my khttpd]

    set reqs {}
    set req [test::create_options_asterisc_request $khttpd]

    for {set splitpoint 1} {$splitpoint < [string length $req]} \
	{incr splitpoint} \
    {
	# The client sends a request 'OPTIONS * HTTP/1.1' splitted into 2
	# segments.
	set first_half [string range $req 0 [expr {$splitpoint - 1}]]
	set second_half [string range $req $splitpoint end]

	puts -nonewline $sock $first_half

	after 100
	update

	set arrival_time [clock milliseconds]
	puts -nonewline $sock $second_half

	# The server sends a successful response to the OPTIONS request.
	test::assert_receiving_options_asterisc_response $sock
	lappend reqs [list message $req status 200 peer $sock \
			  arrival_time $arrival_time \
			  completion_time [clock milliseconds]]
    }

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    test::assert_eof $sock

    # The server writes entries for the requests
    test::check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    test::assert_error_log_is_empty $khttpd
}

test::define khttpd_request_size_limit_in_request test::khttpd_testcase {
    global message_size_max

    set khttpd [my khttpd]

    set reqs {}

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
	set sock [[my khttpd] connect]
	try {
	    set target [string repeat x $tgtlen]
	    set arrival_time [clock milliseconds]
	    set req $reqline_head$target$reqline_tail$fields
	    set reqlen [string length $req]
	    puts -nonewline $sock $req

	    set response [test::assert_receiving_response $sock OPTIONS]
	    try {
		test::assert {[$response rest] == ""}

		if {$message_size_max < $reqline_wo_tgt_len + $tgtlen} {
		    # The request line is too large

		    # The server sends Bad Request response.
		    test::assert {[$response status] == 400}

		    # The server closes the connection
		    set connection [$response field Connection]
		    test::assert {[llength $connection] == 1 &&
			[lindex $connection 0] == "close"}
		    test::assert_eof $sock

		} elseif {$message_size_max < $reqlen} {
		    # The request header field is too large

		    # The server sends Request header field too large response.
		    test::assert {[$response status] == 431}

		    # The server closes the connection
		    set connection [$response field Connection]
		    test::assert {[llength $connection] == 1 &&
			[lindex $connection 0] == "close"}
		    test::assert_eof $sock

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

		# When the server sends the above error responses, Content-Type
		# field value is application/problem+json.
		set content_type [$response field Content-Type]
		test::assert {[llength $content_type] == 1 &&
		    [lindex $content_type 0] eq
		    "application/problem+json; charset=utf-8"}

		# The response body is a JSON object.
		set ents [json::many-json2dict [$response body]]
		test::assert {[llength $ents] == 1}

		# The object's property 'status' has the same status code as
		# the status line of the response.
		test::assert {[dict get [lindex $ents 0] status] ==
		    [$response status]}

		lappend reqs [list message $req status [$response status] \
				  peer $sock arrival_time $arrival_time \
				  completion_time [clock milliseconds]]

	    } on error {msg opts} {
		test::add_data response [$response response]
		return -options $opts $msg

	    } finally {
		$response destroy
	    }
	} finally {
	    close $sock
	}
    }

    # The server writes entries for the requests
    test::check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    test::assert_error_log_is_empty $khttpd
}
