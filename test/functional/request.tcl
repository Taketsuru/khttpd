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
    test::test_chan $sock 1000 {} {
	method on_readable {chan} {
	    set data [read $chan]
	    test::assert {$data == "" && [eof $chan]}
	    my ok
	}
    }
}

proc assert_immediate_eof {sock} {
    test::test_chan $sock 1000 {} {
	method on_readable {chan} {
	    set data [read $chan]
	    test::assert {$data == "" && [eof $chan]}
	    my ok
	}
    }
}

test::define khttpd_request_crlf_only test::khttpd_1conn_testcase {
    set sock [my socket]

    # The client sends CRLFs.
    puts -nonewline $sock [string repeat "\r\n" 512]

    # The client shuts down the socket.
    close $sock write

    # The server closes the connection without sending any data.
    assert_immediate_eof $sock
}

proc create_options_asterisc_request {khttpd} {
    set req "OPTIONS * HTTP/1.1\r\n"
    append req "Host: [$khttpd host]\r\n\r\n"
    return $req
}

proc assert_receiving_response_header {sock} {
    return [test::test_chan $sock 1000 {} {
	variable response

	method _setup {} {
	    set response ""
	}

	method _teardown {msg opts} {
	    if {$opts != ""} {
		test::add_data response $response
	    }
	}

	method on_readable {chan} {
	    append response [read $chan]

	    set pos [string first "\r\n\r\n" $response]
	    if {$pos == -1} {
		test::assert {![eof $chan]}
		return
	    }

	    set rest [string range $response [expr {$pos + 4}] end]
	    set header [test::http_response_header new \
			    [string range $response 0 [expr {$pos + 3}]]]
	    my ok [list header $header rest $rest raw_data $response]
	}
    }]
}

proc receive_body {sock data_var len} {
    upvar 1 $data_var data
    set data [test::test_chan $sock 10000 [list data $data len $len] {
	method on_readable {chan} {
	    append data [read $chan]
	    set data_len [string length $data]
	    if {$data_len < $len} {
		test::assert {![eof $chan]}
		return
	    }

	    my ok $data
	}
    }]
}

proc assert_receiving_response {sock} {
    set result [assert_receiving_response_header $sock]
    set header [dict get $result header]
    try {
	set rest [dict get $result rest]
	set content_length [$header field Content-Length]

	# XXX chunk transfer is not supported yet.

	if {$content_length != ""} {
	    test::assert {[regexp -- {^(0|[1-9][0-9]*)$} $content_length]}

	    set rest_len [string length $rest]
	    if {$rest_len < $content_length} {
		receive_body $sock rest $content_length
		set rest_len [string length $rest]
	    }

	    dict set result body \
		[string range $rest 0 [expr {$content_length - 1}]]
	    dict set result rest [string range $rest $content_length end]
	} else {
	    dict set result body ""
	}
    } on error {msg opts} {
	$header destroy
	return -options $opts $msg
    }

    return $result
}

proc assert_receiving_options_asterisc_response {sock} {
    set response [assert_receiving_response_header $sock]
    set header [dict get $response header]
    try {
	test::assert {[dict get $response rest] == ""}

	# The status is 200 (success)
	test::assert {[$header status] == 200}

	# The value of Content-Length: is 0
	set content_length [$header field content-length]
	test::assert {[llength $content_length] == 1 &&
	    [lindex $content_length 0] == 0}

	# There is an Allow field
	set allow [$header field allow]
	test::assert {[llength $allow] == 1}
	test::assert {[lindex $allow 0] == "ACL, BASELINE-CONTROL,\
	    BIND, CHECKIN, CHECKOUT, CONNECT, COPY, DELETE, GET, HEAD,\
	    LABEL, LINK, LOCK, MERGE, MKACTIVITY, MKCALENDAR, MKCOL,\
	    MKREDIRECTREF, MKWORKSPACE, MOVE, OPTIONS, ORDERPATCH,\
	    PATCH, POST, PRI, PROPFIND, PROPPATCH, PUT, REBIND,\
	    REPORT, SEARCH, TRACE, UNBIND, UNCHECKOUT, UNLINK, UNLOCK,\
	    UPDATE, UPDATEREDIRECTREF, VERSION-CONTROL"}

    } on error {msg opts} {
	test::add_data response [dict get $response raw_data]
	return -options $opts $msg

    } finally {
	$header destroy
    }
}

proc check_access_log {khttpd reqs} {
    global time_fudge

    set logname [test::local_file [dict get [$khttpd logs] access-log]]

    for {set retry 0} {$retry < 4} {incr retry} {
	after 1000
	update

	set file [open $logname r]
	set ents [json::many-json2dict [read $file]]
	close $file

	if {[llength $reqs] <= [llength $ents]} {
	    break
	}
    }

    test::assert {[llength $ents] == [llength $reqs]}

    foreach entry $ents req $reqs {
	set arrival_time [dict get $entry arrivalTime]
	set completion_time [dict get $entry completionTime]
	set actual_status [dict get $entry status]
	set actual_peer_family [dict get $entry peer family]
	set actual_peer_addr [dict get $entry peer address]
	set actual_peer_port [dict get $entry peer port]
	set actual_request [dict get $entry request]

	set expected_header [dict get $req header]
	set expected_request \
	    [string range $expected_header 0 \
		 [expr {[string first "\r\n" $expected_header] + 1}]]
	set expected_status [dict get $req status]
	set expected_arrival_time \
	    [expr {[dict get $req arrival_time] / 1000.0}]
	set expected_completion_time \
	    [expr {[dict get $req completion_time] / 1000.0}]

	test::assert {$arrival_time < $completion_time}
	test::assert {abs($expected_arrival_time - $arrival_time) <
	    $time_fudge}
	test::assert {abs($expected_completion_time - $completion_time) < 
	    $time_fudge}
	test::assert {$actual_status == $expected_status}
	if {$actual_status == 400} {
	    test::assert {[string equal \
			       -length [string length $actual_request] \
			       $actual_request $expected_request]}
	} else {
	    test::assert {$actual_request eq $expected_request}
	}
	test::assert {$actual_peer_family == "inet"}
	#test::assert {$actual_peer_address == ""}
	#test::assert {$actual_peer_port == ""}
    }
}

proc assert_error_log_is_empty {khttpd} {
    set logname [test::local_file [dict get [$khttpd logs] error-log]]
    test::assert {[file size $logname] == 0}
}

test::define khttpd_request_options_asterisc test::khttpd_1conn_testcase {
    set sock [my socket]
    set khttpd [my khttpd]

    set reqs {}

    # The client sends a request 'OPTIONS * HTTP/1.1'.
    set req [create_options_asterisc_request $khttpd]
    set arrival_time [clock milliseconds]
    puts -nonewline $sock $req

    # The server sends a successful response to the OPTIONS method.
    assert_receiving_options_asterisc_response $sock
    lappend reqs [list header $req status 200 peer $sock \
		      arrival_time $arrival_time \
		      completion_time [clock milliseconds]]

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    assert_immediate_eof $sock

    # The server writes an entry for the request
    check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    assert_error_log_is_empty $khttpd
}

test::define khttpd_request_crlfs_followed_by_options_asterisc \
    test::khttpd_1conn_testcase \
{
    global message_size_max

    set sock [my socket]
    set khttpd [my khttpd]

    set reqs {}

    # The client sends a request 'OPTIONS * HTTP/1.1'.
    set req [create_options_asterisc_request $khttpd]
    set msg [string repeat "\r\n" \
		 [expr {($message_size_max - [string length $req]) / 2}]]
    append msg $req
    set arrival_time [clock milliseconds]
    puts -nonewline $sock $req

    # The server sends a successful response to the OPTIONS method.
    assert_receiving_options_asterisc_response $sock
    lappend reqs [list header $req status 200 peer $sock \
		      arrival_time $arrival_time \
		      completion_time [clock milliseconds]]

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    assert_immediate_eof $sock

    # The server writes an entry for the request
    check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    assert_error_log_is_empty $khttpd
}

test::define khttpd_request_fragmented_options_asterisc \
    test::khttpd_1conn_testcase \
{
    set sock [my socket]
    set khttpd [my khttpd]

    set reqs {}
    set req [create_options_asterisc_request $khttpd]

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
	assert_receiving_options_asterisc_response $sock
	lappend reqs [list header $req status 200 peer $sock \
			  arrival_time $arrival_time \
			  completion_time [clock milliseconds]]
    }

    # The client shuts down the socket.
    close $sock write

    # The server close the connection without sending any data.
    assert_immediate_eof $sock

    # The server writes entries for the requests
    check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    assert_error_log_is_empty $khttpd
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

	    set response [assert_receiving_response $sock]
	    set header [dict get $response header]
	    try {
		test::assert {[dict get $response rest] == ""}

		if {$message_size_max < $reqline_wo_tgt_len + $tgtlen} {
		    test::assert {[$header status] == 400}

		    # The server closes the connection
		    set connection [$header field Connection]
		    test::assert {[llength $connection] == 1 &&
			[lindex $connection 0] == "close"}
		    assert_immediate_eof $sock

		} elseif {$message_size_max < $reqlen} {
		    test::assert {[$header status] == 431}

		    # The server closes the connection
		    set connection [$header field Connection]
		    test::assert {[llength $connection] == 1 &&
			[lindex $connection 0] == "close"}
		    assert_immediate_eof $sock

		} else {
		    test::assert {[$header status] == 404}

		    # The server doesn't close the connection
		    test::assert {[llength [$header field Connection]] == 0}
		    test::assert {![eof $sock]}

		    # The client shuts down the socket.
		    close $sock write

		    # The server closes the connection without sending any
		    # data.
		    assert_immediate_eof $sock

		}

		# When the server sends the above error responses, Content-Type
		# field value is application/problem+json.
		set content_type [$header field Content-Type]
		test::assert {[llength $content_type] == 1 &&
		    [lindex $content_type 0] eq
		    "application/problem+json; charset=utf-8"}

		# The response body is a JSON object.
		set ents [json::many-json2dict [dict get $response body]]
		test::assert {[llength $ents] == 1}

		# The object's property 'status' has the same status code as
		# the status line of the response.
		test::assert {[dict get [lindex $ents 0] status] ==
		    [$header status]}

		lappend reqs [list header $req status [$header status] \
				  peer $sock arrival_time $arrival_time \
				  completion_time [clock milliseconds]]

	    } on error {msg opts} {
		test::add_data response [dict get $response raw_data]
		return -options $opts $msg

	    } finally {
		$header destroy
	    }
	} finally {
	    close $sock
	}
    }

    # The server writes entries for the requests
    check_access_log $khttpd $reqs

    # The server doesn't write any error log entries.
    assert_error_log_is_empty $khttpd
}
