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

namespace eval test {
    namespace eval fastcgi {
	namespace path ::test

	variable type_id
	set type_id(begin_request)	1
	set type_id(abort_request)	2
	set type_id(end_request)	3
	set type_id(params)		4
	set type_id(stdin)		5
	set type_id(stdout)		6
	set type_id(stderr)		7
	set type_id(data)		8
	set type_id(get_values)		9
	set type_id(get_values_result)	10
	set type_id(unknown_type)	11

	variable type_name
	set type_name(1)	begin_request
	set type_name(2)	abort_request
	set type_name(3)	end_request
	set type_name(4)	params
	set type_name(5)	stdin
	set type_name(6)	stdout
	set type_name(7)	stderr
	set type_name(8)	data
	set type_name(9)	get_values
	set type_name(10)	get_values_result
	set type_name(11)	unknown_type

	variable is_management_record_type
	set is_management_record_type(1)	0
	set is_management_record_type(2)	0
	set is_management_record_type(3)	0
	set is_management_record_type(4)	0
	set is_management_record_type(5)	0
	set is_management_record_type(6)	0
	set is_management_record_type(7)	0
	set is_management_record_type(8)	0
	set is_management_record_type(9)	1
	set is_management_record_type(10)	1
	set is_management_record_type(11)	1

	variable is_client_record_type
	set is_client_record_type(1)	1
	set is_client_record_type(2)	1
	set is_client_record_type(3)	0
	set is_client_record_type(4)	1
	set is_client_record_type(5)	1
	set is_client_record_type(6)	0
	set is_client_record_type(7)	0
	set is_client_record_type(8)	1
	set is_client_record_type(9)	1
	set is_client_record_type(10)	0
	set is_client_record_type(11)	0

	variable protocol_status
	set protocol_status(request_complete) 0
	set protocol_status(cant_mpx_conn) 1
	set protocol_status(overloaded) 2
	set protocol_status(unknown_role) 3

	variable content_length_max 65535

	proc read_name_value_length {pos_var payload} {
	    upvar $pos_var pos 
	    assert {[binary scan $payload "x$pos c" len] == 1}

	    if {0 <= $len} {
		incr pos

	    } else {
		assert {[binary scan $payload "x$pos I" len] == 1}
		incr pos 4
		set len [expr {$len & 0x7fffffff}]
		assert {0x80 <= $len}
	    }

	    return $len
	}

	proc expect_name_value_pairs {payload} {
	    set payload_len [string length $payload]
	    set pos 0
	    while {$pos < $payload_len} {
		set name_len [read_name_value_length pos $payload]
		set value_len [read_name_value_length pos $payload]
		assert {$pos + $name_len + $value_len <= $payload_len}

		set name [string range $payload $pos \
			      [expr {$pos + $name_len - 1}]]
		incr pos $name_len

		set value [string range $payload $pos \
			       [expr {$pos + $value_len - 1}]]
		incr pos $value_len

		lappend result $name $value
	    }

	    return $result
	}

	proc name_value_length {len} {
	    if {$len < 0x80} {
		return [binary format c $len]
	    }
	    return [binary format I [expr {$len | 0x80000000}]]
	}

	proc name_value_pair {name value} {
	    append result [name_value_length [string length $name]]
	    append result [name_value_length [string length $value]]
	    append result $name $value
	    return $result
	}

	proc dump {data} {
	    binary scan $data c* bytes
	    puts [join [lmap byte $bytes { format %02x $byte }]]
	}

	proc construct_record {type cnt} {
	    variable type_id
	    variable is_management_record_type

	    if {$type in [array names type_id]} {
		set type $type_id($type)
	    }

	    set reqid [expr {$is_management_record_type($type) ? 0 : 1}]
	    set len [string length $cnt]
	    set padding [expr {-$len & 7}]
	    set hdr [binary format ccSScc 1 $type $reqid $len $padding 0]
	    set pad [string repeat "\0" $padding]

	    return $hdr$cnt$pad
	}

	proc expect_get_values_record {record} {
	    variable type_id

	    assert {[$record type] == $type_id(get_values)}
	    set payload [$record payload]
	    set nvlist [expect_name_value_pairs $payload]

	    foreach {name value} $nvlist {
		assert {$name in
		    {FCGI_MAX_CONNS FCGI_MAX_REQS FCGI_MPXS_CONNS}}
		assert {$value eq ""}
	    }
	}

	proc get_values_result_record {request results} {
	    variable type_id

	    set payload ""
	    set nvlist [expect_name_value_pairs [$request payload]]
	    foreach {name empty} $nvlist {
		if {[dict exists $results $name]} {
		    set value [dict get $results $name]
		    append payload [name_value_pair $name $value]
		}
	    }

	    return [construct_record get_values_result $payload]
	}

	proc receive_record {client {previous ""}} {
	    set result [record new]

	    if {$previous ne "" && [$result add_data [$previous rest]]} {
		return $result
	    }

	    try {
		test_chan -props [list result $result] $client {
		    method on_readable {chan} {
			variable result
			if {[$result add_data [read $chan]]} {
			    my done
			} else {
			    assert {![chan eof $chan]}
			}
		    }
		}

	    } on error {msg opts} {
		$result destroy
		return -options $opts $msg
	    }

	    return $result
	}

	proc exchange_config_values {client} {
	    set result [receive_record $client]
	    try {
		expect_get_values_record $result
		puts -nonewline $client \
		    [get_values_result_record $result \
			 [dict create FCGI_MPXS_CONNS 0]]
	    } finally {
		$result destroy
	    }
	}

	proc receive_params {client {prev_record ""}} {
	    variable type_id

	    set data ""
	    while {1} {
		set params_record [receive_record $client $prev_record]
		assert {[$params_record type] == $type_id(params)}
		$prev_record destroy
		set prev_record $params_record

		if {[$params_record payload] eq ""} {
		    break
		}

		append data [$params_record payload]
	    }

	    set params [expect_name_value_pairs $data]

	    return [list $params $prev_record]
	}

	proc receive_stdin {client {prev_record ""}} {
	    variable type_id

	    set data ""
	    while {1} {
		set record [receive_record $client $prev_record]
		assert {[$record type] == $type_id(stdin)}
		$prev_record destroy
		set prev_record $record

		if {[$record payload] eq ""} {
		    break
		}

		append data [$params_record payload]
	    }

	    return [list $data $prev_record]
	}

	proc send_output {type client data} {
	    variable content_length_max

	    test::assume {$type in {stdout stderr}}

	    while {$data ne ""} {
		set chunk [string range $data 0 $content_length_max]
		set data [string range $data $content_length_max+1 end]
		puts -nonewline $client [construct_record $type $chunk]
	    }
	}

	proc close_output {type client} {
	    test::assume {$type in {stdout stderr}}
	    puts -nonewline $client [construct_record $type ""]
	}

	proc send_end_request {client {app_status 0} {protocol_status 0}} {
	    set cnt [binary format Icc3 $app_status $protocol_status {0 0 0}]
	    puts -nonewline $client [construct_record end_request $cnt]
	}
    }
}

oo::class create test::fastcgi::record {
    variable _data
    variable _type _content_length _padding_length
    variable _payload_dict

    constructor {} {
	set _data ""
	set _type ""

	oo::objdefine [self] {
	    method add_data {data} {
		tailcall my _add_header $data
	    }
	}
    }

    method is_complete {} {
	return [expr {$_type ne "" && 
		      8 + $_content_length + $_padding_length <= 
		      [string length $_data]}]
    }

    method type {} {
	return $_type
    }

    method content_length {} {
	return $_content_length
    }

    method payload {} {
	test::assume {[my is_complete]}
	set end [expr {8 + $_content_length - 1}]
	return [string range $_data 8 $end]
    }

    method payload_dict {} {
	return $_payload_dict
    }

    method rest {} {
	set pos [expr {8 + $_content_length + $_padding_length}]
	return [string range $_data $pos end]
    }

    method _add_header {data} {
	variable ::test::fastcgi::type_id
	variable ::test::fastcgi::type_name
	variable ::test::fastcgi::is_client_record_type
	variable ::test::fastcgi::is_management_record_type

	append _data $data
	if {[string length $_data] < 8} {
	    return 0
	}

	binary scan $_data "ccSScc" version _type request_id \
	    _content_length _padding_length reserved
	set _content_length [expr {$_content_length & 0xffff}]

	test::assert {$version == 1}
	test::assert {0 < $_type && $_type <= 11}
	test::assert {$is_client_record_type($_type)}
	test::assert {$request_id ==
	    $is_management_record_type($_type) ? 0 : 1}
	test::assert {0 <= $_padding_length && $_padding_length < 8}
	test::assert {$reserved == 0}
	test::assert {($_content_length + $_padding_length) % 8 == 0}

	oo::objdefine [self] \
	    "method add_data {data} { tailcall my _add_payload \$data }"
	tailcall my _add_payload ""
    }

    method _add_payload {data} {
	variable ::test::fastcgi::type_name

	append _data $data
	if {![my is_complete]} {
	    return 0
	}

	my _validate_$type_name($_type)_payload
	return 1
    }

    method _validate_begin_request_payload {} {
	test::assert {[binary scan [my payload] "Scc5" role flags reserved]
	    == 3}
	test::assert {1 <= $role && $role <= 3}
	test::assert {$flags == 0 || $flags == 1}
	foreach byte $reserved {
	    test::assert {$byte == 0}
	}

	dict set _payload_dict role $role
	dict set _payload_dict flags $flags
    }

    method _validate_end_request_payload {} {
    }

    method _validate_params_payload {} {
    }

    method _validate_stdin_payload {} {
    }

    method _validate_data_payload {} {
    }

    method _validate_get_values_payload {} {
    }
}

oo::class create test::fastcgi::client {
    variable _chan _addr _port

    constructor {chan addr port} {
	set _chan $chan
	set _addr $addr
	set _port $port
    }

    destructor {
	chan close $_chan
    }

    method chan {} {
	return $_chan
    }
}

oo::class create test::fastcgi::upstream {
    variable _cmd _chan _clients _port

    constructor {cmd} {
	variable ::test::host_addr
	set _cmd $cmd
	set _chan [socket -server "[self] accept" -myaddr $host_addr 0]
	set _port [lindex [chan configure $_chan -sockname] 2]
	set _clients {}
	chan configure $_chan -blocking 0 -buffering none \
	    -encoding binary -translation binary
    }

    destructor {
	foreach client $_clients {
	    $client destroy
	}
	chan close $_chan
    }

    method accept {chan addr port} {
	chan configure $chan -blocking 0 -buffering none \
	    -encoding binary -translation binary
	set client [test::fastcgi::client new $chan $addr $port]
	lappend _clients $client
	eval $_cmd $client
    }

    method clients {} {
	return $_clients
    }

    method get_config {} {
	set sockname [chan configure $_chan -sockname]
	set addr [json::write object family [json::write string inet] \
		      address [json::write string [lindex $sockname 0]] \
		      port [lindex $sockname 2]]
	return [json::write object address $addr]
    }

    method chan {} {
	return $_chan
    }
}

oo::class create test::fastcgi::testcase {
    superclass test::khttpd_file_testcase
    variable _upstreams _client_count

    method upstreams {} {
	return $_upstreams
    }

    method add_client {client} {
	incr _client_count
    }

    method client_chan {{upstream_index 0} {client_index 0}} {
	set upstream [lindex $_upstreams $upstream_index]
	set client [lindex [$upstream clients] $client_index]
	return [$client chan]
    }

    method wait_client_arrival {} {
	vwait [my varname _client_count]
    }

    method _setup {} {
	my _setup_upstreams
	next
    }

    method _teardown {} {
	next
	foreach upstream $_upstreams {
	    $upstream destroy
	}
    }

    method _script_uri_dir {} {
	return /0/1/2
    }

    method _setup_upstreams {} {
	lappend _upstreams [test::fastcgi::upstream new \
			    "[self] add_client"]
    }

    method _create_fcgi_location_config {} {
	set khttpd [my khttpd]
	set config [list id [json::write string [test::uuid_new]] \
			type [json::write string khttpd_fastcgi] \
			server [json::write string [my server_id]] \
			path [json::write string [my _script_uri_dir]] \
		        scriptSuffix [json::write string .fcgi] \
			fsPath [json::write string \
				    [$khttpd remote_path [my fs_path]]]]

	set upstream_confs [lmap upstream $_upstreams {
	    $upstream get_config
	}]
	lappend config upstreams [json::write array {*}$upstream_confs]

	return [json::write object {*}$config]
    }

    method _create_locations_config {} {
	return [concat [list [my _create_fcgi_location_config]] [next]]
    }
}

test::define fcgi_get_basic test::fastcgi::testcase {
    variable ::test::fastcgi::type_id
    variable ::test::host_addr
    variable ::test::target_addr
    variable ::test::http_port
    variable ::test::server_software
    variable ::test::fastcgi::type_id

    set khttpd [my khttpd]

    my wait_client_arrival
    set client [my client_chan]
    test::fastcgi::exchange_config_values $client

    my with_connection {sock} {
	# Create a script file
	set script_fs_path \
	    [test::local_file [file join [my fs_path] "test.fcgi"]]
	set script_file [open $script_fs_path w]
	close $script_file

	# The client sends a GET request for the script.
	set script_name [my _script_uri_dir]/test.fcgi
	set req "GET $script_name/x/hogehoge HTTP/1.1\r\n"
	append req "Host: [$khttpd host]\r\n"
	append req "X-Test: foobar\r\n\r\n"
	puts -nonewline $sock $req

	# The server sends a begin_request record to the fastcgi server.
	set begin_request [test::fastcgi::receive_record $client]
	test::assert {[$begin_request type] == $type_id(begin_request)}
	set payload [$begin_request payload_dict]

	# The role is FCGI_RESPONDER
	test::assert {[dict get $payload role] == 1}

	# The server sends param records to the fastcgi server
	lassign [test::fastcgi::receive_params $client $begin_request] \
	    params last_record

	# Check mandatory params
	test::assert {![dict exists $params CONTENT_LENGTH]}
	test::assert {![dict exists $params CONTENT_TYPE]}
	test::assert {[dict get $params GATEWAY_INTERFACE] eq "CGI/1.1"}
	test::assert {[dict get $params PATH_INFO] eq "/x/hogehoge"}
	test::assert {[dict get $params PATH_TRANSLATED] eq \
			  [$khttpd remote_path \
			       [file join [my fs_path] "x/hogehoge"]]}
	test::assert {[dict get $params QUERY_STRING] eq ""}
	test::assert {[dict get $params REMOTE_ADDR] eq $host_addr}
	test::assert {[dict get $params REQUEST_METHOD] eq "GET"}
	test::assert {[dict get $params SCRIPT_NAME] eq $script_name}
	test::assert {[dict get $params SERVER_NAME] eq $target_addr}
	test::assert {[dict get $params SERVER_PORT] eq $http_port}
	test::assert {[dict get $params SERVER_PROTOCOL] eq "HTTP/1.1"}
	test::assert {[dict get $params SERVER_SOFTWARE] eq $server_software}
	test::assert {[dict get $params HTTP_X_TEST] eq "foobar"}

	# The server send an empty stdin record to the fastcgi server
	lassign [test::fastcgi::receive_stdin client $last_record] \
	    stdin last_record

	# The fastcgi server sends the response.
	set body {<!DOCTYPE html><html><head><meta charset="utf-8">}
	append body {<title>The document root</title></head>}
	append body {<body>Hello World!</body></html>}
	set content_type text/html
	set resp "Content-Type: $content_type\n"
	append resp "Content-Length: [string length $body]\n"
	append resp "X-Test: foobar\n"
	append resp "\n"
	append resp $body
	test::fastcgi::send_output stdout $client $resp
	test::fastcgi::close_output stdout $client
	test::fastcgi::send_end_request $client

	# The server relays the response to the client.
	set response [my receive_response $sock $req]
	test::assert {[$response status] == 200}
	test::assert {[$response field Content-Type] eq $content_type}
	test::assert {[$response field Content-Length] ==
	    [string length $body]}
	test::assert {[$response field X-Test] eq "foobar"}
	test::assert {[$response body] eq $body}
    }

    my check_access_log
    test::assert_error_log_is_empty $khttpd
}

# TODO

# HEAD method

# property 'scriptSuffix'

# property 'fsPath'

# property 'upstreams'

# property 'upstreams.address'
