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

	variable next_port 32768

	proc dump {data} {
	    binary scan $data c* bytes
	    return [join [lmap byte $bytes {
		format %02x [expr {$byte & 0xff}]}]]
	}

	proc scan_name_value_length {pos_var contents} {
	    upvar $pos_var pos 
	    assert {[binary scan $contents "x$pos c" len] == 1}

	    if {0 <= $len} {
		incr pos

	    } else {
		assert {[binary scan $contents "x$pos I" len] == 1}
		incr pos 4
		set len [expr {$len & 0x7fffffff}]
		assert {0x80 <= $len}
	    }

	    return $len
	}

	proc scan_name_value_pairs {contents} {
	    set contents_len [string length $contents]
	    set pos 0
	    while {$pos < $contents_len} {
		set name_len [scan_name_value_length pos $contents]
		set value_len [scan_name_value_length pos $contents]
		assert {$pos + $name_len + $value_len <= $contents_len}

		set name [string range $contents $pos \
			      [expr {$pos + $name_len - 1}]]
		incr pos $name_len

		set value [string range $contents $pos \
			       [expr {$pos + $value_len - 1}]]
		incr pos $value_len

		lappend result $name $value
	    }

	    return $result
	}

	proc scan_get_values_record {contents} {
	    variable type_id

	    set nvlist [scan_name_value_pairs $contents]

	    set result {}
	    foreach {name value} $nvlist {
		assert {$name in
		    {FCGI_MAX_CONNS FCGI_MAX_REQS FCGI_MPXS_CONNS}}
		assert {$value eq ""}
		lappend result $name
	    }

	    return $result
	}

	proc scan_begin_request {contents} {
	    test::assert {[binary scan $contents "Scc5" role flags reserved]
		== 3}
	    return [list role $role flags $flags reserved $reserved]
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

	proc construct_name_value_length {len} {
	    if {$len < 0x80} {
		return [binary format c $len]
	    }
	    return [binary format I [expr {$len | 0x80000000}]]
	}

	proc construct_name_value_pair {name value} {
	    append result [construct_name_value_length [string length $name]]
	    append result [construct_name_value_length [string length $value]]
	    append result $name $value
	    return $result
	}

	proc construct_get_values_result_record {request results} {
	    variable type_id

	    set contents ""
	    set nvlist [scan_name_value_pairs [$request contents]]
	    foreach {name empty} $nvlist {
		if {[dict exists $results $name]} {
		    set value [dict get $results $name]
		    append contents [construct_name_value_pair $name $value]
		}
	    }

	    return [construct_record get_values_result $contents]
	}

	proc send_output {type client data} {
	    variable content_length_max

	    test::assume {$type in {stdout stderr}}

	    while {$data ne ""} {
		set chunk [string range $data 0 $content_length_max]
		set data [string range $data $content_length_max+1 end]
		set record [construct_record $type $chunk]
		puts -nonewline $client $record
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
    variable _data _type _content_length _padding_length

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

    method contents {} {
	test::assume {[my is_complete]}
	set end [expr {8 + $_content_length - 1}]
	return [string range $_data 8 $end]
    }

    method rest {} {
	set pos [expr {8 + $_content_length + $_padding_length}]
	return [string range $_data $pos end]
    }

    method is_empty {} {
	return [expr {$_data eq ""}]
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
	    "method add_data {data} { tailcall my _add_contents \$data }"
	tailcall my _add_contents ""
    }

    method _add_contents {data} {
	variable ::test::fastcgi::type_name

	append _data $data
	if {![my is_complete]} {
	    return 0
	}

	set handler _validate_$type_name($_type)_contents
	set handler_type [lindex [info object call [self] $handler] 0 0]
	if {$handler_type ne "unknown"} {
	    my $handler
	}

	return 1
    }

    method _validate_begin_request_contents {} {
	set values [test::fastcgi::scan_begin_request [my contents]]
	dict with $values role flags reserved {
	    test::assert {1 <= $role && $role <= 3}
	    test::assert {$flags == 0 || $flags == 1}
	    foreach byte $reserved {
		test::assert {$byte == 0}
	    }
	}
    }
}

oo::class create test::fastcgi::client {
    variable _upstream _chan _addr _port
    variable _record _records
    variable _params_contents _params

    constructor {upstream chan addr port} {
	set _upstream $upstream
	set _chan $chan
	set _addr $addr
	set _port $port
	set _record [test::fastcgi::record new]
	set _params_contents ""
	lappend _records $_record
	chan event $chan readable "[self] on_readable"
    }

    destructor {
	if {$_chan ne ""} {
	    chan close $_chan
	}
	$_upstream remove_client [self]
    }

    method chan {} {
	return $_chan
    }

    method close {} {
	chan close $_chan
	set _chan ""
    }

    method validate_params {} {
    }

    method handle_params {} {
	test::assume {[$_record type] == $::test::fastcgi::type_id(params)}

	set contents [$_record contents]
	if {$contents eq ""} {
	    set _params \
		[test::fastcgi::scan_name_value_pairs $_params_contents]
	    my validate_params
	} else {
	    append _params_contents $contents
	}
    }

    method on_record_arrival {} {
	set type [$_record type]
	if {[info exists ::test::fastcgi::type_name($type)]} {
	    set handler handle_$::test::fastcgi::type_name($type)
	} else {
	    set handler handle_unknown_type
	}

	if {[lindex [info object call [self] $handler] 0 0] ne "unknown"} {
	    tailcall my $handler
	}
    }

    method on_eof {} {
    }

    method on_readable {} {
	set data [read $_chan]
	while {[$_record add_data $data]} {
	    my on_record_arrival
	    set data [$_record rest]
	    set prev $_record
	    set _record [test::fastcgi::record new]
	    lappend _records $_record
	}

	if {$_chan eq ""} {
	    return
	}

	test::assert {[$_record is_empty] || ![chan eof $_chan]}

	if {[chan eof $_chan]} {
	    my on_eof
	    chan event $_chan readable ""
	}
    }
}

oo::class create test::fastcgi::upstream {
    variable _addr _port
    variable _client_factory _chan _clients
    variable _configured
    variable _testcase

    constructor {client_factory {addr ""} {port ""}} {
	set _client_factory $client_factory

	if {$addr eq ""} {
	    set addr $::test::host_addr
	}
	set _addr $addr

	if {$port eq ""} {
	    set port [incr ::test::fastcgi::next_port]
	}
	set _port $port

	set _clients {}
	set _chan ""
	set _configured 0
    }

    destructor {
	foreach client $_clients {
	    $client destroy
	}
	my close
    }

    method open {} {
	test::assume {$_chan eq ""}
	set _chan [socket -server "[self] accept" -myaddr $_addr $_port]
	chan configure $_chan -blocking 0 -buffering none \
	    -encoding binary -translation binary
    }

    method close {} {
	test::assume {$_chan ne ""}
	chan close $_chan
	set _chan ""
    }

    method set_testcase {testcase} {
	set _testcase $testcase
    }

    method testcase {} {
	return $_testcase
    }

    method is_configured {} {
	return $_configured
    }

    method set_configured {} {
	set _configured 1
    }

    method set_client_factory {client_factory} {
	set _client_factory $client_factory
    }

    method accept {chan addr port} {
	chan configure $chan -blocking 0 -buffering none \
	    -encoding binary -translation binary
	set client [eval $_client_factory [list [self] $chan $addr $port]]
	lappend _clients $client
    }

    method remove_client {client} {
	set pos [lsearch -exact $_clients $client]
	test::assume {0 <= $pos}
	set _clients [lreplace $_clients $pos $pos {}]
    }

    method clients {} {
	return $_clients
    }

    method get_config {} {
	set addr [json::write object family [json::write string inet] \
		      address [json::write string $_addr] \
		      port $_port]
	return [json::write object address $addr]
    }

    method chan {} {
	return $_chan
    }
}

oo::class create test::fastcgi::testcase {
    superclass test::khttpd_file_testcase
    variable _upstreams

    method upstreams {} {
	return $_upstreams
    }

    method add_upstream {upstream} {
	$upstream set_testcase [self]
	lappend _upstreams $upstream
    }

    method _teardown {} {
	next
	foreach upstream $_upstreams {
	    $upstream destroy
	}
    }

    method script_location_path {} {
	return /0/1/2
    }

    method _create_fcgi_location_config {} {
	set khttpd [my khttpd]
	set config [list id [json::write string [test::uuid_new]] \
			type [json::write string khttpd_fastcgi] \
			server [json::write string [my server_id]] \
			path [json::write string [my script_location_path]] \
		        scriptSuffix [json::write string .fcgi] \
			fsPath [json::write string \
				    [test::remote_path [my fs_path]]]]

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

oo::class create ::test::fastcgi::basic_client {
    superclass ::test::fastcgi::client
    variable _script_name _fs_path _state _resp_hdr _resp_body
    variable _counter _counter_script _counter_expired
    
    constructor {script_name fs_path resp_hdr resp_body 
	counter counter_script upstream chan addr port} {
	if {$counter != 0 && $counter_script eq ""} {
	    error "counter_script is not given" -errorcode [KHTTPD TEST error]
	}

	set _script_name $script_name
	set _fs_path $fs_path
	set _resp_hdr $resp_hdr
	set _resp_body $resp_body
	set _state begin
	set _counter $counter
	set _counter_script $counter_script
	set _counter_expired 0
	next $upstream $chan $addr $port
    }

    method validate_params {} {
	variable _params

	test::assert {![dict exists $_params CONTENT_LENGTH]}
	test::assert {![dict exists $_params CONTENT_TYPE]}
	test::assert {[dict get $_params GATEWAY_INTERFACE] eq "CGI/1.1"}
	test::assert {[dict get $_params PATH_INFO] eq "/x/hogehoge"}
	test::assert {[dict get $_params PATH_TRANSLATED] eq \
			  [test::remote_path \
			       [file join $_fs_path "x/hogehoge"]]}
	test::assert {[dict get $_params QUERY_STRING] eq ""}
	test::assert {[dict get $_params REMOTE_ADDR] eq
	    $::test::host_addr}
	test::assert {[dict get $_params REQUEST_METHOD] eq "GET"}
	test::assert {[dict get $_params SCRIPT_NAME] eq $_script_name}
	test::assert {[dict get $_params SERVER_NAME] eq
	    $::test::target_addr}
	test::assert {[dict get $_params SERVER_PORT] eq
	    $::test::http_port}
	test::assert {[dict get $_params SERVER_PROTOCOL] eq "HTTP/1.1"}
	test::assert {[dict get $_params SERVER_SOFTWARE] eq
	    $::test::server_software}
	test::assert {[dict exists $_params HTTP_X_TEST]}
    }

    method handle_begin_request {} {
	variable _record

	# The role is FCGI_RESPONDER
	set contents [test::fastcgi::scan_begin_request [$_record contents]]
	test::assert {[dict get $contents role] == 1}
    }

    method tick {} {
	puts "[self] tick $_counter"
	if {[incr _counter -1] != 0} {
	    return
	}

	puts "[self] tick => expire"

	set _counter_expired 1
	if {![eval "$_counter_script [self]"]} {
	    uplevel return
	}
    }

    method on_record_arrival {} {
	variable _upstream
	variable _record
	variable _params
	variable ::test::fastcgi::type_id

	my tick
	if {[my chan] eq ""} {
	    return
	}

	next

	if {![$_upstream is_configured]} {
	    test::assert {[$_record type] == $type_id(get_values)}
	    set resp [test::fastcgi::construct_get_values_result_record \
			  $_record [list FCGI_MPXS_CONNS 0]]
	    puts -nonewline [my chan] $resp
	    $_upstream set_configured

	    return
	}

	switch -exact -- $_state {
	    begin {
		test::assert {[$_record type] == $type_id(begin_request)}
		set _state params
	    }

	    params {
		test::assert {[$_record type] == $type_id(params)}
		if {[$_record contents] eq ""} {
		    set _state stdin
		}
	    }

	    stdin {
		test::assert {[$_record type] == $type_id(stdin)}
		if {[$_record contents] eq ""} {
		    set _state begin

		    set resp $_resp_hdr
		    set xtest [dict get $_params HTTP_X_TEST]
		    append resp "X-Test-Response: $xtest\n"
		    append resp "\n"
		    append resp $_resp_body

		    # The fastcgi server sends the response.
		    test::fastcgi::send_output stdout [my chan] $resp
		    test::fastcgi::close_output stdout [my chan]
		    test::fastcgi::send_end_request [my chan]
		    chan flush [my chan]
		}
	    }

	    default {
		throw [list KHTTPD TEST error] "unknown state $_state"
	    }
	}
    }
}

oo::class create test::fastcgi::get_basic_testcase {
    superclass test::fastcgi::testcase
    variable _script_name _resp_hdr _resp_body

    method _setup {} {
	set _script_name [my script_location_path]/test.fcgi

	set _resp_body {<!DOCTYPE html><html><head><meta charset="utf-8">}
	append _resp_body {<title>The document root</title></head>}
	append _resp_body {<body>Hello World!</body></html>}

	set _resp_hdr "Content-Type: text/html\n"
	append _resp_hdr "Content-Length: [string length $_resp_body]\n"

	set upstream [test::fastcgi::upstream new \
			  "[list ::test::fastcgi::basic_client new \
		       	     $_script_name [my fs_path]\
			     $_resp_hdr $_resp_body 0 {}]" "" 10000]
	my add_upstream $upstream
	$upstream open

	next
    }
}

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

oo::class create test::fastcgi::timed_client_factory {
    variable _script_name _fs_path _resp_hdr _resp_body
    variable _count
    variable _last_client
    variable _expired

    constructor {script_name fs_path resp_hdr resp_body} {
	set _script_name $script_name
	set _fs_path $fs_path
	set _resp_hdr $resp_hdr
	set _resp_body $resp_body
	set _count 0
    }

    method set_counter {count} {
	set _count $count
    }

    method create {upstream chan addr port} {
	set _expired 0
	set _last_client [::test::fastcgi::basic_client new \
			      $_script_name $_fs_path $_resp_hdr $_resp_body \
			      $_count "[self] expire" \
			      $upstream $chan $addr $port]
	return $_last_client
    }

    method last_client {} {
	return $_last_client
    }

    method expire {client} {
	puts "[self] expire $client"
	$client close
	set _expired 1
    }

    method expired {} {
	return $_expired
    }
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

    for {set i 1} {1} {incr i} {
	puts "counter = $i"
	$_client_factory set_counter $i

	set req "GET $_script_name/x/hogehoge HTTP/1.1\r\n"
	append req "Host: [$khttpd host]\r\n"
	append req "X-Test: $i\r\n\r\n"

	my with_connection {sock} {
	    # The client sends a GET request for the script.
	    puts -nonewline $sock $req

	    # The server relays the response to the client.
	    set response [my receive_response $sock $req]

	    if {[$_client_factory expired]} {
		test::assert {[$response status] == 500}
		test::assert_it_is_default_error_response $response

	    } else {
		test::assert {[$response status] == 200}
		test::assert {[$response field Content-Type] eq "text/html"}
		test::assert {[$response field Content-Length] ==
		    [string length $_resp_body]}
		test::assert {[$response field X-Test-Response] eq "$i"}
		test::assert {[$response body] eq $_resp_body}
		break
	    }
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

# test for partial responses from the FastCGI server
