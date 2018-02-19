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

package provide test_khttpd 0.0
package require test

namespace eval test {
    namespace export {[a-z]*}

    variable message_size_max 16384

    proc assert_eof {sock} {
	test_chan $sock {
	    method on_readable {chan} {
		set data [read $chan]
		test::assert {$data == "" && [eof $chan]}
		my done
	    }
	}
    }

    proc assert_error_log_is_empty {khttpd} {
	set logname [local_file [dict get [$khttpd logs] error-log]]
	assert {[file size $logname] == 0}
    }

    proc assert_it_is_options_asterisc_response {response} {
	# The status is 200 (success)
	assert {[$response status] == 200}

	# The value of Content-Length: is 0
	set content_length [$response field Content-Length]
	assert {[llength $content_length] == 1 &&
	    [lindex $content_length 0] == 0}

	# There is an Allow field
	set allow [$response field allow]
	assert {[llength $allow] == 1}
	assert {[lindex $allow 0] == "ACL, BASELINE-CONTROL,\
	    BIND, CHECKIN, CHECKOUT, CONNECT, COPY, DELETE, GET, HEAD,\
	    LABEL, LINK, LOCK, MERGE, MKACTIVITY, MKCALENDAR, MKCOL,\
	    MKREDIRECTREF, MKWORKSPACE, MOVE, OPTIONS, ORDERPATCH,\
	    PATCH, POST, PRI, PROPFIND, PROPPATCH, PUT, REBIND,\
	    REPORT, SEARCH, TRACE, UNBIND, UNCHECKOUT, UNLINK, UNLOCK,\
	    UPDATE, UPDATEREDIRECTREF, VERSION-CONTROL"}
    }

    proc assert_receiving_response {sock req {arrival_time ""} {rest ""}} {
	if {$arrival_time eq ""} {
	    set arrival_time [expr {[clock milliseconds] / 1000.0}]
	}

	set result [http_response new $req $arrival_time]
	try {
	    if {$rest ne ""} {
		$result append $rest
	    }

	    test_chan -props [list response $result] $sock {
		variable response

		method on_readable {chan} {
		    set data [read $chan]
		    if {[$response append $data]} {
			my done
		    } else {
			test::assert {![eof $chan]}
		    }
		}
	    }
	} on error {msg opts} {
	    $result destroy
	    return -options $opts $msg
	}

	return $result
    }

    proc check_access_log {khttpd responces} {
	set time_fudge 1.0
	set logname [local_file [dict get [$khttpd logs] access-log]]
	set last_nents 0
	set retry 0

	while {$retry < 3} {
	    after 1200
	    update

	    try {
		set file [open $logname r]
		set ents [json::many-json2dict [read $file]]
		if {[llength $responces] <= [llength $ents]} {
		    break
		}
		if {[llength $ents] == $last_nents} {
		    incr retry
		} else {
		    set last_nents [llength $ents]
		}

	    } on error {msg opts} {
		continue

	    } finally {
		close $file
	    }
	}

	assert {[llength $ents] == [llength $responces]}

	foreach entry $ents resp $responces {
	    set arrival_time [dict get $entry arrivalTime]
	    set completion_time [dict get $entry completionTime]
	    set actual_status [dict get $entry status]
	    set actual_peer_family [dict get $entry peer family]
	    set actual_peer_addr [dict get $entry peer address]
	    set actual_peer_port [dict get $entry peer port]
	    set actual_request [dict get $entry request]

	    set expected_request [$resp request_line]
	    set expected_status [$resp status]
	    set expected_arrival_time [$resp arrival_time]
	    set expected_completion_time [$resp completion_time]

	    assert {$arrival_time <= $completion_time}
	    assert {abs($expected_arrival_time - $arrival_time) <
		$time_fudge}
	    assert {abs($expected_completion_time - $completion_time) < 
		$time_fudge}
	    assert {$actual_status == $expected_status}
	    if {$actual_status == 400} {
		assert {[string equal -length [string length $actual_request] \
			     $actual_request $expected_request]}
	    } else {
		assert {$actual_request eq $expected_request}
	    }
	    assert {$actual_peer_family == "inet"}
	    #test::assert {$actual_peer_address == ""}
	    #test::assert {$actual_peer_port == ""}

	    if {[dict exists $entry responsePayloadSize]} {
		set actual [dict get $entry responsePayloadSize]
		set expect [string length [$resp body]]
		test::assert {$actual == $expect}
	    }
	}
    }

    proc create_port_conf {id protocol family addr port} {
	set addr_list [list family [json::write string $family]]
	if {$addr != ""} {
	    lappend addr_list address [json::write string $addr]
	}
	if {$port != ""} {
	    lappend addr_list port $port
	}
	set addr_json [json::write object {*}$addr_list]
	set id_json [json::write string $id]
	set protocol_json [json::write string "http"]
	return [json::write object id $id_json protocol $protocol_json \
		    address $addr_json]
    }

    proc create_server_conf {id name ports} {
	set id_json [json::write string $id]
	set name_json [json::write string $name]
	set ports_json [json::write array \
			    {*}[lmap {port_id} $ports {
				json::write string $port_id
			    }]]
	return [json::write object id $id_json name $name_json \
		    ports $ports_json]
    }

    proc create_location_conf {id type server path args} {
	set config [list id [json::write string $id] \
			   type [json::write string $type] \
			   server [json::write string $server] \
			   path [json::write string $path]]

	foreach {key value} $args {
	    lappend config $key [json::write string $value]
	}

	return [json::write object {*}$config]
    }

    proc create_options_asterisc_request {khttpd} {
	set req "OPTIONS * HTTP/1.1\r\n"
	append req "Host: [$khttpd host]\r\n\r\n"
	return $req
    }

    oo::class create khttpd {
	variable handler host loaded module_dirname port \
	    remote_abs_project_root remote_rel_project_root

	constructor {host_arg port_arg} {
	    set handler ""
	    set host $host_arg
	    set loaded 0
	    set module_dirname modules/khttpd
	    set port $port_arg
	    # Assume that the local and the remote home directory are the same
	    # with each other.
	    set remote_rel_project_root work/khttpd
	    set remote_abs_project_root \
		[file join $::env(HOME) $remote_rel_project_root]
	}

	destructor {
	} 

	method check_leak {} {
	    set findleak [test::local_file tools/bin/findleak.tcl]
	    set logs_dict [dict create {*}[my logs]]
	    set ktr_log [test::local_file [dict get $logs_dict ktr-log]]
	    set leaks [exec -- $findleak $ktr_log]

	    if {$leaks != ""} {
		throw [list KHTTPD TEST fail] "memory leak is detected\n$leaks"
	    }
	}

	method clear_logs {} {
	    foreach {name path} [my logs] {
		set logdir ""
		set path [test::local_file $path]
		foreach component [file split [file dirname $path]] {
		    set logdir [file join $logdir $component]
		    file mkdir $logdir
		}
	    }
	    file delete -force \
		{*}[lmap {name path} [my logs] { test::local_file $path }]
	}

	method collect_logs {} {
	    set result [dict create]
	    foreach {key filename} [my logs] {
		if {[file readable [test::local_file $filename]]} {
		    set file [open [test::local_file $filename] "r"]
		    dict set result $key [read $file]
		    close $file
		}
	    }
	    return $result
	}

	method connect {} {
	}

	method shutdown {} {
	    chan close $sock write
	}

	method create_config {rewriters ports servers locations} {
	    set logs_dict [dict create {*}[my logs]]
	    set access_log_conf \
		[my create_log_file_conf [dict get $logs_dict access-log]]
	    set error_log_conf \
		[my create_log_file_conf [dict get $logs_dict error-log]]
	    set rewriters_conf [json::write array {*}$rewriters]
	    set ports_conf [json::write array {*}$ports]
	    set servers_conf [json::write array {*}$servers]
	    set locations_conf [json::write array {*}$locations]
	    return [json::write object accessLog $access_log_conf \
			errorLog $error_log_conf \
			rewriters $rewriters_conf \
			ports $ports_conf \
			servers $servers_conf \
			locations $locations_conf]
	}

	method create_log_file_conf {path} {
	    return [json::write object type [json::write string "file"] \
		    path [json::write string [my remote_path $path]]]
	}

	method connect {} {
	    set sock [socket -async [my host] [my port]]

	    try {
		chan configure $sock -blocking 0 -buffering none -eofchar "" \
		    -translation binary -encoding binary
		test::test_chan $sock {
		    method on_writable {chan} {
			my done
		    }
		}
	    } on error {msg opts} {
		close $sock
		return -options $opts $msg
	    }

	    return $sock
	}

	method host {} {
	    return $host
	}

	method load_kmod {} {
	    if {!$loaded} {
		my run_remotely \
		    "sudo kldload [file join $module_dirname khttpd.ko]" ""
		set loaded 1
	    }
	}

	method logs {} {
	    return [list access-log test/log/access.log \
		    error-log test/log/error.log \
		    ktr-log test/log/ktr.log]
	}

	method port {} {
	    return $port
	}

	method remote_path {path} {
	    return [file join $remote_abs_project_root $path]
	}

	method run_remotely {cmd input} {
	    set result [exec -- ssh $host "cd $remote_rel_project_root; $cmd" \
			    << $input 2>@1]
	    if {$result != ""} {
		set log [[test::test_driver instance] log_chan]
		puts $log $result
	    }
	}

	method start {config} {
	    my run_remotely "sudo usr.sbin/khttpdctl/khttpdctl load -" $config
	}

	method stop {} {
	    my run_remotely "sudo usr.sbin/khttpdctl/khttpdctl stop"
	}

	method unload_kmod {} {
	    if {$loaded} {
		my run_remotely "sudo kldunload -f khttpd.ko" ""
		set loaded 0
	    }
	}
    }

    oo::class create khttpd_testcase {
	superclass test::testcase
	variable _khttpd _port_id _server_id _responses

	constructor {} {
	    next
	    set _khttpd [test::khttpd new 192.168.56.3 80]
	    set _port_id [test::uuid_new]
	    set _server_id [test::uuid_new]
	    set _responses ""
	}

	destructor {
	    foreach response $_responses {
		$response destroy
	    }

	    $_khttpd destroy
	    next
	}

	method check_access_log {} {
	    test::check_access_log $_khttpd $_responses
	}

	method khttpd {} {
	    return $_khttpd
	}

	method receive_response {sock req {arrival_time ""} {rest ""}} {
	    if {$rest eq ""} {
		set last_response [lindex $_responses end]
		if {$last_response ne ""} {
		    set rest [$last_response rest]
		}
	    }
	    set response [test::assert_receiving_response $sock $req \
			      $arrival_time $rest]
	    lappend _responses $response
	    return $response
	}

	method responses {} {
	    return $_responses
	}

	method port_id {} {
	    return $_port_id
	}

	method server_id {} {
	    return $_server_id
	}

	method with_connection {var body} {
	    set sock [$_khttpd connect]
	    try {
		return [uplevel set [list $var] [list $sock]\; $body]

	    } finally {
		close $sock
	    }
	}

	method _create_ports_config {} {
	    return [list [test::create_port_conf $_port_id http \
			      inet "" [$_khttpd port]]]
	}

	method _create_servers_config {} {
	    return [list [test::create_server_conf $_server_id \
			      [$_khttpd host] [list $_port_id]]]
	}

	method _create_rewriters_config {} {
	    return {}
	}

	method _create_locations_config {} {
	    return {}
	}

	method _config {} {
	    return  [$_khttpd create_config [my _create_rewriters_config] \
			[my _create_ports_config] [my _create_servers_config] \
			[my _create_locations_config]]
	}

	method _setup {} {
	    next
	    $_khttpd clear_logs
	    $_khttpd load_kmod
	    try {
		$_khttpd start [my _config]
	    } on error {msg opt} {
		$_khttpd unload_kmod
		return -options $opt $msg
	    }
	}

	method _teardown {} {
	    $_khttpd unload_kmod
	    $_khttpd collect_logs
	    next
	}

	method _check {} {
	    $_khttpd check_leak
	}

	method _collect {data_dict} {
	    if {$_responses eq ""} {
		return [dict merge [next $data_dict] [$_khttpd collect_logs]]

	    } else {
		set response [lindex $_responses end]
		return [dict merge [next $data_dict] [$_khttpd collect_logs] \
			    [list request [$response request] \
				 response [$response response]]]
	    }
	}

    }

    oo::class create khttpd_1conn_testcase {
	superclass test::khttpd_testcase
	variable _sock

	method socket {} {
	    return $_sock;
	}

	method _setup {} {
	    next
	    set _sock [[my khttpd] connect]
	}

	method _teardown {} {
	    if {$_sock != ""} {
		close $_sock
		set _sock ""
	    }
	    next
	}
    }

    oo::class create khttpd_file_testcase {
	superclass test::khttpd_testcase
	variable _random

	method fs_path {} {
	    return test/tmp
	}

	method random {size} {
	    return [read $_random $size]
	}

	method _setup {} {
	    set _random [tcl::chan::random [list 0 1 2 3 4 5]]
	    chan configure $_random -translation binary -encoding binary

	    set dir ""
	    foreach component [file split [test::local_file [my fs_path]]] {
		set dir [file join $dir $component]
		if {![file exists $dir]} {
		    file mkdir $dir
		}
	    }

	    next
	}

	method _teardown {} {
	    close $_random
	    file delete -force [test::local_file [my fs_path]]
	    next
	}

	method _create_locations_config {} {
	    set khttpd [my khttpd]
	    return [list [test::create_location_conf \
			      [test::uuid_new] khttpd_file [my server_id] / \
			      fsPath [$khttpd remote_path [my fs_path]]]]
	}
    }
}
