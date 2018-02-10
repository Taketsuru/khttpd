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
    namespace export khttpd khttpd_testcase

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
		foreach component [file split [file dirname $path]] {
		    set dir [file join $logdir $component]
		    file mkdir $dir
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
	    return [list accessLog $access_log_conf \
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

	method create_port_conf {id protocol family addr port} {
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

	method connect {} {
	    set sock [socket -async [my host] [my port]]

	    try {
		chan configure $sock -blocking 0 -buffering none -eofchar "" \
		    -translation binary -encoding binary
		test::test_chan $sock 1000 {} {
		    method on_writable {chan} {
			my ok
		    }
		}
	    } on error {msg opts} {
		close $sock
		return -options $opts $msg
	    }

	    return $sock
	}

	method create_server_conf {id name ports} {
	    set id_json [json::write string $id]
	    set name_json [json::write string $name]
	    set ports_json [json::write array \
				{*}[lmap {port_id} $ports {
				    json::write string $port_id
				}]]
	    return [json::write object id $id_json name $name_json \
			ports $ports_json]
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
	    set cfg_json [json::write object {*}$config]
	    my run_remotely "sudo usr.sbin/khttpdctl/khttpdctl load -" \
		$cfg_json
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
	variable _khttpd _port_id _server_id

	constructor {} {
	    next
	    set _khttpd [test::khttpd new 192.168.56.3 80]
	    set _port_id [test::uuid_new]
	    set _server_id [test::uuid_new]
	}

	destructor {
	    $_khttpd destroy
	    next
	}

	method create_config {rewriters_json_list locations_json_list} {
	    set port_json [$_khttpd create_port_conf $_port_id http \
			       inet "" [$_khttpd port]]
	    set server_json [$_khttpd create_server_conf $_server_id \
				 [$_khttpd host] [list $_port_id]]
	    return [$_khttpd create_config $rewriters_json_list \
			[list $port_json] [list $server_json] \
			$locations_json_list]
	}

	method khttpd {} {
	    return $_khttpd
	}

	method _config {} {
	    return [my create_config {} {}]
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
	    return [dict merge [next $data_dict] [$_khttpd collect_logs]]
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
}
