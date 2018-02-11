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

package provide test 0.0

namespace eval test {

    namespace export assert assume define continue_if local_file logger \
	testcase test_driver uuid_new

    proc assert {cond {msg ""}} {
	if {![uplevel 1 expr [list $cond]]} {
	    set expcond [uplevel 1 subst [list $cond]]
	    set pos [_format_pos [info frame -1]]
	    if {$msg == ""} {
		set msg [format "%sfailure: %s\n%s" $pos \
			     "\"$cond\" is false." \
			     "The condition is expanded to $expcond"]
	    }
	    return -code error -errorcode [list KHTTPD TEST fail] $msg
	}
    }

    proc assume {cond {msg ""}} {
	if {![uplevel 1 expr [list $cond]]} {
	    set expcond [uplevel 1 subst [list $cond]]
	    set pos [_format_pos [info frame -1]]
	    if {$msg == ""} {
		set msg [format "%serror: %s\n%s" $pos \
			     "\"$cond\" is false." \
			     "The condition is expanded to $expcond"]
	    }
	    return -code error -errorcode [list KHTTPD TEST error] $msg
	}
    }

    proc continue_if {cond {msg ""}} {
	if {![uplevel 1 expr [list $cond]]} {
	    set expcond [uplevel 1 subst [list $cond]]
	    set pos [_format_pos [info frame -1]]
	    if {$msg == ""} {
		set msg [format "%sskip: %s\n%s" $pos \
			     "\"$cond\" is false." \
			     "The condition is expanded to $expcond"]
	    }
	    return -code error -errorcode [list KHTTPD TEST skip] $msg
	}
    }

    proc add_data {name value} {
	[test::test_driver instance] add_data $name $value
    }

    proc define {testname classname body} {
	set driver [test::test_driver instance]
	set caller_ns [uplevel 1 namespace current]

	if {![string match "::*" $testname]} {
	    if {$caller_ns == "::"} {
		set testname "::$testname"
	    } else {
		set testname "$caller_ns::$testname"
	    }
	}

	if {![string match "::*" $classname]} {
	    if {$caller_ns == "::"} {
		set classname "::$classname"
	    } else {
		set classname "$caller_ns::$testname"
	    }
	}

	set test_class [oo::class create $testname "
		superclass $classname
		method _test {} {$body}"]

	try {
	    set obj [$test_class new]

	    try {
		if {![info object class $obj testcase]} {
		    return -code error -errorcode [list KHTTPD TEST error] \
			"class $classname must be a subclass of test::testcase"
		}
	    } finally {
		$obj destroy
	    }

	    set frame [info frame -1]
	    $driver add $test_class \
		[dict get $frame file] [dict get $frame line]

	} on error {msg options} {
	    $test_class destroy
	    return -options $options $msg
	}
    }

    oo::class create event_tester {
	variable _callout _chan _wchan _msg _opts _props _result

	constructor {chan props} {
	    set _callout ""
	    set _chan $chan
	    set _result ""
	    set _props {}
	    foreach {name value} $props {
		test::assume {![string match _* $name]}
		my variable $name
		set $name $value
		lappend _props $name
	    }
	}

	method bgerror {msg_arg opt_arg} {
	    set _msg $msg_arg
	    set _opts $opt_arg
	    set _wchan 1
	}

	method disable {type} {
	    catch {fileevent $_chan $type ""}
	}

	method enable {type} {
	    fileevent $_chan $type "[self] upcall on_$type"
	}

	method props {} {
	    set _rv {}
	    foreach _name $_props {
		my variable $name
		lappend _rv $name [set $name]
	    }
	    return $_rv
	}

	method upcall {type} {
	    my $type $_chan
	}

	method test {timeout} {
	    my _setup

	    set _msg ""
	    set _opts ""
	    set old_bgerror [interp bgerror {}]
	    try {
		set methods [info object methods [self] -all]
		if {[lsearch -exact $methods on_readable] != -1} {
		    my enable readable
		}
		if {[lsearch -exact $methods on_writable] != -1} {
		    my enable writable
		}
		set _callout [after $timeout "[self] on_timeout"]
		interp bgerror {} "[self] bgerror"
		vwait [my varname _wchan]
	    } finally {
		interp bgerror {} $old_bgerror
		if {$_callout != ""} {
		    after cancel $_callout
		    set _callout ""
		}
		my disable readable
		my disable writable
	    }

	    my _teardown $_msg $_opts 

	    if {$_opts != ""} {
		return -options $_opts $_msg
	    }

	    return $_result
	}

	method done {{result ""}} {
	    set _result $result
	    set _wchan 1
	}

	method on_timeout {} {
	    return -code error -errorcode [list KHTTPD TEST fail] "timeout"
	}

	method _setup {} {
	}

	method _teardown {msg opts} {
	}
    }

    proc test_chan {args} {
	if {[llength $args] < 1} {
	    return -code error -errorcode [list KHTTPD TEST error] \
		"wrong # args: should be \"test_chan ?-timeout millis?\
		?-result result_var? ?-props props? chan body"
	}

	set props {}
	set timeout 1000
	set n [llength $args]
	for {set i 0} {$i < $n - 2} {incr i} {
	    set arg [lindex $args $i]
	    switch -exact -- $arg {
		-props {
		    incr i
		    set props [lindex $args $i]
		}
		-result {
		    incr i
		    upvar 1 [lindex $args $i] result
		}
		-timeout {
		    incr i
		    set timeout [lindex $args $i]
		}
		default {
		    return -code error -errorcode [KHTTPD TEST error] \
			"bad option \"$arg\": must be -props, -result,\
			or -timeout"
		}
	    }
	}

	set tester [test::event_tester new [lindex $args end-1] $props]
	try {
	    oo::objdefine $tester [lindex $args end]
	    set result [$tester test $timeout]
	} finally {
	    $tester destroy
	}

	return $result
    }

    # This proc returns the absolute path corresponds to argument 'path'
    # interpreted relative to the project root.
    proc local_file {path} {
	set local_dirname [file join [file dirname [info script]] .. ..]
	return [file normalize [file join $local_dirname $path]]
    }

    oo::class create logger {
	variable chan name buffer

	constructor {name_arg} {
	    namespace upvar [info object namespace test::logger] \
		instances instances
	    if {[info exists instances]} {
		dict set instances $name_arg [self]
	    } else {
		set instances [dict create $name_arg [self]]
	    }

	    try {
		set chan [chan create w [self]]
		set name $name_arg
		set buffer ""
		chan configure $chan -buffering none -encoding binary \
		    -translation binary
	    } on error {msg opts} {
		dict remove instances $name_arg
		return -options $opts $msg
	    }
	}

	destructor {
	    close $chan
	    namespace upvar [info object namespace test::logger] \
		instances instances
	    dict remove instances $name
	}

	method chan {} {
	    return $chan
	}

	method collect {} {
	    set result $buffer
	    set buffer ""
	    return $result
	}

	method finalize {c} {
	}

	method initialize {c mode} {
	    return [list finalize initialize watch write]
	}

	method watch {c event} {
	}

	method write {c data} {
	    namespace upvar [info object namespace test::logger] \
		collecting collecting
	    if {$collecting} {
		append buffer $data
	    } else {
		puts -nonewline $data
	    }
	    return [string length $data]
	}
    }

    oo::objdefine logger {
	variable instances collecting

	method set_collecting {value} {
	    set collecting $value
	}
	
	method instances {} {
	    return $instances
	}
    }

    logger set_collecting 0

    oo::class create testcase {
	variable chan data finish_time start_time status bailed_out

	construct {} {
	    set status ""
	    set bailed_out 0
	    set chan [[test::test_driver instance] log_chan]
	    set data [dict create]
	}

	destructor {
	}

	method add_data {name value} {
	    if {[dict exists $data $name]} {
		dict append data $name $value
	    } else {
		dict set data $name $value
	    }
	}

	method bailed_out {} {
	    return $bailed_out
	}

	method data {} {
	    return $data
	}

	method finish_time {} {
	    return $finish_time
	}

	method run {} {
	    set start_time [clock microseconds]

	    test::logger set_collecting 1

	    try {
		set need_teardown 0
		my _setup
		set need_teardown 1
		my _test

	    } on ok {msg opt} {
		set status pass

	    } trap {KHTTPD TEST} {msg opt} {
		set status [lindex [dict get $opt -errorcode] 2]
		puts $chan [my _format_error_options $opt]

	    } on error {msg opt} - \
	      on return {msg opt} - \
	      on break {msg opt} - \
	      on continue {msg opt} {
		set status error
		puts $chan [my _format_error_options $opt]

	    } finally {
		if {$need_teardown} {
		    set bailed_out [expr {[catch {my _teardown} msg opt] != 0}]
		    if {$bailed_out} {
			puts $chan [my _format_error_options $opt]
		    }
		}
	    }

	    if {$status == "pass"} {
		try {
		    my _check
		} on ok {msg opt} {

		} trap {KHTTPD TEST} {msg opt} {
		    set status [lindex [dict get $opt -errorcode] 2]
		    puts $chan [my _format_error_options $opt]

		} on error {msg opt} - \
		  on return {msg opt} - \
		  on break {msg opt} - \
		  on continue {msg opt} {
		      set status error
		      puts $chan [my _format_error_options $opt]
		}
	    }

	    test::logger set_collecting 0

	    set data [my _collect $data]
	    set finish_time [clock microseconds]
	}

	method start_time {} {
	    return $start_time
	}

	method status {} {
	    return $status
	}

	method _collect {data_dict} {
	    set data_dict [dict merge $data_dict $data]
	    dict for {name logger} [test::logger instances] {
		dict set data_dict $name [$logger collect]
	    }
	    return $data_dict
	}

	method _format_error_options {options} {
	    return "[dict get $options -errorinfo]"
	}

	method _check {} {}

	method _setup {} {}

	method _test {} {}

	method _teardown {} {}
    }

    oo::class create test_driver {
	variable current_obj log test_classes test_objs

	constructor {} {
	    test::test_driver set_instance [self]
	    set current_obj ""
	    set log [test::logger new log]
	    set test_classes {}
	    set test_objs {}
	}

	destructor {
	    my _clear_objs
	    foreach class $test_classes {
		$class destroy
	    }
	    $log destroy
	    test::test_driver clear_instance
	}

	method add {class file line} {
	    if {[dict exists $test_classes $class]} {
		return -code error -errorcode {KHTTPD TEST error} \
		    "duplicate test $class"
	    }
	    dict set test_classes $class [list $file $line]
	}

	method log_chan {} {
	    return [$log chan]
	}

	method report {file} {
	    puts $file "<?xml version=\"1.0\" ?>"

	    set i -1
	    set n [llength $test_objs]
	    foreach obj $test_objs {
		incr i
		set class [info object class $obj]
		set class_info [dict get $test_classes $class]
		set class_file [lindex $class_info 0]
		set class_line [lindex $class_info 1]
		set time [expr {[$obj finish_time] - [$obj start_time]}]
		set status [$obj status]

		if {$status == ""} {
		    continue
		}

		puts -nonewline $file "<testcase name=\"$class\""
		puts -nonewline $file " file=\"$class_file\""
		puts -nonewline $file " line=\"$class_line\""
		puts $file " elapsed-time=\"$time\" status=\"$status\">"

		if {$status != "pass"} {
		    dict for {name value} [$obj data] {
			puts $file "<data name=\"$name\">"
			set body [regsub -all -- "]]>" $value \
				      "]]]]><!\[CDATA\[>"]
			puts $file "<!\[CDATA\[$body]]>"
			puts $file "</data>"
		    }
		}

		puts $file "</testcase>"
	    }
	}

	method run {} {
	    set name_field_len 0

	    foreach obj $test_objs {
		set len [string length [info object class $obj]]
		if {$name_field_len < $len} {
		    set name_field_len $len
		}
	    }

	    set done_count 0
	    set pass_count 0
	    set fail_count 0
	    set error_count 0
	    set skip_count 0

	    foreach obj $test_objs {
		set current_obj $obj
		set class [regsub -- {^::(.*)$} [info object class $obj] {\1}]
		set class_len [string length $class]
		set leader_len [expr {$name_field_len - $class_len + 1}]
		puts -nonewline "$class[string repeat . $leader_len]"
		flush stdout

		$obj run

		if {[$obj bailed_out]} {
		    incr done_count
		    incr error_count
		    puts "bailout"
		    break
		}

		set status [$obj status]
		puts $status

		incr done_count

		switch -exact -- $status {
		    pass	{ incr pass_count }
		    fail	{ incr fail_count }
		    error	{ incr error_count }
		    skip	{ incr skip_count }
		}
	    }

	    set current_obj {}
	    puts -nonewline "total: [llength $test_objs], "
	    puts -nonewline "pass: $pass_count, fail: $fail_count, "
	    puts -nonewline "error: $error_count, skip: $skip_count, "
	    puts "ignore: [expr {[llength $test_objs] - $done_count}]"
	}

	method select {filter} {
	    my _clear_objs

	    foreach class [lsort [dict keys $test_classes]] {
		set obj [$class new]
		try {
		    if {[apply $filter $obj]} {
			lappend test_objs $obj
			set obj ""
		    }

		} finally {
		    if {$obj != ""} {
			$obj destroy
		    }
		}
	    }
	}

	method write {chan data} {
	    if {$current_obj == ""} {
		puts -nonewline $data
	    } else {
		$current_obj write $chan $data
	    }
	}

	method add_data {name value} {
	    if {$current_obj != ""} {
		$current_obj add_data $name $value
	    }
	}

	method _clear_objs {} {
	    foreach obj $test_objs {
		$obj destroy
	    }
	    set test_objs {}
	}
    }

    oo::objdefine test::test_driver {
	method set_instance {obj} {
	    if {[catch {my instance} result] == 0} {
		return -code error -errorcode {KHTTPD TEST error} \
		    "duplicate test_driver"
	    }

	    oo::objdefine test::test_driver "
	    	method instance {} {
			return $obj
		}"
	}

	method clear_instance {} {
	    oo::objdefine test_driver deletemethod instance
	}
    }

    proc uuid_new {} {
	set fd [open "/dev/random" rb]
	set random [read $fd 16]
	close $fd

	binary scan $random "c*" random_array

	set output ""
	set i -1
	foreach val $random_array {
	    incr i

	    switch -exact -- $i {
		6 {
		    set val [expr {($val & 0x0f) | 0x40}]
		}
		8 {
		    set val [expr {($val & 0x3f) | 0x80}]
		}
		default {
		    set val [expr {$val & 0xff}]
		}
	    }

	    switch -exact -- $i {
		4 -
		6 -
		8 -
		10 {
		    append output "-"
		}
	    }

	    append output [format {%02x} $val]
	}

	return $output
    }

    proc _format_pos {frame} {
	if {"[dict get $frame type]" == "source"} {
	    set file [dict get $frame file]
	    set line [dict get $frame line]
	    return "$file:$line: "
	}
	return ""
    }
}

# Local Variables:
# mode: tcl
# End:
