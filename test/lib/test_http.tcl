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

package provide test_http 0.0

namespace eval test {

    namespace export http_status

    proc is_token {str} {
	return [regexp -- {^[a-zA-Z0-9!#$%&'*+-.^_`|~]+$} $str]
    }

    oo::class create http_response_header {
	variable _fields _status_line

	constructor {response} {
	    set pos [string first "\r\n\r\n" $response]
	    test::assert {$pos != -1} "no CRLF CRLF sequence in the response"

	    set header [string range $response 0 $pos]
	    set lines [split $header "\n"]

	    foreach line $lines {
		test::assert {[string index $line end] == "\r"} \
		    "line \"$line\" is not terminated by a CRLF sequence"
	    }

	    set _status_line [string range [lindex $lines 0] 0 end-1]
	    test::assert {[regexp -- {HTTP/1\.1 [0-9]+ .*} $_status_line]}

	    set _fields {}
	    foreach line [lrange $lines 1 end] {
		set ch [string index $line 0]
		test::assert {$ch != " " && $ch != "\t"} \
		    "whitespace preceding line $line"

		set pos [string first ":" $line]
		test::assert {$pos != -1} \
		    "no \":\" in a header field \"$line\""
		test::assert {$pos != 0} \
		    "no field name in \"$line\""

		set ch [string index $line [expr {$pos - 1}]]
		test::assert {$ch != " " && $ch != "\t"} \
		    "a whitespace preceding \":\" in line $line"

		set name [string range $line 0 [expr {$pos - 1}]]
		test::assert {[test::is_token $name]}

		lappend _fields $name \
		    [string trim [string range $line [expr {$pos + 1}] end-1] \
			"\t "]
	    }
	}

	method field {name_arg} {
	    set result {}
	    foreach {name value} $_fields {
		if {[string compare -nocase $name $name_arg] == 0} {
		    lappend result $value
		}
	    }
	    return $result
	}

	method reason {} {
	    regexp -- {HTTP/1\.1 [0-9]+ (.*)} $_status_line match result]
	    return $result
	}

	method status {} {
	    test::assume {[regexp -- {HTTP/1\.1 ([0-9]+) .*} \
			      $_status_line match result]}
	    return $result
	}

	method status_line {} {
	    return $_status_line
	}
    }
}

# Local Variables:
# mode: tcl
# End:
