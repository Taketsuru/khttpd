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

package require json
package require test

namespace eval test {

    namespace export {[a-z]*}

    variable _header_only_fields [lmap {v} {
	Age
	Authorization
	Cache-Control
	Content-Encoding
	Content-Length
	Content-Range
	Content-Type
	Expect
	Expires
	Data
	Host
	Location
	Max-Forwards
	Pragma
	Proxy-Authenticate
	Proxy-Authorization
	Range
	Retry-After
	Set-Cookie
	TE
	Trailer
	Transfer-Encoding
	Vary
	Warning
	WWW-Authenticate
    } { string tolower $v }]
    variable token_regexp {[a-zA-Z0-9!#$%&'*+-.^_`|~]+}

    proc assert_it_is_default_error_response {response} {
	set content_type [$response field Content-Type]
	assert {[llength $content_type] == 1 &&
	    [lindex $content_type 0] eq
	    "application/problem+json; charset=utf-8"}

	# The response body is a JSON object.
	set ents [json::many-json2dict [$response body]]
	assert {[llength $ents] == 1}

	# The object's property 'status' has the same status code as
	# the status line of the response.
	assert {[dict get [lindex $ents 0] status] ==
	    [$response status]}
    }

    proc assert_it_is_the_last_response {sock response} {
	set connection [$response field Connection]
	test::assert {[llength $connection] == 1 &&
	    [lindex $connection 0] == "close"}
	test::assert {[$response rest] == ""}
	test::assert_eof $sock
    }

    proc get_list_field {fields key} {
	set result {}
	foreach line [split $fields "\n"] {
	    if {![regexp -- {^([^:]+):([^\n]*)$} $line match name value]} {
		continue
	    }

	    if {$name ne $key} {
		continue
	    }

	    foreach value [split $value ,] {
		set value [string trim $value]
		if {$value ne ""} {
		    lappend result $value
		}
	    }
	}
	return $result
    }


    proc is_token {str} {
	variable ::test::token_regexp
	return [regexp -- "^$token_regexp\$" $str]
    }

    proc remove_dot_segments {path} {
	set result ""

	while {$path ne ""} {
	    switch -glob -- $path {
		../* {
		    # case A
		    set path [string range $path 3 end]
		}
		./* {
		    # case A
		    set path [string range $path 2 end]
		}
		/./* {
		    # case B
		    set path [string range $path 2 end]
		}
		/. {
		    # case B
		    set path /
		}
		/../* {
		    # case C
		    set path [string range $path 3 end]
		    set pos [string last / $result]
		    set result [string replace $result $pos end ""]
		}
		/.. {
		    # case C
		    set path /
		    set pos [string last / $result]
		    set result [string replace $result $pos end ""]
		}
		. -
		.. {
		    # case D
		    set path ""
		}
		/* {
		    # case E
		    set pos [string first / $path 1]
		    if {$pos == -1} {
			append result $path
			set path ""
		    } else {
			append result [string range $path 0 $pos-1]
			set path [string range $path $pos end]
		    }
		}
		default {
		    # case E
		    set pos [string first / $path]
		    if {$pos == -1} {
			append result $path
			set path ""
		    } else {
			append result [string range $path 0 $pos-1]
			set path [string range $path $pos end]
		    }
		}
	    }
	}
	return $result
    }

    proc tokenize_field {list} {
	set value [join $list ,]
	regsub -all {[ \t]} $value "" value
	regsub -all {,+} $value "," value
	set value [split $value ,]
	return $value
    }

    oo::class create http_response {
	variable _arrival_time _body_ranges _completion_time \
	    _chunk_pos _end _fields \
	    _fields_pos _request _response _trailer_pos

	constructor {request arrival_time} {
	    set _request $request
	    set _arrival_time $arrival_time
	    set _trailer_pos ""

	    oo::objdefine [self] method append {data} {
		tailcall my _append_1st_line $data
	    }
	}

	method arrival_time {} {
	    return $_arrival_time
	}

	method body {} {
	    set result ""
	    foreach {start end} $_body_ranges {
		append result [string range $_response $start [expr {$end - 1}]]
	    }
	    return $result
	}

	method field {name} {
	    set canon_name [string tolower $name]
	    if {[info exists _fields($canon_name)]} {
		return $_fields($canon_name)
	    } else {
		return {}
	    }
	}

	method completion_time {} {
	    return $_completion_time
	}

	method response {} {
	    return $_response
	}

	method reason {} {
	    test::assume {[regexp -- {^[^ ]+ [0-9]+ ([^\n]*)\n} \
			       $_response match result]}
	    return $result
	}

	method rest {} {
	    return [string range $_response $_end end]
	}

	method request {} {
	    return $_request
	}

	method request_line {} {
	    set pos [string first "\r\n" $_request]
	    if {$pos == -1} {
		return $_request
	    } else {
		return [string range $_request 0 $pos+1]
	    }
	}

	method status {} {
	    test::assume {[regexp -- {HTTP/1\.1 ([0-9]+) .*} \
			      $_response match result]}
	    return $result
	}

	method _add_fields {str} {
	    variable ::test::_header_only_fields

	    set lines [split $str "\n"]
	    foreach line $lines {
		test::assert {[string index $line end] == "\r"} \
		    "field \"$line\" is not terminated by a CRLF sequence"

		set ch [string index $line 0]
		test::assert {$ch != " " && $ch != "\t"} \
		    "whitespace preceding line $line"

		set pos [string first ":" $line]
		test::assert {$pos != -1} \
		    "no \":\" in a header field \"$line\""
		test::assert {$pos != 0} \
		    "no field name in \"$line\""

		set ch [string index $line $pos-1]
		test::assert {$ch != " " && $ch != "\t"} \
		    "a whitespace preceding \":\" in line $line"

		# A field name is a token.
		set name [string range $line 0 $pos-1]
		test::assert {[test::is_token $name]}

		# Some fields can't be used in trailers.
		test::assert {$_trailer_pos == "" ||
		    [string tolower $name] ni $_header_only_fields}

		# For the sake of readability, the server inserts a
		# whitespace just after ':'.
		test::assert {[string index $line $pos+1] == " "}

		# The server adds no whitespace around the field value
		# except just after ':'.
		set value [string range $line $pos+2 end-1]
		test::assert {$value eq [string trim $value "\t "]}

		lappend _fields([string tolower $name]) $value
	    }
	}

	method _append_1st_line {data} {
	    append _response $data

	    set pos [string first "\r\n" $_response]
	    if {$pos == -1} {
		return 0
	    }

	    # The status line is well-formed.
	    test::assert {[regexp -- {^HTTP/1\.1 [1-9][0-9]{2} .*$} \
			       [string range $_response 0 $pos-1]]}

	    set _fields_pos [expr {$pos + 2}]

	    oo::objdefine [self] method append {data} {
		tailcall my _append_field $data
	    }

	    tailcall my _append_field ""
	}

	method _append_body {data} {
	    append _response $data

	    set resp_len [string length $_response]
	    set end [lindex $_body_ranges end]
	    if {$resp_len < $end} {
		return 0
	    }

	    if {$_chunk_pos == 0} {
		set _end $end
		set _completion_time [expr {[clock milliseconds] / 1000.0}]
		return 1
	    }

	    oo::objdefine [self] method append {data} {
		tailcall my _append_chunk $data
	    }

	    tailcall my _append_chunk ""
	}

	method _append_chunk {data} {
	    variable ::test::token_regexp
	    append _response $data

	    set pos [string first "\r\n" $_response $_chunk_pos+2]
	    if {$pos == -1} {
		return 0
	    }

	    set end [expr {$pos + 2}]
	    set line [string range $_response $_chunk_pos $pos-1]
	    test::assert {regexp -- "^\r\n(\[0-9a-fA-f]+)(?:;${token_regexp}(?:=(?:$token_regexp|\"\[^\"]*\"))?)*$" $line match chunk_size}
	    scan $chunk_size {%llx} chunk_size

	    if {$chunk_size == 0} {
		set _trailer_pos $end
		oo::objdefine [self] method append {data} {
		    tailcall my _append_field $data
		}

	    } else {
		set _chunk_pos [expr {$end + $chunk_size}]
		lappend _body_ranges $end $_chunk_pos

		oo::objdefine [self] method append {data} {
		    tailcall my _append_body $data
		}
	    }

	    tailcall my append ""
	}

	method _append_field {data} {
	    append _response $data

	    if {$_trailer_pos == ""} {
		set start [expr {$_fields_pos - 2}]
	    } else {
		set start [expr {$_trailer_pos - 2}]
	    }

	    set pos [string first "\r\n\r\n" $_response $start]
	    if {$pos == -1} {
		return 0
	    }

	    my _add_fields [string range $_response $start+2 $pos]

	    set end [expr {$pos + 4}]

	    if {$_trailer_pos != ""} {
		set _end $end
		set _completion_time [expr {[clock milliseconds] / 1000.0}]
		return 1
	    }

	    test::assume {[regexp -- {^[^ ]+ ([0-9]+)} $_response match status]}
	    set status_type [expr {$status / 100}]

	    if {![regexp -- {(^[^ ]+) } $_request match method]} {
		set method ""
	    }

	    if {$method eq "HEAD" ||
		($method eq "CONNECT" && $status_type == 2) ||
		$status_type == 1 || $status == 204 || $status == 304} {
		lappend _body_ranges $end $end
		tailcall my _done
	    }

	    set transfer_encoding \
		[test::tokenize_field [my field Transfer-Encoding]]
	    set chunked_pos [lsearch -exact $transfer_encoding chunked]

	    if {$chunked_pos != -1} {
		# If there is token 'chunked in the Transfer-Encoding
		# field, it must be the last element.
		test::assert {$chunked_pos == [llength $transfer_encoding] - 1}

		oo::objdefine [self] method append {data} {
		    tailcall my _append_chunk $data
		}

		set _chunk_pos [expr {$pos + 2}]

	    } else {
		# If 'chunked' is not specified, there is a valid
		# Content-Length field.
		set content_length [my field Content-Length]
		test::assert {[llength $content_length] == 1}
		set content_length [lindex $content_length 0]
		test::assert {[regexp -- {^(0|[1-9][0-9]*)$} $content_length]}

		lappend _body_ranges $end [expr {$end + $content_length}]

		oo::objdefine [self] method append {data} {
		    tailcall my _append_body $data
		}

		set _chunk_pos 0
	    }

	    tailcall my append ""
	}
    }
}

# Local Variables:
# mode: tcl
# End:
