#!/bin/sh
# \
exec tclsh8.7 "$0" ${1+"$@"}

# findleak --
#
#	This file implements memory leak detector for khttpd.ko.
#
# Copyright (c) 2017 Taketsuru <taketsuru11@gmail.com>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

set filename [lindex $argv 0]
set ktrfile [open $filename]

set heap [dict create]
set lastAlloc [dict create]

while {[gets $ktrfile line] >= 0} {
    if {[regexp -line -- {^[[:blank:]]*#.*$} $line]} {
	continue
    }

    if {![regexp -line -- {([[:digit:]]+) ([[:digit:]]+) ([[:digit:]]+) (.*)$} \
	      $line match timestamp thread cpu desc]} {
	puts "malformed: $line"
	continue
    }

    if {[regexp -line -- {^#([[:digit:]]+) (.*)$} $desc match depth caller] &&
	[dict exist $lastAlloc $thread] &&
	$depth == [dict get $heap [dict get $lastAlloc $thread] depth]} {
	set mem [dict get $lastAlloc $thread]
	dict set heap $mem "stack$depth" $caller
	dict set heap $mem depth [expr {[dict get $heap $mem depth] + 1}]
	continue
    }

    dict unset lastAlloc $thread

    if {![regexp -line -- {^([^ ]+) .*$} $desc match word]} {
	# puts "no word: $line"
	continue
    }

    switch -exact -- $word {
	alloc {
	    if {[scan $desc {alloc %llx %llx} mem size] != 2} {
		puts "malformed alloc: $desc"
		continue
	    }
	    dict set heap $mem [dict create thread $thread \
				    timestamp $timestamp size $size depth 0]
	    dict set lastAlloc $thread $mem
	}

	free {
	    if {[scan $desc {free %llx} mem] != 1} {
		puts "malformed free: $line"
		continue
	    }

	    if {$mem == 0} {
		continue
	    }

	    if {![dict exists $heap $mem]} {
		puts "missing alloc: $line"
		continue
	    }
	    dict unset heap $mem
	}
    }
}

close $ktrfile

dict for {mem value} $heap {
    puts [format {leak %#x %#x at %d} $mem [dict get $value size] \
	      [dict get $value timestamp]]
    set depth [dict get $value depth]
    for {set i 0} {$i < $depth} {incr i} {
	puts [format {  %d %s} $i [dict get $value "stack$i"]]
    }
}
