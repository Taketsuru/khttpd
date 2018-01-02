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
set baseTime [lindex $argv 1]
set freqInMHz [lindex $argv 2]

set ktrfile [open $filename]
set freq [expr {$freqInMHz * 1000000}]

set heap [dict create]
set lastAlloc [dict create]

while {[gets $ktrfile line] >= 0} {
    set line [string trim $line]

    if {$line eq "" || [regexp -line -- {^#.*$} $line]} {
	puts $line
	continue
    }

    if {![regexp -line -- {([[:digit:]]+) ([[:digit:]]+) ([[:digit:]]+) (.*)$} \
	      $line match timestamp thread cpu desc]} {
	puts $line
	continue
    }

    puts [format {%.6f %d %d %s} \
	      [expr {($timestamp - $baseTime + 0.0) / $freq}] \
	      $thread $cpu $desc]
}

close $ktrfile
