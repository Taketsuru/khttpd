# Copyright (c) 2017, Taketsuru <taketsuru11@gmail.com>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SRCS = khttpd_ktr.c khttpd_malloc.c khttpd_test.c khttpd_init.c khttpd_main.c
SRCS +=	khttpd_costruct.c khttpd_string.c khttpd_mbuf.c khttpd_json.c
SRCS += khttpd_uuid.c khttpd_strtab.c khttpd_method.c khttpd_rewriter.c
SRCS += khttpd_webapi.c
SRCS += khttpd_job.c khttpd_log.c khttpd_event.c
SRCS += khttpd_stream.c khttpd_port.c khttpd_server.c khttpd_vhost.c
SRCS += khttpd_http.c
SRCS += khttpd_ctrl.c
SRCS += khttpd_file.c
#SRCS += khttpd_sysctl.c
#SRCS += khttpd_sdt.c
SRCS += 
KMOD = khttpd

.if !defined(KERNBUILDDIR)

beforedepend: ddb crypto
beforebuild: ddb crypto
ddb:
	ln -fhs `(cd ${SYSDIR}/ddb && /bin/pwd)` ddb
crypto:
	ln -fhs `(cd ${SYSDIR}/crypto && /bin/pwd)` crypto
CLEANFILES += ddb crypto

.endif

.include <bsd.kmod.mk>

CFLAGS += -O0 -g -DKHTTPD_DEBUG -DKTR=1 -DDDB=1
CFLAGS += -DKHTTPD_KTR_LOGGING \
	-DKHTTPD_KTR_FILE=\"$(.CURDIR)/../../test/ktr.txt\"
CFLAGS += -DKHTTPD_TRACE_MALLOC -DKHTTPD_TRACE_MALLOC_STACK_DEPTH=12
CFLAGS += -DKHTTPD_TRACE_FN -DKHTTPD_TRACE_BRANCH -DKHTTPD_TRACE_NOTE
CFLAGS += -DKHTTPD_TEST_REPORT_PATH=\"$(.CURDIR)/../../report.xml\"
CWARNFLAGS += -Wno-cast-qual

cscope:
	find . -name '*.[ch]' -print > cscope.files
	find /usr/src/sys -type f -name '*.[ch]' -print |egrep -v '^/usr/src/sys/(netatalk|ia64|arm|i386|pc98|riscv|sparc64|mips|boot|contrib|gnu|powerpc|tools|cddl)/' >> cscope.files
	cscope -b -q
