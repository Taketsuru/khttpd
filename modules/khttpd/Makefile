# Copyright (c) 2018, Taketsuru <taketsuru11@gmail.com>
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

SRCS = khttpd_ktr.c khttpd_test.c khttpd_malloc.c khttpd_gcov.c khttpd_init.c
SRCS += khttpd_main.c
SRCS +=	khttpd_string.c khttpd_mbuf.c khttpd_problem.c khttpd_json.c
SRCS += khttpd_costruct.c
SRCS += khttpd_uuid.c khttpd_strtab.c
SRCS += khttpd_method.c khttpd_field.c khttpd_status_code.c
SRCS += khttpd_rewriter.c khttpd_webapi.c khttpd_task.c
SRCS += khttpd_stream.c khttpd_port.c khttpd_job.c khttpd_log.c
SRCS += khttpd_server.c khttpd_vhost.c
SRCS += khttpd_http.c
SRCS += khttpd_ctrl.c
SRCS += khttpd_file.c
SRCS += khttpd_sysctl.c
SRCS += khttpd_fcgi.c

KMOD = khttpd

.if !defined(KERNBUILDDIR)

beforedepend: ddb crypto vnode_if_newproto.h vnode_if_typedef.h vnode_if.h
beforebuild: ddb crypto vnode_if_newproto.h vnode_if_typedef.h vnode_if.h
ddb:
	ln -fhs `(cd ${SYSDIR}/ddb && /bin/pwd)` ddb
crypto:
	ln -fhs `(cd ${SYSDIR}/crypto && /bin/pwd)` crypto
vnode_if_newproto.h:
	awk -f ${SYSDIR}/tools/vnode_if.awk ${SYSDIR}/kern/vnode_if.src -p
vnode_if_typedef.h:
	awk -f ${SYSDIR}/tools/vnode_if.awk ${SYSDIR}/kern/vnode_if.src -q
vnode_if.h:
	awk -f ${SYSDIR}/tools/vnode_if.awk ${SYSDIR}/kern/vnode_if.src -h
CLEANFILES += ddb crypto vnode_if.h

.endif

.include <bsd.kmod.mk>

.if defined(DEBUG_BUILD)

CFLAGS += -O0 -g -DKHTTPD_DEBUG -DKTR=1 -DDDB=1 -DDEBUG_LOCKS
CFLAGS += -DWITNESS -DINVARIANTS -DINVARIANT_SUPPORT
CFLAGS += -DKHTTPD_KTR_LOGGING \
	-DKHTTPD_KTR_FILE=\"$(.CURDIR)/../../test/log/ktr.log\"
CFLAGS += -DKHTTPD_TRACE_MALLOC
CFLAGS += -DKHTTPD_TRACE_FN -DKHTTPD_TRACE_BRANCH -DKHTTPD_TRACE_NOTE
CFLAGS += -DKHTTPD_TEST_ENABLE

.if defined(COVERAGE)
CFLAGS += --coverage -DKHTTPD_COVERAGE_ENABLE
LDFLAGS += --script khttpd_gcov.lds
.endif

.endif

CWARNFLAGS += -Wno-cast-qual

cscope:
	find . -name '*.[ch]' -print > cscope.files
	find /usr/src/sys -type f -name '*.[ch]' -print |egrep -v '^/usr/src/sys/(netatalk|ia64|arm|i386|pc98|riscv|sparc64|mips|boot|contrib|gnu|powerpc|tools|cddl)/' >> cscope.files
	cscope -b -q

CLEANFILES += $(SRCS:.c=.c.gcov) $(SRCS:.c=.gcno) $(SRCS:.c=.gcda)
