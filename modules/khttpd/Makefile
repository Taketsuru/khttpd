SYSDIR = /usr/home/taketsuru/freebsd/sys
KERNBUILDDIR = $(MAKEOBJDIRPREFIX)$(SYSDIR)/KDEV

SRCS = khttpd.c khttpd_string.c khttpd_mbuf.c khttpd_json.c
SRCS += khttpd_sysctl.c khttpd_file.c khttpd_sdt.c
KMOD = khttpd

#CFLAGS +=
CFLAGS += -g -DKHTTPD_DEBUG

.include <bsd.kmod.mk>
