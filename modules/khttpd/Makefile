SYSDIR = $(HOME)/freebsd/sys

SRCS = khttpd.c khttpd_string.c khttpd_mbuf.c khttpd_json.c
SRCS += khttpd_sysctl.c khttpd_file.c khttpd_sdt.c
KMOD = khttpd

#CFLAGS +=
CFLAGS += -DINVARIANTS -DKTR -DKHTTPD_DEBUG -g

.include <bsd.kmod.mk>
