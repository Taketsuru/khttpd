SYSDIR = /home/taketsuru/freebsd/sys

SRCS = khttpd.c khttpd_json.c khttpd_sysctl.c khttpd_file.c
KMOD = khttpd

#CFLAGS +=
CFLAGS += -DINVARIANTS -DKTR -DKHTTPD_DEBUG

.include <bsd.kmod.mk>
