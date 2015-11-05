SYSDIR = $(HOME)/src/sys

SRCS = khttpd.c
KMOD = khttpd

#CFLAGS +=
CFLAGS += -DINVARIANTS -DKTR -DKHTTPD_DEBUG

EXPORT_SYMS =
EXPORT_SYMS += khttpd_route_add
EXPORT_SYMS += khttpd_route_remove
EXPORT_SYMS += khttpd_route_clear_all
EXPORT_SYMS += khttpd_socket_retain
EXPORT_SYMS += khttpd_socket_release
EXPORT_SYMS += khttpd_enable
EXPORT_SYMS += khttpd_disable

.include <bsd.kmod.mk>

