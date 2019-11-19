SUBDIRS = utils

bin_PROGRAMS = yarrp

yarrp_SOURCES = \
  icmp.cpp \
  iplist.cpp \
  listener.cpp \
  listener6.cpp \
  mac.cpp \
  net.cpp \
  patricia.cpp \
  random_list.cpp \
  status.cpp \
  subnet.cpp \
  subnet_list.cpp \
  trace.cpp \
  trace4.cpp \
  trace6.cpp \
  util.cpp \
  yarrp.cpp \
  yconfig.cpp \
  libcperm/cperm.c \
  libcperm/prefix.c \
  libcperm/cycle.c \
  libcperm/ciphers/rc5.c \
  libcperm/ciphers/rc5-16.c \
  libcperm/ciphers/speck.c

include_HEADERS = \
  icmp.h \
  mac.h \
  patricia.h \
  random_list.h \
  stats.h \
  status.h \
  subnet.h \
  subnet_list.h \
  trace.h \
  ttlhisto.h \
  yarrp.h \
  yconfig.h \
  libcperm/cperm.h \
  libcperm/cperm-internal.h \
  libcperm/cycle.h \
  libcperm/feistel.h \
  libcperm/prefix.h \
  libcperm/ciphers/rc5-16.h \
  libcperm/ciphers/rc5.h \
  libcperm/ciphers/speck.h

man_MANS = \
  yarrp.1 

EXTRA_DIST = \
  $(man_MANS) \
  LICENSE \
  CHANGES 

yarrp.1.pdf: yarrp.1
	man -t ./yarrp.1 | ps2pdf - > yarrp.1.pdf
