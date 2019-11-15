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
  yconfig.cpp

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
  yconfig.h

man_MANS = \
  yarrp.1 

EXTRA_DIST = \
  $(man_MANS) \
  LICENSE \
  CHANGES 

yarrp.1.pdf: yarrp.1
	man -t ./yarrp.1 | ps2pdf - > yarrp.1.pdf
