#
# $Id: configure.ac $
#

AC_INIT([yarrp],[0.6],[yarrp@cmand.org])
AC_CONFIG_SRCDIR([yarrp.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AC_PROG_CXX
AC_LANG(C++)
AX_CXX_COMPILE_STDCXX_11([],[])

AC_REVISION([m4_esyscmd_s([git describe --always])])
AC_DEFINE(GITREV,"[m4_esyscmd_s([git describe --always])]", "Git revision")

AX_PTHREAD([],AC_MSG_ERROR([Requires POSIX threading.]))
LIBS="$PTHREAD_LIBS $LIBS"
CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS -I/usr/local/include"
LDFLAGS="-L/usr/local/lib"

AX_CHECK_ZLIB


AC_MSG_RESULT(Determined host operating system: $host_os)
case $host_os in
*linux*)
    AC_DEFINE(OS,"LINUX",[Operating System String])
    AC_DEFINE(_LINUX,1,[Define to 1 if a Linux operating system]);;
*bsd*)
    AC_DEFINE(OS,"BSD",[Operating System String])
    AC_DEFINE(_BSD,1,[Define to 1 if a BSD-like operating system]);;
*darwin*)
    AC_DEFINE(OS,"OSX",[Operating System String])
    AC_DEFINE(_BSD,1,[Define to 1 if a BSD-like operating system])
    AC_DEFINE(_OSX,1,[Define to 1 if an Apple OSX operating system]);;
*)
    AC_DEFINE(OS,"UNDEF",[Operating System String]);;
esac

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h])
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h strings.h])
AC_CHECK_HEADERS([sys/param.h sys/stat.h sys/types.h sys/socket.h unistd.h])
AC_CHECK_HEADERS([netinet/in_systm.h netinet/udp.h])
AC_CHECK_HEADERS([netinet/tcp.h])
AC_CHECK_HEADERS([netinet/ip.h netinet/ip_icmp.h netinet/ip_var.h], [], [], [
   #ifdef HAVE_SYS_TYPES_H
   #include <sys/types.h>
   #endif
   #ifdef HAVE_NETINET_IN_SYSTM_H
   #include <netinet/in_systm.h>
   #endif
   #ifdef HAVE_NETINET_IN_H
   #include <netinet/in.h>
   #endif
])
AC_CHECK_HEADERS([netinet/udp_var.h], [], [], [
   #ifdef HAVE_SYS_TYPES_H
   #include <sys/types.h>
   #endif
   #ifdef HAVE_NETINET_IN_SYSTM_H
   #include <netinet/in_systm.h>
   #endif
   #ifdef HAVE_NETINET_IN_H
   #include <netinet/in.h>
   #endif
   #ifdef HAVE_NETINET_UDP_H
   #include <netinet/udp.h>
   #endif
   #ifdef HAVE_NETINET_IP_H
   #include <netinet/ip_var.h>
   #endif
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_STDBOOL
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CACHE_CHECK(whether in_addr_t is defined, sip_cv_type_in_addr_t,
   [AC_EGREP_HEADER(in_addr_t, netinet/in.h,
      sip_cv_type_in_addr_t=yes,
      sip_cv_type_in_addr_t=no)])

if test $sip_cv_type_in_addr_t = yes; then
  AC_DEFINE(HAVE_IN_ADDR_T,1,[Define to 1 if type in_addr_t is available.])
fi[]


# Check architecture endianness
AC_C_BIGENDIAN
if test "x$ac_cv_c_bigendian" = "xyes"; then
  AC_DEFINE(HAVE_BIG_ENDIAN,1,[Define to 1 for big endian, 0 otherwise.])
fi

# Checks for library functions.
AC_CHECK_FUNCS([inet_ntoa memset select socket strerror])

AC_SEARCH_LIBS([socket], [socket])

# Include pcap library on non-Linux systems
# Don't need pcap on Linux since we can use recvfrom on raw socket
AS_CASE([$host_os], [*linux*], , 
	[AC_SEARCH_LIBS(pcap_close, pcap,, AC_MSG_ERROR(pcap library required))])

AC_CHECK_HEADER([cperm.h],
        AC_CHECK_LIB([cperm], [cperm_create], ,
                AC_MSG_ERROR([libcperm required 
                              (https://github.com/lancealt/libcperm)])),
        AC_MSG_ERROR([libcperm required (https://github.com/lancealt/libcperm)]))

AC_CONFIG_FILES([
	Makefile
	utils/Makefile
])
AC_OUTPUT
