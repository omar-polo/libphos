AC_INIT([libphos], [0.1.0], [phos@omarpolo.com])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_PROG_CC
AM_PROG_AR
LT_INIT

AC_ARG_WITH([tlsbackend],
	AS_HELP_STRING([--with-tlsbackend], [The TLS backend to use [default=libtls]]))

if test "x$with_tlsbacked" = "x"; then
	with_tlsbackend=libtls
fi

case "$with_tlsbackend" in
	libtls)
		tls_backend=libtls
		AC_SEARCH_LIBS([tls_init], [tls], [],
			[AC_MSG_ERROR([unable to find libtls])])
		AC_DEFINE([WITH_LIBTLS], [1], [Wether we're using libtls])
		;;
	*)
		AC_MSG_ERROR([Invalid $with_tlsbackend TLS backend.])
		;;
esac

AC_CHECK_FUNCS([asr_run])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
