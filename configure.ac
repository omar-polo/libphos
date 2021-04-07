AC_INIT([libphos], [0.1.0], [phos@omarpolo.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_LIBOBJ_DIR([compat])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_PROG_CC
AM_PROG_AR
LT_INIT

AC_REPLACE_FUNCS([
	explicit_bzero	\
	memmem		\
	strlcat		\
	strlcpy		\
])

AC_CHECK_FUNCS([asr_run])

AC_SEARCH_LIBS([tls_init], [tls], [],
	[AC_MSG_ERROR([unable to find libtls])])
AC_DEFINE([WITH_LIBTLS], [1], [Wether we're using libtls])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
