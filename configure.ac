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

# check compiler flags
AC_DEFUN([CC_ADD_CHECK_FLAGS], [
	AC_MSG_CHECKING([if $CC supports $1 flag])
	old_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $1"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
		AC_MSG_RESULT(yes),
		AC_MSG_RESULT(no)
		CFLAGS="$old_CFLAGS")
])
CC_ADD_CHECK_FLAGS([-Wall])
CC_ADD_CHECK_FLAGS([-Wextra])
CC_ADD_CHECK_FLAGS([-Wmissing-prototypes])
CC_ADD_CHECK_FLAGS([-Wstrict-prototypes])
CC_ADD_CHECK_FLAGS([-Wwrite-strings])
CC_ADD_CHECK_FLAGS([-Wno-unused-parameter])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
