
AC_PREREQ([2.69])
AC_INIT([libxjwt], [1.0.1])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/key.c])
AM_INIT_AUTOMAKE([subdir-objects foreign])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

LT_INIT
AC_SUBST([LIBTOOL_DEPS])

AC_CHECK_HEADERS([malloc.h stddef.h stdint.h stdlib.h string.h])

AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset setenv strdup strrchr])

AX_CHECK_OPENSSL(
  [have_openssl=yes],
  [AC_MSG_ERROR([OpenSSL is required])]
)

if test "x$have_openssl" = "xyes"; then
  LIBS="$LIBS $OPENSSL_LIBS"
  CFLAGS="$CFLAGS $OPENSSL_INCLUDES"
  LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
fi

AC_CHECK_LIB([crypto],[EVP_PKEY_free], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_HEADERS([openssl/evp.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

AC_ARG_WITH([jansson],
    [AS_HELP_STRING([--with-jansson=DIR],
    [Path to Jansson])],
    [with_jansson=$withval],
    [])

AS_IF([test "x$with_jansson" != "x"],
    [AC_MSG_NOTICE([Found --with-jansson=${with_jansson}])])

AS_IF([test "x$with_jansson" != "x"],
    [CPPFLAGS="$CPPFLAGS -I${with_jansson}/include"])
AS_IF([test "x$with_jansson" != "x"],
    [LDFLAGS="$LDFLAGS -L${with_jansson}/lib -Wl,-rpath,${with_jansson}/lib"])

AX_CHECK_LIBRARY([JANSSON],[jansson.h],[jansson], [],
    [AC_MSG_ERROR([Unable to find libjansson])])

if test "x$ax_cv_have_JANSSON" = "xyes"; then
  CFLAGS="$CFLAGS $JANSSON_CPPFLAGS"
  LDFLAGS="$LDFLAGS $JANSSON_LDFLAGS"
fi
AC_CHECK_LIB([jansson],[json_true], [], [AC_MSG_ERROR([Jansson libraries required. Try adding --with-jansson=DIR])])

AC_CONFIG_HEADERS([src/internal/xjwt_config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
