
AC_PREREQ([2.69])
AC_INIT([libxjwt], [1.0.1])
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

AX_CHECK_OPENSSL

AC_CHECK_LIB([crypto],[EVP_PKEY_free], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_HEADERS([openssl/evp.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

AC_CHECK_LIB([jansson],[json_true], [], [AC_MSG_ERROR([Jansson libraries required])])
AC_CHECK_HEADERS([jansson.h],[],[AC_MSG_ERROR([Jansson headers required])])


AC_CONFIG_HEADERS([src/internal/xjwt_config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT