ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = .clang-format \
    buildconf.sh \
    CODE_OF_CONDUCT.md \
    CONTRIBUTING.md \
    NOTICE \
    LICENSE \
    ./dist/rpm/libxjwt.spec \
    README.md

lib_LTLIBRARIES = libxjwt.la
noinst_LIBRARIES = libcmockery.a
check_PROGRAMS = test_all
TESTS = $(check_PROGRAMS)

xjwtincludedir = $(includedir)/xjwt
xjwtinclude_HEADERS = include/xjwt/xjwt_error.h \
    include/xjwt/xjwt.h \
    include/xjwt/xjwt_keyset.h \
    include/xjwt/xjwt_validator.h \
    include/xjwt/xjwt_visibility.h

libxjwt_la_CPPFLAGS = -I$(top_srcdir)/include

libxjwt_la_SOURCES = src/b64.c \
    src/error.c \
    src/json.c \
    src/key.c \
    src/key_ec.c \
    src/keyset.c \
    src/parse.c \
    src/validator.c \
    src/internal/xjwt_b64.h \
    src/internal/xjwt_json.h \
    src/internal/xjwt_key.h \
    src/internal/xjwt_keyset.h \
    src/internal/xjwt_parse.h

libxjwt_la_LDFLAGS = -version-info 1:0:1

libcmockery_a_CPPFLAGS = -I$(top_srcdir)/vendor/cmockery/src/google \
    -U HAVE_CONFIG_H

libcmockery_a_SOURCES = vendor/cmockery/src/cmockery.c \
	vendor/cmockery/src/google/cmockery.h

EXTRA_DIST += vendor/cmockery/COPYING \
	vendor/cmockery/README

test_all_CPPFLAGS = -I$(top_srcdir)/include \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/vendor/cmockery/src/google \
    -DXJWT_TEST_ALL=1

test_all_SOURCES = tests/test_all.c \
    tests/test_keyset.c \
    tests/test_split.c \
    tests/test_verify.c \
    tests/utils.c \
    tests/xjwt_tests.h

EXTRA_DIST += ./tests/fixtures/e1_af.jwt \
	 ./tests/fixtures/e1_jwk.json \
	 ./tests/fixtures/jwk_af.json

test_all_LDADD = libxjwt.la libcmockery.a

CLANG_FORMAT = clang-format
CLANG_FORMAT_OPTIONS = -style=file -i

format: $(libxjwt_la_SOURCES) $(test_all_SOURCES) $(HEADERS)
	$(CLANG_FORMAT) $(CLANG_FORMAT_OPTIONS) $(libxjwt_la_SOURCES) $(test_all_SOURCES) $(HEADERS)

.PHONY: format
