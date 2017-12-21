lib_LTLIBRARIES = libxjwt.la

xjwtincludedir = $(includedir)/xjwt
xjwtinclude_HEADERS = include/xjwt/xjwt_error.h \
    include/xjwt/xjwt.h \
    include/xjwt/xjwt_keyset.h \
    include/xjwt/xjwt_validator.h \
    include/xjwt/xjwt_visibility.h

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
