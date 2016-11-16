lib_LTLIBRARIES = librvi.la
librvi_la_SOURCES = btree.c rvi_list.c rvi.c
librvi_la_LDFLAGS = -version-info 0:1:0 $(OPENSSL_LDFLAGS) $(JANSSON_LDFLAGS) $(JWT_LDFLAGS)
librvi_la_CPPFLAGS = -I$(top_srcdir)/include $(OPENSSL_INCLUDES) $(CODE_COVERAGE_CPPFLAGS) -Wall
librvi_la_CFLAGS = $(JANSSON_CFLAGS) $(OPENSSL_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(JWT_CFLAGS) -std=gnu99
librvi_la_LIBADD = $(JANSSON_LIBS) $(OPENSSL_LIBS) $(JWT_LIBS) $(CODE_COVERAGE_LDFLAGS)

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = librvi.pc
