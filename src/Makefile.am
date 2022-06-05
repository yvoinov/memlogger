AM_CPPFLAGS = -I$(top_srcdir)/src
libmemlogger_la_CXXFLAGS = @CXXFLAGS@ -fPIC
libmemlogger_la_LDFLAGS = @LDFLAGS@ -shared -version-info @MEMLOGGER_CURRENT@:@MEMLOGGER_REVISION@:@MEMLOGGER_AGE@

lib_LTLIBRARIES = libmemlogger.la
libmemlogger_la_SOURCES = memlogger.h memlogger.cc

DISTCLEANFILES = \
	Makefile




