AM_CPPFLAGS = -I$(top_srcdir)/src
libmemlogger_la_CXXFLAGS = @CXXFLAGS@ -fPIC -ldl
libmemlogger_la_LDFLAGS = @LDFLAGS@ -shared -version-info @MEMLOGGER_CURRENT@:@MEMLOGGER_REVISION@:@MEMLOGGER_AGE@

lib_LTLIBRARIES = libmemlogger.la
libmemlogger_la_SOURCES = memlogger.h memlogger.cc

memlogger_report_CXXFLAGS = @CXXFLAGS@
memlogger_report_LDFLAGS = @LDFLAGS@ @STATIC_LIBS@

bin_PROGRAMS = memlogger-report
memlogger_report_SOURCES = memlogger-report.cc

BUILT_SOURCES = \
	memlogger-report.h

CLEANFILES = \
	memlogger-report.h

DISTCLEANFILES = \
	Makefile \
	memlogger-report.h



