## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4
# Maximum pigz compression
GZIP_ENV = -11

licdir = $(libdir)
lic_DATA = LICENSE

SUBDIRS	= src
DIST_SUBDIRS = src

EXTRA_DIST = \
	README* \
	ChangeLog \
	bootstrap.sh \
	LICENSE \
	CMakeLists.txt \
	cmake_uninstall.cmake.in \
	cmake_check_interference_sizes.cmake

DISTCLEANFILES = \
        _configs.sed
