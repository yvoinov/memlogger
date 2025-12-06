cmake_minimum_required(VERSION 3.12.0 FATAL_ERROR)

project(memlogger VERSION 2.2.2 LANGUAGES CXX)

option(ENABLE_RELEASE "Enable release build" ON)
option(ENABLE_TOPDIR "Enable including package top dir to distribution" OFF)

include(CheckCXXSourceCompiles)

check_cxx_source_compiles("namespace Outer {namespace Inner { int i = 0; }}
                           using namespace Outer::Inner;
                           int foo() { return i; }
                           int main() { return foo(); }"
                           HAVE_NAMESPACES
                         )

if (HAVE_NAMESPACES)
    check_cxx_source_compiles("#include <list>
                               #include <deque>
                               using namespace std;
                               int main() { list<int> x; x.push_back(5);
                               list<int>::iterator iter = x.begin();
                               if (iter != x.end()) ++iter;
                               return 0; }"
                               HAVE_STL
                             )
    if (NOT HAVE_STL)
        message(FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER} has no STL.")
    endif()
else()
        message(FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER} has no namespaces.")
endif()

function(add_opt_if_missing opt)
    string(FIND "${CMAKE_CXX_FLAGS}" "${opt}" found)
    if (found EQUAL -1)
        add_compile_options("${opt}")
    endif()
endfunction()

include(CheckCXXCompilerFlag)

# Check and set highest possible C++ dialect
string(REGEX MATCH "-std=[^ ]+" USER_STD "${CMAKE_CXX_FLAGS}")
if (NOT USER_STD)
    CHECK_CXX_COMPILER_FLAG("-std=c++20" COMPILER_SUPPORTS_CXX20)
    CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
    CHECK_CXX_COMPILER_FLAG("-std=c++14" COMPILER_SUPPORTS_CXX14)
    CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
    if (COMPILER_SUPPORTS_CXX20)
        add_opt_if_missing("-std=c++20")
    elseif (COMPILER_SUPPORTS_CXX17)
        add_opt_if_missing("-std=c++17")
    elseif (COMPILER_SUPPORTS_CXX14)
        add_opt_if_missing("-std=c++14")
    elseif (COMPILER_SUPPORTS_CXX11)
        add_opt_if_missing("-std=c++11")
    else()
        message(FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER} has no C++11 support.")
    endif()
endif()

find_package(Threads)

if (Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
    set(HAVE_PTHREAD_H 1)
    set(_REENTRANT 1)
endif()

# Check and set compiler specific options
if (CMAKE_CXX_COMPILER_ID MATCHES SunPro)
    add_opt_if_missing("-xO4")
    add_opt_if_missing("-mt=yes")
    add_opt_if_missing("-xatomic=studio")
    CHECK_CXX_COMPILER_FLAG("-xlinkopt=2" COMPILER_SUPPORTS_LINKOPT)
    if (COMPILER_SUPPORTS_LINKOPT)
        add_opt_if_missing("-xlinkopt=2")
    endif()
elseif (CMAKE_CXX_COMPILER_ID MATCHES Clang)
    add_opt_if_missing("-O3")
    add_opt_if_missing("-stdlib=libc++")
    add_opt_if_missing("-flto=thin")
    add_link_options(-lpthread)
    CHECK_CXX_COMPILER_FLAG("-flto=thin" COMPILER_SUPPORTS_LTOTHIN)
    if (COMPILER_SUPPORTS_LTOTHIN)
        add_opt_if_missing("-flto=thin")
    endif()
elseif (CMAKE_CXX_COMPILER_ID MATCHES GNU)
    add_opt_if_missing("-O3")
    add_opt_if_missing("-pthread")
    add_opt_if_missing("-flto")
    add_link_options(-lpthread)
    CHECK_CXX_COMPILER_FLAG("-flto" COMPILER_SUPPORTS_LTO)
    if (COMPILER_SUPPORTS_LTO)
        add_opt_if_missing("-flto")
    endif()
else()
    add_opt_if_missing("-O3")
    add_opt_if_missing("-pthread")
    add_link_options(-lpthread)
endif()

if (ENABLE_RELEASE)
    # Strip binary for release builds
    add_link_options(-s)
endif()

include(cmake_check_interference_sizes.cmake)

include(CheckFunctionExists)
include(CheckIncludeFiles)

check_include_files(dlfcn.h HAVE_DLFCN_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(sys/mman.h HAVE_SYS_MMAN_H)

add_subdirectory(${PROJECT_SOURCE_DIR}/src)

configure_file(${PROJECT_SOURCE_DIR}/src/autoconf.h.cmake.in ${PROJECT_SOURCE_DIR}/src/autoconf.h)

install(FILES LICENSE TYPE LIB)

if (NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
  )
endif()

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PROJECT_NAME}-${PROJECT_VERSION})
set(CPACK_SYSTEM_NAME ${CMAKE_SYSTEM}-${CMAKE_SYSTEM_PROCESSOR})
set(CPACK_PACKAGE_DESCRIPTION "\
Very simple memory logger, designed to profile the application by the nature of memory allocations in accordance with the size of the chunks.\
Feel free to check project wiki at https://github.com/yvoinov/memlogger/wiki\
")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/yvoinov/memlogger")

set(CPACK_SET_DESTDIR ON)

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ${ENABLE_TOPDIR})

set(CPACK_SOURCE_GENERATOR "TBZ2;TGZ")
set(CPACK_GENERATOR "TBZ2;TGZ")

set(CPACK_SOURCE_IGNORE_FILES
    /.git
    /.libs
    /.deps
    /autom4te.cache
    /.*build.*
    /*~$
    /dist.sh
    /libtool$
    /Makefile$
    /autoconf.h$
    /config.log
    /config.status
    /stamp-.*
    /libmemlogger.*
    /*.gz
    /*.bz2
)

include(CPack)
