cmake_minimum_required(VERSION 3.12.0 FATAL_ERROR)

project(memlogger VERSION 2.1.2 LANGUAGES CXX)

option(ENABLE_RELEASE "Enable release build" ON)

include(CheckCXXCompilerFlag)

# Check and set highest possible C++ dialect
CHECK_CXX_COMPILER_FLAG("-std=c++20" COMPILER_SUPPORTS_CXX20)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
CHECK_CXX_COMPILER_FLAG("-std=c++14" COMPILER_SUPPORTS_CXX14)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if (COMPILER_SUPPORTS_CXX20)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")
elseif (COMPILER_SUPPORTS_CXX17)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
elseif (COMPILER_SUPPORTS_CXX14)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
elseif (COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(FATAL_ERROR "Compiler ${CMAKE_CXX_COMPILER} has no C++11 support.")
endif()

# Check and set compiler specific options
if (CMAKE_CXX_COMPILER_ID MATCHES SunPro)
    add_compile_options(-xO4 -mt=yes -xatomic=studio)
    CHECK_CXX_COMPILER_FLAG("-xlinkopt=2" COMPILER_SUPPORTS_LINKOPT)
    if (COMPILER_SUPPORTS_LINKOPT)
        add_compile_options(-xlinkopt=2)
    endif()
elseif (CMAKE_CXX_COMPILER_ID MATCHES Clang)
    add_compile_options(-O3 -stdlib=libc++ -flto=thin)
    add_link_options(-lpthread)
    CHECK_CXX_COMPILER_FLAG("-flto=thin" COMPILER_SUPPORTS_LTOTHIN)
    if (COMPILER_SUPPORTS_LTOTHIN)
        add_compile_options(-flto=thin)
    endif()
elseif (CMAKE_CXX_COMPILER_ID MATCHES GNU)
    add_compile_options(-O3 -pthread -flto)
    add_link_options(-lpthread)
    CHECK_CXX_COMPILER_FLAG("-flto" COMPILER_SUPPORTS_LTO)
    if (COMPILER_SUPPORTS_LTO)
        add_compile_options(-flto)
    endif()
else()
    add_compile_options(-O3 -pthread)
    add_link_options(-lpthread)
endif()

include(CheckFunctionExists)
include(CheckIncludeFiles)

check_function_exists(malloc_usable_size HAVE_MALLOC_USABLE_SIZE)

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
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PROJECT_NAME}-${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION "\
Very simple memory logger, designed to profile the application by the nature of memory allocations in accordance with the size of the chunks.\
Feel free to check project wiki at https://github.com/yvoinov/memlogger/wiki\
")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/yvoinov/memlogger")

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)

set(CPACK_SOURCE_GENERATOR "TBZ2;TGZ")
set(CPACK_SOURCE_IGNORE_FILES
    /.git
    /.libs
    /.deps
    /autom4te.cache
    /.*build.*
    /dist.sh
    /libtool
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
