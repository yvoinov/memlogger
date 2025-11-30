#
# SYNOPSIS
#
#   AX_INTERFERENCE_SIZES([ACTION-IF-FOUND])
#
# DESCRIPTION
#
#   Check if interference_sizes are defined
#
#   If any of the test for the interference_sizes were succeeded, the configure
#   script would run ACTION-IF-FOUND if it is specified.
#
# LICENSE
#
#   Copyright (c) 2021-2025 Yuri Voinov <yvoinov@gmail.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 4

AC_DEFUN([AX_INTERFERENCE_SIZES],[
  AC_LANG([C++])
  AC_MSG_CHECKING([if STL has interference_sizes])
  AC_RUN_IFELSE([AC_LANG_PROGRAM([
#include <new>
                                 ],
                                 [
#ifdef __cpp_lib_hardware_interference_size
    return !(std::hardware_constructive_interference_size &&
             std::hardware_destructive_interference_size); // return 0 if the interference_sizes are defined
#else
    return 1; // no interference_sizes
#endif
                                 ])],
                    [AC_MSG_RESULT([yes])
                     AC_SUBST([$1],[0])],
                    [AC_MSG_RESULT([no])
                     AC_SUBST([$1],[1])])
])
