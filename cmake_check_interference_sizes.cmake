# --- Test interference sizes ---
file(WRITE "${CMAKE_BINARY_DIR}/check_interference_sizes.cpp" "
#include <new>
int main() {
#ifdef __cpp_lib_hardware_interference_size
    return !(std::hardware_constructive_interference_size &&
             std::hardware_destructive_interference_size);
#else
    return 1;
#endif
}
")

try_run(
    INTERFERENCE_RUN_RESULT
    INTERFERENCE_COMPILE_RESULT
    ${CMAKE_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/check_interference_sizes.cpp
)

if (INTERFERENCE_COMPILE_RESULT AND INTERFERENCE_RUN_RESULT EQUAL 0)
    message(STATUS "STL provides hardware interference sizes")
    add_compile_definitions(INTERFERENCE_SIZES)
    if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
        CHECK_CXX_COMPILER_FLAG("-Wno-interference-size" HAVE_NO_INTERFERENCE_WARN)
        if (HAVE_NO_INTERFERENCE_WARN)
            add_compile_options(-Wno-interference-size)
        endif()
    endif()
else()
    message(STATUS "No interference sizes in STL")
endif()
