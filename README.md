# Memlogger
[![CodeQL](https://github.com/yvoinov/memlogger/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/yvoinov/memlogger/actions/workflows/codeql-analysis.yml) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://github.com/yvoinov/memlogger/blob/main/LICENSE)
## Concepts

Unlike most similar solutions, memlogger is designed to profile the application by the nature of memory allocations in accordance with the size of the chunks.

Accordingly, only functions that directly allocate memory are logged. Logging of malloc, realloc, calloc (on compatible platforms), free (on platforms with malloc_usable_size), and reallocarray is supported.

Memlogger is implemented as a shared library. It produces the report immediately after logging completion. No separate log processor is required.

Log processing is performed directly in the library. The report contains the number of allocation requests for each function, grouped by requested size into buckets from 64 KiB upward. It also contains the maximum requested allocation size, average allocation calls per second, peak allocation calls per second, and logging session elapsed time.

This data allows you to get an idea of the memory allocation profile for the application and can be used to select the optimal parameters for the external memory allocator to achieve maximum performance.

Generally speaking, such statistics helps you define appropriate chunk size for chunk-based allocator in accordance with best-fit strategy.

## Build and installation

### Autotools build

To make and install memlogger run (GCC, most platforms):
```sh
# ./configure 'CXXFLAGS=-m64' --libdir=/usr/local/lib/64
```
or
```sh
# ./configure 'CXXFLAGS=-m32' --libdir=/usr/local/lib
```
then
```sh
# make && make install-strip
```
Installation prefix by default is /usr/local. Logging library `libmemlogger.so` will install into `$PREFIX/lib`.

### CMake build

32 bit (GCC, Clang):
```sh
mkdir build
cd build
CXX=g++ cmake -G "Unix Makefiles" ..
make
make install
```
64 bit (GCC, Clang):
```sh
mkdir build
cd build
CXX=g++ CXXFLAGS="-m64" cmake -G "Unix Makefiles" -DCMAKE_INSTALL_LIBDIR=/usr/local/lib/64 ..
make
make install
```
**Note**: Systems with gcc and clang can mix runtimes, leading to initialization errors due to incompatible ABIs. Typically, the userspace for such systems is gnu. To avoid such errors, explicitly specify the compiler before configuring and building.

## Using memlogger

### Prerequisites

Most modern OS require to permit libraries/path to be used with LD_PRELOAD. To run libmemlogger, make sure you configured access to installation directory for dynamic linker.

Some examples:

#### Solaris

Run (for 32 bit memlogger):
```sh
# crle -c /var/ld/ld.config -l /lib:/usr/lib:/usr/local/lib -s /lib/secure:/usr/lib/secure:/usr/lib:/usr/local/lib
```
and/or (for 64 bit memlogger):
```sh
# crle -64 -c /var/ld/64/ld.config -l /lib/64:/usr/lib/64:/usr/local/lib -s /lib/secure/64:/usr/lib/secure/64:/usr/local/lib
```
#### Linux

Run the command:
```sh
# echo "/usr/local/lib" > /etc/ld.so.conf.d/memlogger.conf
```
then run ldconfig as root or reboot your machine

or

add `/usr/local/lib` to `/etc/ld.so.conf`, then run ldconfig as root.

After the preparation is complete, you are ready to profile your application.

Since the easiest way to intercept memory allocation functions cross-platform is to use LD_PRELOAD, you must load the logger library before using (after building memlogger of the appropriate bit size):
```sh
# export LD_PRELOAD=libmemlogger.so
```
in POSIX-compatible shells, or
```sh
setenv LD_PRELOAD libmemlogger.so
```
in C-shell.

Logging session runs (for foreground processes) till Ctrl+C pressed, or till SIGTERM/SIGINT send to logged process.

After that, report will be output to STDOUT by default.

### High-resolution small-allocation statistics

For diagnostic runs, detailed statistics for small allocations can be enabled with:
```sh
# export MEMLOGGER_HIRES_SMALL_ALLOC=1
```

in POSIX-compatible shells, or
```sh
setenv MEMLOGGER_HIRES_SMALL_ALLOC 1
```
in C-shell.

The variable accepts `0` or `1`. The default value is `0`, so high-resolution statistics are disabled unless explicitly enabled.

When enabled, memlogger maintains a separate set of counters for allocation sizes from 4 to 64 KiB. The range is divided into the following buckets:
```text
4-8
9-16
17-32
33-64
65-128
129-256
257-512
513-1024
1025-2048
2049-4096
4097-8192
8193-16384
16385-32768
32769-65536
```
The high-resolution report is printed before the regular memory allocations report. For each supported allocation function it reports the total number of calls, average calls per second, and peak calls per second for every small-allocation bucket. The report includes `malloc`, `realloc`, `calloc` where supported, `free` where `malloc_usable_size` is available, and `reallocarray`. If a function has no calls, the report explicitly states that.

High-resolution statistics are intended for special diagnostic runs. They are maintained separately from the regular allocation statistics and are not updated when `MEMLOGGER_HIRES_SMALL_ALLOC=0`.

**Note**: Some platforms uses `LD_PRELOAD_32/LD_PRELOAD_64/LDR_PRELOAD/LDR_PRELOAD64` environment variables instead.

**Note**: To produce report to log file directly, just specify filename via environment variable before starting the profiled program:
```sh
# export MEMLOGGER_LOG_FILENAME=/tmp/memory.log
```
When permission denied or file cannot be created (or path does not exists),
following occurs (example):
```sh
Cannot open log file /1/memory3.log
```
Please note on some platform current directory can have no permission to write. Choose writable directory to save reports.

**Note**: If target file exists, it will be overwritten.

The result will be as follows:
```
Memory allocations report
===================================================
malloc up to 64k           : 2321
malloc from 64k to 128k    : 0
malloc from 128k to 256k   : 0
malloc from 256k to 512k   : 0
malloc from 512k to 1024k  : 0
malloc from 1024k to 2048k : 0
malloc from 2048k to 4096k : 0
malloc from 4096k to 8192k : 0
malloc >8192k              : 0
malloc max size            : 4k
---------------------------------------------------
Avg 12 malloc calls/sec
Peak 85 malloc calls/sec
---------------------------------------------------
realloc up to 64k           : 524
realloc from 64k to 128k    : 0
realloc from 128k to 256k   : 0
realloc from 256k to 512k   : 0
realloc from 512k to 1024k  : 0
realloc from 1024k to 2048k : 1
realloc from 2048k to 4096k : 0
realloc from 4096k to 8192k : 0
realloc >8192k              : 0
realloc max size            : 1536k
---------------------------------------------------
Avg 2 realloc calls/sec
Peak 381 realloc calls/sec
---------------------------------------------------
calloc up to 64k           : 11
calloc from 64k to 128k    : 0
calloc from 128k to 256k   : 0
calloc from 256k to 512k   : 0
calloc from 512k to 1024k  : 0
calloc from 1024k to 2048k : 0
calloc from 2048k to 4096k : 0
calloc from 4096k to 8192k : 0
calloc >8192k              : 0
calloc max size            : 4k
---------------------------------------------------
Avg 0 calloc calls/sec
Peak 8 calloc calls/sec
---------------------------------------------------
free up to 64k           : 2688
free from 64k to 128k    : 0
free from 128k to 256k   : 0
free from 256k to 512k   : 0
free from 512k to 1024k  : 0
free from 1024k to 2048k : 0
free from 2048k to 4096k : 1
free from 4096k to 8192k : 0
free >8192k              : 0
free max size            : 2052k
---------------------------------------------------
Avg 14 free calls/sec
Peak 78 free calls/sec
---------------------------------------------------
No reallocarray calls found
Elapsed time: 190 seconds (00:03:10)
```

where the numbers show the number of calls to the corresponding function with the requested size in the range of the corresponding bucket. `Avg` shows the average number of calls per second, `Peak` shows the maximum number of calls per second observed during the logging session, and `Elapsed time` shows the total logging time. `Max size` is the maximum requested allocation size observed for the corresponding function.
