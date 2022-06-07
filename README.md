# Memlogger
[![CodeQL](https://github.com/yvoinov/memlogger/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/yvoinov/memlogger/actions/workflows/codeql-analysis.yml) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://github.com/yvoinov/memlogger/blob/main/LICENSE)
## Concepts

Unlike most similar solutions, memlogger is designed to profile the application by the nature of memory allocations in accordance with the size of the chunks.

Accordingly, only functions that directly allocate memory are logged.

Memlogger now implemented as only shared library. It produces instant report immediately after logging completion with O(1) complexity. No more log processor required.

Log processing is now performed directly in library. Library contains global shared array. Each entry contains the name of the allocation function, size of the requested memory in bytes, start/stop epoch timestamp. The report, produces by library, contains the number of allocation requests of each type, in accordance with the entry into the given bucket size - i.e. 0-64 kb, 64-128 kb, 128-256  kb, and so on. Also it contains average allocation calls per second and logging session elapsed time.

This data allows you to get an idea of the memory allocation profile for the application and can be used to select the optimal parameters for the external memory allocator to achieve maximum performance.

Generally speaking, such statistics helps you define appropriate chunk size for chunk-based allocator in accordance with best-fit strategy.

## Build and installation

### Build memlogger

To make and install memlogger run:
```sh
# ./configure 'CXXFLAGS=-m64'
```
or
```sh
# ./configure 'CXXFLAGS=-m32'
```
then
```sh
# make && make install-strip
```

Installation prefix by default is /usr/local. Logging library `libmemlogger.so` will install into `$PREFIX/lib`.

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

Since  the  easiest  way to intercept memory allocation functions cross-platform is to use LD_PRELOAD, you must load the logger library before using (after building memlogger of the appropriate bit size):

```sh
# export LD_PRELOAD=libmemlogger.so
```

Logging  session  runs  (for  foreground processes) till Ctrl+C pressed, or till SIGTERM/SIGINT send to logged process.

After that, report will be output to STDOUT by default.

Note: Some platforms uses `LD_PRELOAD_32/LD_PRELOAD_64/LDR_PRELOAD/LDR_PRELOAD64` environment variables instead.

Note:  To  produce  report  to  log  file  directly,  just  specify filename via environment variable before starting the profiled program:

```sh
# export MEMLOGGER_LOG_FILENAME=/tmp/memory.log
```

When  permission  denied  or  file  cannot be created (or path does not exists),
following occurs (example):

```sh
Cannot open log file /1/memory3.log
```

Please note on some platform current directory can have no permission to write. Choose writable directory to save reports.

Note: If target file exists, it will be overwritten.

The result will be as follows:

```
Memory allocations report
===================================================
malloc up to 64k           : 43199
malloc from 64k to 128k    : 1
malloc from 128k to 256k   : 0
malloc from 256k to 512k   : 0
malloc from 512k to 1024k  : 0
malloc from 1024k to 2048k : 0
malloc from 2048k to 4096k : 0
malloc from 4096k to 8192k : 0
malloc >8192k              : 0
malloc max size            : 71k
---------------------------------------------------
960 malloc calls/sec
---------------------------------------------------
realloc up to 64k           : 6
realloc from 64k to 128k    : 0
realloc from 128k to 256k   : 0
realloc from 256k to 512k   : 0
realloc from 512k to 1024k  : 0
realloc from 1024k to 2048k : 0
realloc from 2048k to 4096k : 0
realloc from 4096k to 8192k : 0
realloc >8192k              : 0
realloc max size            : 1k
---------------------------------------------------
6 realloc calls/sec
---------------------------------------------------
calloc up to 64k           : 1047
calloc from 64k to 128k    : 0
calloc from 128k to 256k   : 1
calloc from 256k to 512k   : 0
calloc from 512k to 1024k  : 0
calloc from 1024k to 2048k : 0
calloc from 2048k to 4096k : 0
calloc from 4096k to 8192k : 0
calloc >8192k              : 0
calloc max size            : 182k
---------------------------------------------------
1048 calloc calls/sec
---------------------------------------------------
Elapsed time: 45 sec
```

where the numbers show the number of calls to the corresponding function with the size in the range of the corresponding bucket. "Elapsed time" shows total logging time.
