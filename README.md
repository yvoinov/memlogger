# Memlogger
[![CodeQL](https://github.com/yvoinov/memlogger/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/yvoinov/memlogger/actions/workflows/codeql-analysis.yml) [![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://github.com/yvoinov/memlogger/blob/main/LICENSE)
## Concepts

Unlike most similar solutions, memlogger is designed to profile the application by the nature of memory allocations in accordance with the size of the chunks.

Accordingly, only functions that directly allocate memory are logged.

Memlogger consists of two components: a very simple logging library preloaded with a dynamic loader, and a log processor.

Log processing is performed in one pass. Each entry contains the name of the allocation function and the size of the requested memory in bytes. The log processor counts the number of allocation requests of each type, in accordance with the entry into the given bucket size - i.e. 0-64 kb, 64-128 kb, 128-256 kb, and so on.

The resulting report is a simple table, grouped by allocation function, with call counter values for each bucket.

This data allows you to get an idea of the memory allocation profile for the application and can be used to select the optimal parameters for the external memory allocator to achieve maximum performance.

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

Installation prefix by default is /usr/local. Logging library `libmemlogger.so` will install into `$PREFIX/lib`; log processor, memlogger-report, will install into `$PREFIX/bin`.

Configuration options:
`--enable-static-libs` - This options configure memlogger-report statically. Useful on systems with different and incompatible libstdc++ runtimes.

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

Note: Please keep in mind that logging is carried out in STDERR (due to technical limitations of writing to a file inside the logger library itself), and, accordingly, you need to redirect the STDERR output to a file to save the raw log on disk.

To  write  allocations to the log, you need to start your application as follows (interactively or similarly as a service):

```sh
# your_program_name 2>memory.log
```

Then allow your program or application to run for a while to accumulate relevant data.

Note: The log is saved in the current directory by default.

Also you can use logger this manner to preload, start and redirect log to file:

```sh
# LD_PRELOAD=libmemlogger.so your_program_name 2>memory.log
```

Note: Some platforms uses `LD_PRELOAD_32/LD_PRELOAD_64/LDR_PRELOAD/LDR_PRELOAD64` environment variables instead.

Note: Please keep in mind that logging is carried out in STDERR by default. To log allocations to log file directly, just specify filename via environment variable before starting the profiled program:

```sh
# export MEMLOGGER_LOG_FILENAME=/tmp/memory.log
```

When permission denied or file cannot be created (or path does not exists), following occurs:

```
Cannot open log file /1/memory3.log
Segmentation Fault (core dumped)
```

Raw log contains the follows:
```
malloc:72704:1607278434
malloc:160:1607278434
malloc:160:1607278434
malloc:2:1607278434
malloc:40:1607278434
malloc:7:1607278434
malloc:3:1607278434
malloc:40:1607278434
malloc:5:1607278434
malloc:3:1607278434
malloc:40:1607278434
malloc:5:1607278434
malloc:6:1607278434
...
```
where first number is the size of the allocation, the second is epoch timestamp.

Once you have finished accumulating raw data, you are ready to process it.

First of all, unset LD_PRELOAD, if exported.

To process the data, run the log processor as follows:

```sh
# memlogger-report -lmemory.log
```

Option -l specifies source raw log.

Log processor by default will output result to STDOUT. To save result to the file, use -f option:

```sh
# memlogger-report -lmemory.log -fmemory_alloc_report.txt
```

Note: If target file exists, it will be overwritten.

The result will be as follows:
```
# memlogger-report -lmemory.log
malloc up to 64k           : 14501901
malloc from 64k to 128k    : 75
malloc from 128k to 256k   : 659
malloc from 256k to 512k   : 75
malloc from 512k to 1024k  : 6
malloc from 1024k to 2048k : 6
malloc from 2048k to 4096k : 111
malloc from 4096k to 8192k : 37
malloc >8192k              : 67
malloc max size            : 240836k
---------------------------------------------------
183581 malloc calls/sec
---------------------------------------------------
No other calls found
Elapsed time: 79 sec
...
```
where the numbers show the number of calls to the corresponding function with the size of the sice in the range of the corresponding bucket. "Elapsed time" shows total logging time.

## Log processor arguments

Log processor command line arguments are:
```sh
-l<full log file name> - set log file. Default ./memory.log
-f<full output file name> - set output file. Default ./memory_alloc_report.log
-v - show version and exit
-h|-? - show this help and exit
```
Option -l should always be specified.

Note: Option -f can contain no filename; when specified without it uses default for result saving.
