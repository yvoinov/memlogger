#pragma once

#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <atomic>
#include <condition_variable>
#include <mutex>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !HAVE_DLFCN_H
#error Require dlfcn.h to build
#else
#include <dlfcn.h>
#endif

#define OUTPUT_BUFFER_SIZE 4096
#define STATIC_ALLOC_BUFFER_SIZE 32

/* Memory functions names */
#define FUNC_1 "malloc"
#define FUNC_2 "realloc"
#define FUNC_3 "calloc"

/* Fields delimiter */
#define DELIMITER ":"
