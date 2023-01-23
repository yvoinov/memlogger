#pragma once

#if !__cplusplus >= 201103L || !__cplusplus >= 199711L
  #error This program needs at least a C++11 compliant compiler
#endif

#include <csignal>
#include <cstdlib>	/* For std::exit, std::getenv */
#include <chrono>
#include <array>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <algorithm>	/* For std::min_element, std::max_element */
#include <iostream>	/* For std::cout, std::ostream, std::ios */
#include <fstream>
#include <iomanip>	/* For std::setw, std::setfill */
#include <thread>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !HAVE_DLFCN_H
#error Require dlfcn.h to build
#else
#include <dlfcn.h>
#endif

#if !HAVE_UNISTD_H
#error Require unistd.h to build
#else
#include <unistd.h>
#endif

#define STATIC_ALLOC_BUFFER_SIZE 32

/* Counters array size; for 3 functions */
#define ARRAY_SIZE 3

/* Memory functions names */
#define FUNC_1 "malloc"
#define FUNC_2 "realloc"
#define FUNC_3 "calloc"

#define TIMER_INTERVAL 1

/* Report literals */
#define REPORT_HEADING "Memory allocations report"
#define SEPARATION_LINE_1 "==================================================="
#define ALLOC_64K   " up to 64k           : "
#define ALLOC_128K  " from 64k to 128k    : "
#define ALLOC_256K  " from 128k to 256k   : "
#define ALLOC_512K  " from 256k to 512k   : "
#define ALLOC_1024K " from 512k to 1024k  : "
#define ALLOC_2048K " from 1024k to 2048k : "
#define ALLOC_4096K " from 2048k to 4096k : "
#define ALLOC_8192K " from 4096k to 8192k : "
#define ALLOC_MORE  " >8192k              : "
#define ALLOC_MAX   " max size            : "
#define SEPARATION_LINE_2 "---------------------------------------------------"

/* Multiplier */
#define KBYTES 1024

/* Error messages */
#define ERR_MSG "ERROR: "
#define ERR_MSG_A ERR_MSG "Report array empty"
#define ERR_MSG_F ERR_MSG "Failed to open file "
#define ERR_MSG_NF "No other calls found"

/* Return codes */
#define EXIT_0 0	//Normal exit
#define EXIT_1 1	//Report array empty

namespace {

using uInt_t = std::size_t;

/* Uses for decode array index to function name; malloc - 0, realloc - 1, calloc - 2 */
enum Func_values { malloc_fvalue = 0, realloc_fvalue, calloc_fvalue };

std::array<char, STATIC_ALLOC_BUFFER_SIZE> g_static_alloc_buffer;
std::atomic<bool> g_innerMalloc { false }, g_innerCalloc { false };

template <typename T = uInt_t>
class MemoryLoggerFunctions {
	public:
		using voidPtr_t = void*;

		using func1_t = voidPtr_t (*)(T);		/* func1_t Type 1: malloc */
		using func2_t = voidPtr_t (*)(voidPtr_t, T);	/* func2_t Type 2: realloc */
		using func3_t = voidPtr_t (*)(T, T);		/* func3_t Type 3: calloc */
		func1_t m_Malloc;	/* Arg type 1 */
		func2_t m_Realloc;	/* Arg type 2 */
		func3_t m_Calloc;	/* Arg type 3 */

		void fillArrayEntry(const T p_idx, const T p_value);
		void computePeakValue();

		char* m_fname;

		void printReport();

		static MemoryLoggerFunctions& GetInstance() {
			static MemoryLoggerFunctions inst;
			return inst;
		}

		MemoryLoggerFunctions(MemoryLoggerFunctions &other) = delete;
		void operator=(const MemoryLoggerFunctions &) = delete;

		~MemoryLoggerFunctions() { printReport(); }
	private:
		class AdaptiveSpinMutex;

		MemoryLoggerFunctions() : m_fname(std::getenv("MEMLOGGER_LOG_FILENAME")) {
			std::signal(SIGINT, signal_handler);
			std::signal(SIGHUP, signal_handler);
			std::signal(SIGTERM, signal_handler);
			g_innerCalloc.store(true, std::memory_order_release);
			m_Malloc = reinterpret_cast<func1_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_1)));
			m_Realloc = reinterpret_cast<func2_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_2)));
			m_Calloc = reinterpret_cast<func3_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_3)));
			g_innerCalloc.store(false, std::memory_order_release);
		}

		using Counters = struct Counters {
			T allc_64k;
			T allc_128k;
			T allc_256k;
			T allc_512k;
			T allc_1024k;
			T allc_2048k;
			T allc_4096k;
			T allc_8192k;
			T allc_more;
			T allc_max;		/* Max allocation size */
			long start, stop;	/* Time interval in epoch */
			std::atomic<bool> lock;
		};

		std::array<Counters, ARRAY_SIZE> m_CounterArray;
		std::array<T, ARRAY_SIZE> m_PeakValueArray;	/* Peak allocations per second array */

		static constexpr T m_c_num_64K { 64 * KBYTES };
		static constexpr T m_c_num_128K { 128 * KBYTES };
		static constexpr T m_c_num_256K { 256 * KBYTES };
		static constexpr T m_c_num_512K { 512 * KBYTES };
		static constexpr T m_c_num_1024K { 1024 * KBYTES };
		static constexpr T m_c_num_2048K { 2048 * KBYTES };
		static constexpr T m_c_num_4096K { 4096 * KBYTES };
		static constexpr T m_c_num_8192K { 8192 * KBYTES };

		std::size_t get_page_size();
		std::size_t roundup_to_page_size(const T p_size);
		long Now();

		static void signal_handler(int signum)
		{
			if (signum == SIGINT || signum == SIGHUP || signum == SIGTERM) std::exit(EXIT_0);
		}

		std::size_t sumCounters(const T p_idx);
		std::string decodeMemFunc(const T p_idx);
		void printReport(const T p_idx, std::ostream &p_stream = std::cout);
		long computeTotalLoggingTime();
		void printReportTotal(std::ostream &p_stream = std::cout);
};

class OnLoadInit {
	public:
		OnLoadInit() {
			m_timer = std::thread([&]() { while (m_running.load(std::memory_order_relaxed)) {
							std::unique_lock<std::mutex> tlock(m_conditional_mutex);
							if (!m_conditional_lock.wait_for(tlock, std::chrono::seconds(TIMER_INTERVAL),
								[this]() { return !m_running.load(std::memory_order_acquire); })) {
									MemoryLoggerFunctions<>::GetInstance().computePeakValue();
									if (MemoryLoggerFunctions<>::GetInstance().m_fname)
										MemoryLoggerFunctions<>::GetInstance().printReport();
							}
						}
			});
		}
		~OnLoadInit() { m_running.store(false, std::memory_order_release);
				m_conditional_lock.notify_one();
				m_timer.join();
		}
	private:
		std::thread m_timer;
		std::atomic<bool> m_running { true };
		std::condition_variable m_conditional_lock;
		std::mutex m_conditional_mutex;
} onLoadInit;

}	/* namespace */
