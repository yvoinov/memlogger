#pragma once

#if !__cplusplus >= 201103L || !__cplusplus >= 199711L
  #error This program needs at least a C++11 compliant compiler
#endif

#include <climits>	/* For UINT_MAX */
#include <csignal>
#include <cstdlib>	/* For std::exit, std::getenv */
#include <cstdint>	/* For std::uint64_t */
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

using voidPtr_t = void*;
using uInt_t = std::size_t;
using uLongInt_t = std::uint64_t;	/* Accumulators type to prevent possible wrap around with long sessions */

std::array<char, STATIC_ALLOC_BUFFER_SIZE> g_static_alloc_buffer;
std::atomic<bool> g_innerMalloc { false }, g_innerCalloc { false };

template <typename P, typename T, typename L>
class MemoryLogger {
public:
	using func1_t = P (*)(T);	/* func1_t Type 1: malloc */
	using func2_t = P (*)(P, T);	/* func2_t Type 2: realloc */
	using func3_t = P (*)(T, T);	/* func3_t Type 3: calloc */
	func1_t m_Malloc;	/* Arg type 1 */
	func2_t m_Realloc;	/* Arg type 2 */
	func3_t m_Calloc;	/* Arg type 3 */

	char* m_fname;

	void computePeakValue();
	void printReport();

	P malloc_mf_impl(T size);
	P realloc_mf_impl(P ptr, T size);
	P calloc_mf_impl(T n, T size);

	static MemoryLogger& GetInstance() {
		static MemoryLogger inst;
		return inst;
	}

	MemoryLogger(MemoryLogger &other) = delete;
	void operator=(const MemoryLogger &) = delete;

	~MemoryLogger() { printReport(); }
private:
	MemoryLogger() : m_fname(std::getenv("MEMLOGGER_LOG_FILENAME")) {
		std::signal(SIGINT, signal_handler);
		std::signal(SIGHUP, signal_handler);
		std::signal(SIGTERM, signal_handler);
		g_innerCalloc.store(true, std::memory_order_release);
		m_Malloc = reinterpret_cast<func1_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, m_c_func1)));
		m_Realloc = reinterpret_cast<func2_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, m_c_func2)));
		m_Calloc = reinterpret_cast<func3_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, m_c_func3)));
		g_innerCalloc.store(false, std::memory_order_release);
	}

	class AdaptiveSpinMutex;

	/* Uses for decode array index to function name */
	enum Func_values {
		malloc_fvalue = 0,
		realloc_fvalue = 1,
		calloc_fvalue = 2
	};

	/* Memory functions names */
	static constexpr const char* m_c_func1 { "malloc" };
	static constexpr const char* m_c_func2 { "realloc" };
	static constexpr const char* m_c_func3 { "calloc" };

	/* Counters array size; for 3 functions */
	static constexpr T m_c_array_size = 3;

	using Counters = struct Counters {
		L allc_64k;
		L allc_128k;
		L allc_256k;
		L allc_512k;
		L allc_1024k;
		L allc_2048k;
		L allc_4096k;
		L allc_8192k;
		L allc_more;
		L allc_max;		/* Max allocation size */
		long start, stop;	/* Time interval in epoch */
		std::atomic<bool> lock;
	};

	std::array<Counters, m_c_array_size> m_CounterArray;
	std::array<L, m_c_array_size> m_PeakValueArray;	/* Peak allocations per second array */

	static constexpr const T m_c_num_64K { 64 * KBYTES };
	static constexpr const T m_c_num_128K { 128 * KBYTES };
	static constexpr const T m_c_num_256K { 256 * KBYTES };
	static constexpr const T m_c_num_512K { 512 * KBYTES };
	static constexpr const T m_c_num_1024K { 1024 * KBYTES };
	static constexpr const T m_c_num_2048K { 2048 * KBYTES };
	static constexpr const T m_c_num_4096K { 4096 * KBYTES };
	static constexpr const T m_c_num_8192K { 8192 * KBYTES };

	T get_page_size();
	L roundup_to_page_size(const T p_size);
	long Now();

	static void signal_handler(int signum)
	{
		if (signum == SIGINT || signum == SIGHUP || signum == SIGTERM) std::exit(EXIT_0);
	}

	L sumCounters(const T p_idx);
	void fillArrayEntry(const T p_idx, const T p_value);
	const char* decodeMemFunc(const T p_idx);
	void printReport(const T p_idx, std::ostream &p_stream = std::cout);
	long computeTotalLoggingTime();
	void printElapsedTime(std::ostream &p_stream = std::cout);
	void printReportTotal(std::ostream &p_stream = std::cout);
};

using memoryLogger_t = MemoryLogger<voidPtr_t, uInt_t, uLongInt_t>;

class OnLoadInit {
public:
	OnLoadInit() {
		memoryLogger_t& mli = memoryLogger_t::GetInstance();
		m_timer = std::thread([&]() { while (m_running.load(std::memory_order_relaxed)) {
						std::unique_lock<std::mutex> tlock(m_conditional_mutex);
						if (!m_conditional_lock.wait_for(tlock, std::chrono::seconds(TIMER_INTERVAL),
							[this]() { return !m_running.load(std::memory_order_acquire); })) {
								mli.computePeakValue();
								if (mli.m_fname)
									mli.printReport();
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
