#pragma once

#if !__cplusplus >= 201103L || !__cplusplus >= 199711L
#	error This program needs at least a C++11 compliant compiler
#endif

#ifdef HAVE_CONFIG_H
#	include "autoconf.h"
#endif

#include <climits>	/* For UINT_MAX */
#include <csignal>
#include <cstdlib>	/* For std::exit, std::getenv */
#include <cstdint>	/* For std::uint64_t */
#include <ctime>	/* For std::time_t */
#include <chrono>
#include <array>
#include <atomic>
#include <mutex>
#include <string>
#include <ostream>
#include <iostream>	/* For std::cout, std::ostream, std::ios */
#include <fstream>
#include <iomanip>	/* For std::setw, std::setfill */
#include <thread>
#include <functional>	/* For std::function */
#if !defined(__FreeBSD__)
#	include <condition_variable>
#endif
#ifdef HAVE_MALLOC_USABLE_SIZE
#	include <malloc.h>
#endif

#ifndef _GNU_SOURCE
#	define _GNU_SOURCE
#endif

#if !HAVE_DLFCN_H
#	error Require dlfcn.h to build
#else
#	include <dlfcn.h>
#endif

#if !HAVE_UNISTD_H
#	error Require unistd.h to build
#else
#	include <unistd.h>
#endif

#ifdef __linux__
#	include <linux/version.h>
#	if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#	define COMPAT_OS
#	endif
#else
#	define COMPAT_OS
#endif

#ifdef COMPAT_OS
#	if !HAVE_SYS_MMAN_H
#		error Require sys/mman.h to build
#	else
#		include <sys/mman.h>
#	endif
#endif

/* Timer interval in seconds */
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
#define ERR_MSG_NF1 "No "
#define ERR_MSG_NF2 " calls found"

/* Return codes */
#define EXIT_0 0	//Normal exit
#define EXIT_1 1	//Report array empty

#if __cpp_lib_atomic_flag_test >= 201907L
#	define MEMLOGGER_FLAG_TYPE std::atomic_flag
#	define MEMLOGGER_FLAG_DEFAULT
#else // On sparc integer flag type runs much faster; bool is implicitly converted to int (allowed by the standard)
#	define MEMLOGGER_FLAG_TYPE std::atomic<int>
#	define MEMLOGGER_FLAG_DEFAULT false
#endif

#define MEMLOGGER_MEM_RELAXED std::memory_order_relaxed
#define MEMLOGGER_MEM_ACQUIRE std::memory_order_acquire
#define MEMLOGGER_MEM_RELEASE std::memory_order_release

#if __cpp_lib_atomic_flag_test >= 201907L
#	define MEMLOGGER_RELAXED_LOAD(x) x.test(MEMLOGGER_MEM_RELAXED)
#	define MEMLOGGER_ACQUIRE_LOAD(x) x.test(MEMLOGGER_MEM_ACQUIRE)
#	define MEMLOGGER_RELEASE_STORE(x) x.test_and_set(MEMLOGGER_MEM_RELEASE)
#	define MEMLOGGER_ACQUIRE_CAS(x) x.test_and_set(MEMLOGGER_MEM_ACQUIRE)
#	define MEMLOGGER_RELEASE(x) x.clear(MEMLOGGER_MEM_RELEASE)
#else
#	define MEMLOGGER_RELAXED_LOAD(x) x.load(MEMLOGGER_MEM_RELAXED)
#	define MEMLOGGER_ACQUIRE_LOAD(x) x.load(MEMLOGGER_MEM_ACQUIRE)
#	define MEMLOGGER_RELEASE_STORE(x) x.store(true, MEMLOGGER_MEM_RELEASE)
#	define MEMLOGGER_ACQUIRE_CAS(x) x.exchange(true, MEMLOGGER_MEM_ACQUIRE)
#	define MEMLOGGER_RELEASE(x) x.store(false, MEMLOGGER_MEM_RELEASE)
#endif

namespace {

using voidPtr_t = void*;
using uInt_t = std::size_t;
using uLongInt_t = std::uint64_t;	/* Accumulators type to prevent possible wrap around with long sessions */
using flag_t = MEMLOGGER_FLAG_TYPE;

template <typename Fl>
class InnerMallocFlag {
public:
	InnerMallocFlag() { MEMLOGGER_RELEASE_STORE(m_innerMalloc); }
	~InnerMallocFlag() { MEMLOGGER_RELEASE(m_innerMalloc); }
protected:
	bool get_flag()
	{
		if (MEMLOGGER_ACQUIRE_LOAD(m_innerMalloc)) return true;
		else return false;
	}

	void set_flag_on()
	{
		MEMLOGGER_RELEASE_STORE(m_innerMalloc);
	}

	void set_flag_off()
	{
		MEMLOGGER_RELEASE(m_innerMalloc);
	}
private:
	Fl m_innerMalloc;
};

using innerMallocFlag_t = InnerMallocFlag<flag_t>;

template <typename P, typename T, typename L, typename Fl>
class MemoryLogger : protected innerMallocFlag_t {
public:
	using func1_t = P (*)(T);	/* func1_t Type 1: malloc */
	using func2_t = P (*)(P, T);	/* func2_t Type 2: realloc */
	#ifdef COMPAT_OS
	using func3_t = P (*)(T, T);	/* func3_t Type 3: calloc */
	#endif
	#ifdef HAVE_MALLOC_USABLE_SIZE
	using func4_t = void (*)(P);	/* func4_t Type 2: free */
	#endif

	func1_t m_Malloc;	/* Arg type 1 */
	func2_t m_Realloc;	/* Arg type 2 */
	#ifdef COMPAT_OS
	func3_t m_Calloc;	/* Arg type 3 */
	#endif
	#ifdef HAVE_MALLOC_USABLE_SIZE
	func4_t m_Free;		/* Arg type 4 */
	#endif

	char* m_fname;

	void computePeakValue();
	void printReport();

	P malloc_mf_impl(T size);
	P realloc_mf_impl(P ptr, T size);
	#ifdef COMPAT_OS
	P calloc_mf_impl(T n, T size);
	#endif
	#ifdef HAVE_MALLOC_USABLE_SIZE
	void free_mf_impl(P ptr);
	#endif

	static MemoryLogger& GetInstance() {
		static MemoryLogger inst;
		return inst;
	}

	~MemoryLogger() { printReport(); }
private:
	MemoryLogger() : m_fname(std::getenv("MEMLOGGER_LOG_FILENAME")), m_elapsed_start(Now()) {
		std::signal(SIGINT, signal_handler);
		std::signal(SIGHUP, signal_handler);
		std::signal(SIGTERM, signal_handler);
		m_Malloc = reinterpret_cast<func1_t>(dlsym(RTLD_NEXT, m_c_func1));
		m_Realloc = reinterpret_cast<func2_t>(dlsym(RTLD_NEXT, m_c_func2));
		#ifdef COMPAT_OS
		m_Calloc = reinterpret_cast<func3_t>(dlsym(RTLD_NEXT, m_c_func3));
		#endif
		#ifdef HAVE_MALLOC_USABLE_SIZE
		m_Free = reinterpret_cast<func4_t>(dlsym(RTLD_NEXT, m_c_func4));
		#endif
	}

	MemoryLogger(const MemoryLogger&) = delete;
	MemoryLogger(MemoryLogger&&) noexcept = delete;
	MemoryLogger& operator=(const MemoryLogger&) = delete;
	MemoryLogger& operator=(MemoryLogger&&) noexcept = delete;

	class AdaptiveSpinMutex;

	/* Uses for decode array index to function name */
	enum class Func_values : T {
		malloc_fvalue,
		realloc_fvalue
		#ifdef COMPAT_OS
		,calloc_fvalue
		#endif
		#ifdef HAVE_MALLOC_USABLE_SIZE
		,free_fvalue
		#endif
	};

	/* Memory functions names */
	static constexpr const char* m_c_func1 { "malloc" };
	static constexpr const char* m_c_func2 { "realloc" };
	#ifdef COMPAT_OS
	static constexpr const char* m_c_func3 { "calloc" };
	#endif
	#ifdef HAVE_MALLOC_USABLE_SIZE
	static constexpr const char* m_c_func4 { "free" };
	#endif

	/* Counters array size; for 3 functions */
	#if defined(COMPAT_OS) && HAVE_MALLOC_USABLE_SIZE
	static constexpr T m_c_array_size = 4;
	#elif !defined(COMPAT_OS) || !HAVE_MALLOC_USABLE_SIZE
	static constexpr T m_c_array_size = 3;
	#endif

	using Counters = struct Counters {
		L allc_64k {};
		L allc_128k {};
		L allc_256k {};
		L allc_512k {};
		L allc_1024k {};
		L allc_2048k {};
		L allc_4096k {};
		L allc_8192k {};
		L allc_more {};
		L allc_max {};					/* Max allocation size */
		std::time_t start {}, stop {};			/* Time interval */
		Fl lock { MEMLOGGER_FLAG_DEFAULT };

		Counters& operator=(const Counters& other) {	/* Will use custom copy assignment overload */
			if (this != &other) {
				allc_64k = other.allc_64k;
				allc_128k = other.allc_128k;
				allc_256k = other.allc_256k;
				allc_512k = other.allc_512k;
				allc_1024k = other.allc_1024k;
				allc_2048k = other.allc_2048k;
				allc_4096k = other.allc_4096k;
				allc_8192k = other.allc_8192k;
				allc_more = other.allc_more;
				allc_max = other.allc_max;
				start = other.start;
				stop = other.stop;
			}
			return *this;
		}
	};

	std::array<Counters, m_c_array_size> m_CounterArray;

	using Summary = struct Summary {
		L previous {};
		L peak {};
	};

	std::array<Summary, m_c_array_size> m_PeakValueArray;	/* Peak allocations per second array */

	static constexpr const T m_c_num_64K { 64 * KBYTES };
	static constexpr const T m_c_num_128K { 128 * KBYTES };
	static constexpr const T m_c_num_256K { 256 * KBYTES };
	static constexpr const T m_c_num_512K { 512 * KBYTES };
	static constexpr const T m_c_num_1024K { 1024 * KBYTES };
	static constexpr const T m_c_num_2048K { 2048 * KBYTES };
	static constexpr const T m_c_num_4096K { 4096 * KBYTES };
	static constexpr const T m_c_num_8192K { 8192 * KBYTES };

	std::time_t m_elapsed_start;	/* Elapsed time start value */

	#ifdef COMPAT_OS
	P malloc_internal(T p_size)
	{
		return reinterpret_cast<P>((reinterpret_cast<std::uintptr_t>(mmap(nullptr, p_size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)) + 1) & ~1);
	}
	#endif

	T get_page_size();
	L roundup_to_page_size(const T p_size);
	std::time_t Now();

	static void signal_handler(int signum)
	{
		if (signum == SIGINT || signum == SIGHUP || signum == SIGTERM) std::exit(EXIT_0);
	}

	L sumCounters(const T p_idx);
	void fillArrayEntry(const T p_idx, const T p_value);
	const char* decodeMemFunc(const T p_idx);
	void printReport(const T p_idx, std::ostream& p_stream = std::cout);
	void printElapsedTime(std::ostream& p_stream = std::cout);
	void printReportTotal(std::ostream& p_stream = std::cout);
};

using memoryLogger_t = MemoryLogger<voidPtr_t, uInt_t, uLongInt_t, flag_t>;

/* Timer class with on-load init */
/* Intended to run a given block (lambda) on a periodic basis at a given interval */
template <typename T, typename Fn>
class Timer {
public:
	Timer(T p_interval, Fn p_exec) : m_interval(p_interval), m_exec(p_exec), m_running(true) {
		std::thread([this]() { while (m_running) {
					std::this_thread::sleep_for(std::chrono::seconds(m_interval));
					m_exec();
				}
		}).detach();
	}
	~Timer() { m_running = false; }
private:
	T m_interval;
	Fn m_exec;
	bool m_running;
};

Timer<uInt_t, std::function<void()>> timer(TIMER_INTERVAL,
						[]() {  memoryLogger_t& mli = memoryLogger_t::GetInstance();
							mli.computePeakValue();
							if (mli.m_fname)
								mli.printReport();
						});

}	/* namespace */
