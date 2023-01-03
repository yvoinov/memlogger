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

/* Memory functions names and values */
#define FUNC_1 "malloc"
#define FUNC_2 "realloc"
#define FUNC_3 "calloc"

/* Uses for decode array index to function name; malloc - 0, realloc - 1, calloc - 2 */
/* Done to avoid allocations during initialization to prevent cxa_guard_acquire deadlock */
#define FUNC_1_VALUE_1 0
#define FUNC_2_VALUE_2 1
#define FUNC_3_VALUE_3 2

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

template <typename T = uInt_t>
class MemoryLoggerFunctions {
	public:
		std::array<char, STATIC_ALLOC_BUFFER_SIZE> m_static_alloc_buffer;
		std::atomic<bool> m_innerMalloc { false }, m_innerCalloc { false };

		using voidPtr_t = void*;
		using func1_t = voidPtr_t (*)(T);		/* func1_t Type 1: malloc */
		using func2_t = voidPtr_t (*)(voidPtr_t, T);	/* func2_t Type 2: realloc */
		using func3_t = voidPtr_t (*)(T, T);		/* func3_t Type 3: calloc */
		func1_t m_Malloc;	/* Arg type 1 */
		func2_t m_Realloc;	/* Arg type 2 */
		func3_t m_Calloc;	/* Arg type 3 */

		void fillArrayEntry(const T p_idx, const T p_value);
		void computePeakAlloc();

		static MemoryLoggerFunctions& GetInstance() {
			static MemoryLoggerFunctions inst;
			return inst;
		}

		MemoryLoggerFunctions(MemoryLoggerFunctions &other) = delete;
		void operator=(const MemoryLoggerFunctions &) = delete;

		~MemoryLoggerFunctions() { printReportOnExit(); }
	private:
		class AdaptiveSpinMutex {
			public:
				AdaptiveSpinMutex(std::atomic<bool>& v_lock) : m_lock(v_lock) {};
				AdaptiveSpinMutex(const AdaptiveSpinMutex&) = delete;
				~AdaptiveSpinMutex() = default;

				void lock() noexcept {
					T v_spin_count { 0 };

					while (m_lock.load(std::memory_order_relaxed) || m_lock.exchange(true, std::memory_order_acquire)) {
						++v_spin_count;
						if (v_spin_count < m_spin_pred << 1) continue;	/* m_spin_pred << 1 is eq m_spin_pred * 2 */
						std::unique_lock<std::mutex> tlock(m_conditional_mutex);
						m_conditional_lock.wait_for(tlock, std::chrono::nanoseconds(1), [this]() { return !m_lock.load(std::memory_order_relaxed); });
					}

					m_spin_pred += (v_spin_count - m_spin_pred) >> 3;	/* x >> 3 is eq x / 8 */
				}

				void unlock() noexcept {
					m_lock.store(false, std::memory_order_release);
					m_conditional_lock.notify_one();
				}
			private:
				std::atomic<bool>& m_lock;
				std::atomic<T> m_spin_pred { 0 };
				std::mutex m_conditional_mutex;
				std::condition_variable m_conditional_lock;
		};

		MemoryLoggerFunctions() : m_fname(std::getenv("MEMLOGGER_LOG_FILENAME")) {
			std::signal(SIGINT, signal_handler);
			std::signal(SIGHUP, signal_handler);
			std::signal(SIGTERM, signal_handler);
			m_innerCalloc.store(true, std::memory_order_release);
			m_Malloc = reinterpret_cast<func1_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_1)));
			m_Realloc = reinterpret_cast<func2_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_2)));
			m_Calloc = reinterpret_cast<func3_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_3)));
			m_innerCalloc.store(false, std::memory_order_release);
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
			T allc_max;		/* Peak allocation size */
			T peak_allc_s;		/* Peak allocations per second */
			long start, stop;	/* Time interval in epoch */
			std::atomic<bool> lock;
		};

		std::array<Counters, ARRAY_SIZE> m_CounterArray;

		static constexpr T m_c_num_64K { 64 * KBYTES };
		static constexpr T m_c_num_128K { 128 * KBYTES };
		static constexpr T m_c_num_256K { 256 * KBYTES };
		static constexpr T m_c_num_512K { 512 * KBYTES };
		static constexpr T m_c_num_1024K { 1024 * KBYTES };
		static constexpr T m_c_num_2048K { 2048 * KBYTES };
		static constexpr T m_c_num_4096K { 4096 * KBYTES };
		static constexpr T m_c_num_8192K { 8192 * KBYTES };

		char* m_fname;

		std::size_t get_page_size();

		std::size_t roundup_to_page_size(const T p_size);

		long Now();

		void printReportOnExit()
		{
			if (!m_fname)
				printReportTotal();
			else {
				std::string v_OutputFile = std::string(m_fname);
				std::ofstream v_fd = std::ofstream(v_OutputFile, std::ios_base::trunc|std::ios_base::out);
				if (!v_fd.is_open()) {
					std::cerr << ERR_MSG_F + v_OutputFile << std::endl;
					return;
				}
				printReportTotal(v_fd);
				v_fd.close();
			}
		}

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
							if (m_conditional_lock.wait_for(tlock, std::chrono::seconds(TIMER_INTERVAL),
								[this]() { return !m_running.load(std::memory_order_acquire); }))
									MemoryLoggerFunctions<>::GetInstance().computePeakAlloc();
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
