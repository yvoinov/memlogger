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
#include <iostream>	/* For std::cin, std::cout, std::ostream, std::ios, std::flush */
#include <fstream>
#include <ostream>	/* For std::ostream */

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

#define FUNC_1_VALUE_1 1
#define FUNC_2_VALUE_2 2
#define FUNC_3_VALUE_3 3

#define FUNC_1_ARR_IDX_1 (FUNC_1_VALUE_1 - 1)
#define FUNC_2_ARR_IDX_2 (FUNC_2_VALUE_2 - 1)
#define FUNC_3_ARR_IDX_3 (FUNC_3_VALUE_3 - 1)

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

class AdaptiveSpinMutex {
public:
	AdaptiveSpinMutex(std::atomic<bool>& v_lock) : m_lock(v_lock) {};
	AdaptiveSpinMutex(const AdaptiveSpinMutex&) = delete;
	~AdaptiveSpinMutex() = default;

	void lock() noexcept {
		std::size_t v_spin_count { 0 };

		while (m_lock.load(std::memory_order_relaxed) || m_lock.exchange(true, std::memory_order_acquire)) {
			++v_spin_count;
			if (v_spin_count < m_spin_pred * 2) continue;
			std::unique_lock<std::mutex> tlock(m_conditional_mutex);
			m_conditional_lock.wait_for(tlock, std::chrono::nanoseconds(1), [] { return false; });
		}

		m_spin_pred += (v_spin_count - m_spin_pred) / 8;
	}

	void unlock() noexcept {
		m_lock.store(false, std::memory_order_release);
	}

private:
	std::atomic<bool>& m_lock;
	std::atomic<std::size_t> m_spin_pred { 0 };
	std::mutex m_conditional_mutex;
	std::condition_variable m_conditional_lock;
};

class MemoryLoggerFunctions {
	public:
		std::array<char, STATIC_ALLOC_BUFFER_SIZE> m_static_alloc_buffer;
		std::atomic<bool> m_innerMalloc { false }, m_innerCalloc { false };

		using voidPtr = void*;
		using func_t = voidPtr (*)(std::size_t);		/* func_t Type 1: malloc */
		using func2_t = voidPtr (*)(voidPtr, std::size_t);	/* func2_t Type 2: realloc */
		using func3_t = voidPtr (*)(std::size_t, std::size_t);	/* func3_t Type 3: calloc */
		func_t m_Malloc;	/* Arg type 1 */
		func2_t m_Realloc;	/* Arg type 2 */
		func3_t m_Calloc;	/* Arg type 3 */

		void fillArrayEntry(const std::size_t p_idx, const std::size_t p_value);

		static MemoryLoggerFunctions& GetInstance() {
			static MemoryLoggerFunctions inst;
			return inst;
		}

		MemoryLoggerFunctions(MemoryLoggerFunctions &other) = delete;
		void operator=(const MemoryLoggerFunctions &) = delete;

		~MemoryLoggerFunctions() { printReportOnExit(); }
	private:
		MemoryLoggerFunctions() : m_fname(std::getenv("MEMLOGGER_LOG_FILENAME")) {
			std::signal(SIGINT, signal_handler);
			std::signal(SIGHUP, signal_handler);
			std::signal(SIGTERM, signal_handler);
			m_innerCalloc.store(true, std::memory_order_release);
			m_Malloc = reinterpret_cast<func_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_1)));
			m_Realloc = reinterpret_cast<func2_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_2)));
			m_Calloc = reinterpret_cast<func3_t>(reinterpret_cast<std::uintptr_t>(dlsym(RTLD_NEXT, FUNC_3)));
			m_innerCalloc.store(false, std::memory_order_release);
		};

		using Counters = struct Counters {
			std::size_t memory_function;
			std::size_t allc_64k;
			std::size_t allc_128k;
			std::size_t allc_256k;
			std::size_t allc_512k;
			std::size_t allc_1024k;
			std::size_t allc_2048k;
			std::size_t allc_4096k;
			std::size_t allc_8192k;
			std::size_t allc_more;
			std::size_t allc_max;	/* Peak allocation size */
			long start, stop;	/* Time interval in epoch */
			std::atomic<bool> lock;
		};

		std::array<Counters, ARRAY_SIZE> m_CounterArray;

		static constexpr std::size_t m_c_num_64K { 64 * KBYTES };
		static constexpr std::size_t m_c_num_128K { 128 * KBYTES };
		static constexpr std::size_t m_c_num_256K { 256 * KBYTES };
		static constexpr std::size_t m_c_num_512K { 512 * KBYTES };
		static constexpr std::size_t m_c_num_1024K { 1024 * KBYTES };
		static constexpr std::size_t m_c_num_2048K { 2048 * KBYTES };
		static constexpr std::size_t m_c_num_4096K { 4096 * KBYTES };
		static constexpr std::size_t m_c_num_8192K { 8192 * KBYTES };

		char* m_fname;

		std::size_t& get_page_size();

		std::size_t roundup_to_page_size(const std::size_t p_size);

		long Now();

		void printReportOnExit()
		{
			if (!m_fname) {
				printReportTotal();
			} else {
				m_innerMalloc.store(true, std::memory_order_release);
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

		std::size_t sumCounters(const std::size_t p_idx);
		std::string decodeMemFunc(const std::size_t p_idx);
		void printReport(const std::size_t p_idx, std::ostream &p_stream = std::cout);
		long computeTotalLoggingTime();
		void printReportTotal(std::ostream &p_stream = std::cout);
};

}	/* namespace */
