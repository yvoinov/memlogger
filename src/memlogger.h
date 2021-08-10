#pragma once

#if !__cplusplus >= 201103L || !__cplusplus >= 199711L
  #error This program needs at least a C++11 compliant compiler
#endif

#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <array>
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

namespace {

static std::array<char, OUTPUT_BUFFER_SIZE> v_buffer;	/* Static buffer for output to avoid malloc */
static std::array<char, STATIC_ALLOC_BUFFER_SIZE> v_static_alloc_buffer;
static std::atomic<bool> v_innerMalloc { false }, v_innerCalloc { false }, v_IOMalloc { false };

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
		using voidPtr = void*;
		using func_t = voidPtr (*)(std::size_t);		/* func_t Type 1: malloc */
		using func2_t = voidPtr (*)(voidPtr, std::size_t);	/* func2_t Type 2: realloc */
		using func3_t = voidPtr (*)(std::size_t, std::size_t);	/* func3_t Type 3: calloc */
		func_t m_Malloc;	/* Arg type 1 */
		func2_t m_Realloc;	/* Arg type 2 */
		func3_t m_Calloc;	/* Arg type 3 */

		template <typename S, typename T>
		void protectedWrite(S p_function, T p_size);

		static MemoryLoggerFunctions& GetInstance() {
			static MemoryLoggerFunctions inst;
			return inst;
		}

		MemoryLoggerFunctions(MemoryLoggerFunctions &other) = delete;
		void operator=(const MemoryLoggerFunctions &) = delete;

	private:
		MemoryLoggerFunctions() : m_lock(m_output_lock) {
			v_innerCalloc.store(true, std::memory_order_release);
			m_Malloc = reinterpret_cast<func_t>(reinterpret_cast<uintptr_t>(dlsym(RTLD_NEXT, FUNC_1)));
			m_Realloc = reinterpret_cast<func2_t>(reinterpret_cast<uintptr_t>(dlsym(RTLD_NEXT, FUNC_2)));
			m_Calloc = reinterpret_cast<func3_t>(reinterpret_cast<uintptr_t>(dlsym(RTLD_NEXT, FUNC_3)));
			char* fname = std::getenv("MEMLOGGER_LOG_FILENAME");	/* Get logfile name from environment if specified */
			if (fname)
				if (!::freopen(fname, "w", stderr)) {		/* Redirect stderr to logfile */
					std::fprintf(stdout, "%s%s\n", "Cannot open log file ", fname);
					return;					/* Terminate execution; will segfault here */
				}
			v_innerCalloc.store(false, std::memory_order_release);
			std::setbuf(stderr, v_buffer.data());
		};

		std::atomic<bool>& m_lock;
		static std::atomic<bool> m_output_lock;

		long Now();
};

std::atomic<bool> MemoryLoggerFunctions::m_output_lock { false };	/* Avoid linking error 'Undefined first referenced symbol' */

}	/* namespace */
