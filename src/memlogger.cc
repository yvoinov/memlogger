/**
 * Malloc calls simple logger
 */

#include "memlogger.h"

static char v_buffer[OUTPUT_BUFFER_SIZE];	/* Static buffer for output to avoid malloc */
static char v_static_alloc_buffer[STATIC_ALLOC_BUFFER_SIZE];
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
		typedef void* (*func_t)(std::size_t size);		/* func_t Type 1: malloc */
		typedef void* (*func2_t)(void*, std::size_t);		/* func2_t Type 2: realloc */
		typedef void* (*func3_t)(std::size_t, std::size_t);	/* func3_t Type 3: calloc */
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
			m_Malloc = (func_t)dlsym(RTLD_NEXT, FUNC_1);
			m_Realloc = (func2_t)dlsym(RTLD_NEXT, FUNC_2);
			m_Calloc = (func3_t)dlsym(RTLD_NEXT, FUNC_3);
			v_innerCalloc.store(false, std::memory_order_release);
			std::setbuf(stderr, v_buffer);
		};

		std::atomic<bool>& m_lock;
		static std::atomic<bool> m_output_lock;

		long Now();
};

std::atomic<bool> MemoryLoggerFunctions::m_output_lock { false };	/* Avoid linking error 'Undefined first referenced symbol' */

/* Return current time in seconds since epoch */
inline long MemoryLoggerFunctions::Now()
{
	const std::chrono::system_clock::duration c_dtn = std::chrono::system_clock::now().time_since_epoch();
	return c_dtn.count() * std::chrono::system_clock::period::num / std::chrono::system_clock::period::den;
}

template <typename S, typename T>
void MemoryLoggerFunctions::protectedWrite(S p_function, T p_size)
{
	AdaptiveSpinMutex spmux(m_lock);
	v_IOMalloc.store(true, std::memory_order_release);
	{
		std::lock_guard<AdaptiveSpinMutex> lock(spmux);
		std::fprintf(stderr, "%s%s%lu%s%lu\n", p_function, DELIMITER, p_size, DELIMITER, Now());
		std::fflush(stderr);
	}
	v_IOMalloc.store(false, std::memory_order_release);
}

extern "C" {

void *malloc(std::size_t size)
{
	if (v_IOMalloc.load(std::memory_order_acquire))		/* IO malloc hack */
		return v_static_alloc_buffer;
	if (!v_innerMalloc.load(std::memory_order_acquire))
		MemoryLoggerFunctions::GetInstance().protectedWrite(FUNC_1, size);
	return MemoryLoggerFunctions::GetInstance().m_Malloc(size);
}

void *realloc(void *ptr, std::size_t size)
{
	v_innerMalloc.store(true, std::memory_order_release);
	MemoryLoggerFunctions::GetInstance().protectedWrite(FUNC_2, size);
	return v_innerMalloc.store(false, std::memory_order_release),
		MemoryLoggerFunctions::GetInstance().m_Realloc(ptr, size);
}

void *calloc(std::size_t n, std::size_t size)
{
	if (v_innerCalloc.load(std::memory_order_acquire))		/* Dirty hack to stop recursion with dlsym inner calloc call */
		return v_static_alloc_buffer;
	v_innerMalloc.store(true, std::memory_order_release);
	MemoryLoggerFunctions::GetInstance().protectedWrite(FUNC_3, n * size);
	return v_innerMalloc.store(false, std::memory_order_release),
		MemoryLoggerFunctions::GetInstance().m_Calloc(n, size);
}

}// extern C
