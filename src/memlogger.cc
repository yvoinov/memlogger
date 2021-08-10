/**
 * Malloc calls simple logger
 */

#include "memlogger.h"

namespace {

/* Return current time in seconds since epoch */
inline long MemoryLoggerFunctions::Now()
{
	const std::chrono::system_clock::duration c_dtn = std::chrono::system_clock::now().time_since_epoch();
	return c_dtn.count() * std::chrono::system_clock::period::num / std::chrono::system_clock::period::den;
}

template <typename S, typename T>
void MemoryLoggerFunctions::protectedWrite(S p_function, T p_size)
{
	v_IOMalloc.store(true, std::memory_order_release);
	{
		AdaptiveSpinMutex spmux(m_lock);
		std::lock_guard<AdaptiveSpinMutex> lock(spmux);
		std::fprintf(stderr, "%s%s%lu%s%lu\n", p_function, DELIMITER, p_size, DELIMITER, Now());
		std::fflush(stderr);
	}
	v_IOMalloc.store(false, std::memory_order_release);
}

}	/* namespace */

extern "C" {

void *malloc(std::size_t size)
{
	if (!v_innerMalloc.load(std::memory_order_acquire) || !v_IOMalloc.load(std::memory_order_acquire))	/* Do not log own recursive or IO malloc calls */
		MemoryLoggerFunctions::GetInstance().protectedWrite(FUNC_1, size);
	if (v_innerMalloc.load(std::memory_order_acquire))
		v_innerMalloc.store(false, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Malloc(size);
}

void *realloc(void *ptr, std::size_t size)
{
	MemoryLoggerFunctions::GetInstance().protectedWrite(FUNC_2, size);
	v_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Realloc(ptr, size);
}

void *calloc(std::size_t n, std::size_t size)
{
	if (v_innerCalloc.load(std::memory_order_acquire))	/* Requires calloc hack to stop recursion during dlsym inner calloc call */
		return v_static_alloc_buffer.data();
	MemoryLoggerFunctions::GetInstance().protectedWrite(FUNC_3, n * size);
	v_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Calloc(n, size);
}

}// extern C
