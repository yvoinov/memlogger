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

void MemoryLoggerFunctions::fillArrayEntry(const std::size_t p_idx, const std::size_t p_value, const long p_timestamp)
{
	AdaptiveSpinMutex spmux(m_CounterArray[p_idx - 1].lock);
	std::lock_guard<AdaptiveSpinMutex> lock(spmux);         /* Take row-level spinlock here */

	if (m_CounterArray[p_idx - 1].memory_function == 0)	/* Write function if not yet */
		m_CounterArray[p_idx - 1].memory_function = p_idx;

	if (m_CounterArray[p_idx - 1].start == 0)		/* Save timestamp; let's inline it */
		m_CounterArray[p_idx - 1].start = p_timestamp;
	else if (m_CounterArray[p_idx - 1].stop == 0 || m_CounterArray[p_idx - 1].stop < p_timestamp)
		m_CounterArray[p_idx - 1].stop = p_timestamp;

	if (p_value > 0 && p_value <= m_c_num_64K)
		++m_CounterArray[p_idx - 1].allc_64k;
	else if (p_value > m_c_num_64K && p_value <= m_c_num_128K)
		++m_CounterArray[p_idx - 1].allc_128k;
	else if (p_value > m_c_num_128K && p_value <= m_c_num_256K)
		++m_CounterArray[p_idx - 1].allc_256k;
	else if (p_value > m_c_num_256K && p_value <= m_c_num_512K)
		++m_CounterArray[p_idx - 1].allc_512k;
	else if (p_value > m_c_num_512K && p_value <= m_c_num_1024K)
		++m_CounterArray[p_idx - 1].allc_1024k;
	else if (p_value > m_c_num_1024K && p_value <= m_c_num_2048K)
		++m_CounterArray[p_idx - 1].allc_2048k;
	else if (p_value > m_c_num_2048K && p_value <= m_c_num_4096K)
		++m_CounterArray[p_idx - 1].allc_4096k;
	else if (p_value > m_c_num_4096K && p_value <= m_c_num_8192K)
		++m_CounterArray[p_idx - 1].allc_8192k;
	else if (p_value > m_c_num_8192K) {
		++m_CounterArray[p_idx - 1].allc_more;
	}
	if (p_value > m_CounterArray[p_idx - 1].allc_max)
		m_CounterArray[p_idx - 1].allc_max = p_value;
}

std::size_t MemoryLoggerFunctions::sumCounters(const std::size_t p_idx)
{
	std::size_t v_sum = 0;
	v_sum += m_CounterArray[p_idx].allc_64k;
	v_sum += m_CounterArray[p_idx].allc_128k;
	v_sum += m_CounterArray[p_idx].allc_256k;
	v_sum += m_CounterArray[p_idx].allc_512k;
	v_sum += m_CounterArray[p_idx].allc_1024k;
	v_sum += m_CounterArray[p_idx].allc_2048k;
	v_sum += m_CounterArray[p_idx].allc_4096k;
	v_sum += m_CounterArray[p_idx].allc_8192k;
	v_sum += m_CounterArray[p_idx].allc_more;
	return v_sum;
}

std::string MemoryLoggerFunctions::decodeMemFunc(const std::size_t p_idx)
{
	switch (p_idx) {
		case 0:
			return std::string(FUNC_1);
			break;
		case 1:
			return std::string(FUNC_2);
			break;
		case 2:
			return std::string(FUNC_3);
			break;
		default:
			return std::string("");
			break;
	}
}

void MemoryLoggerFunctions::printReport(const std::size_t p_idx, std::ostream &p_stream)
{
	p_stream << decodeMemFunc(p_idx) << ALLOC_64K << m_CounterArray[p_idx].allc_64k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_128K << m_CounterArray[p_idx].allc_128k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_256K << m_CounterArray[p_idx].allc_256k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_512K << m_CounterArray[p_idx].allc_512k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_1024K << m_CounterArray[p_idx].allc_1024k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_2048K << m_CounterArray[p_idx].allc_2048k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_4096K << m_CounterArray[p_idx].allc_4096k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_8192K << m_CounterArray[p_idx].allc_8192k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_MORE << m_CounterArray[p_idx].allc_more << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_MAX << m_CounterArray[p_idx].allc_max / KBYTES << "k" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
	const std::ptrdiff_t c_time_diff = m_CounterArray[p_idx].stop - m_CounterArray[p_idx].start;
	if (c_time_diff != 0 && sumCounters(p_idx) != 0)
		p_stream << sumCounters(p_idx) / c_time_diff << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	else if (c_time_diff == 0 && sumCounters(p_idx) != 0)	/* If allocations fit one epoch tick */
		p_stream << sumCounters(p_idx) << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	else
		p_stream << "0 " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
}

long MemoryLoggerFunctions::computeTotalLoggingTime()
{
	return *std::max_element(&m_CounterArray[0].stop, &m_CounterArray[0].stop + (m_CounterArray.size() - 1)) -
		*std::min_element(&m_CounterArray[0].start, &m_CounterArray[0].start + (m_CounterArray.size() - 1));
}

void MemoryLoggerFunctions::printReportTotal(std::ostream &p_stream)
{
	p_stream << REPORT_HEADING << std::endl;
	p_stream << SEPARATION_LINE_1 << std::endl;
	if (m_CounterArray.size() > 0) {
		for (std::size_t i = 0; i < m_CounterArray.size(); ++i) {
			if (!(m_CounterArray[i].memory_function == 0))
				printReport(i, p_stream);
			else p_stream << ERR_MSG_NF << std::endl;
		}
		p_stream << "Elapsed time: " << computeTotalLoggingTime() << " sec" << std::endl;
	} else {
		std::cerr << ERR_MSG_A << std::endl;
		std::exit(EXIT_1);
	}
}

}	/* namespace */

extern "C" {

void *malloc(std::size_t size)
{
	if (!g_innerMalloc.load(std::memory_order_acquire))	/* Do not log own recursive malloc calls */
		MemoryLoggerFunctions::GetInstance().fillArrayEntry(FUNC_1_VALUE_1, size, MemoryLoggerFunctions::GetInstance().Now());
	if (g_innerMalloc.load(std::memory_order_acquire))
		g_innerMalloc.store(false, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Malloc(size);
}

void *realloc(void *ptr, std::size_t size)
{
	MemoryLoggerFunctions::GetInstance().fillArrayEntry(FUNC_2_VALUE_2, size, MemoryLoggerFunctions::GetInstance().Now());
	g_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Realloc(ptr, size);
}

void *calloc(std::size_t n, std::size_t size)
{
	if (g_innerCalloc.load(std::memory_order_acquire))	/* Requires calloc hack to stop recursion during dlsym inner calloc call */
		return g_static_alloc_buffer.data();
	MemoryLoggerFunctions::GetInstance().fillArrayEntry(FUNC_3_VALUE_3, n * size, MemoryLoggerFunctions::GetInstance().Now());
	g_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Calloc(n, size);
}

}// extern C
