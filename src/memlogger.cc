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

template <typename S, typename T, typename L>
void MemoryLoggerFunctions::fillArrayEntry(S&& p_fname, const T p_value, const L p_timestamp)
{
	T v_array_line = 0;						/* Choose appropriate array line */
	if (p_fname == std::string(FUNC_2)) v_array_line = 1;
	else if (p_fname == std::string(FUNC_3)) v_array_line = 2;

	AdaptiveSpinMutex spmux(v_CounterArray[v_array_line].lock);
	std::lock_guard<AdaptiveSpinMutex> lock(spmux);              	/* Take row-level spinlock here */

	if (v_CounterArray[v_array_line].memory_function.empty())	/* Write function if not yet */
		v_CounterArray[v_array_line].memory_function = p_fname;

	if (v_CounterArray[v_array_line].start == 0)			/* Save timestamp; let's inline it */
		v_CounterArray[v_array_line].start = p_timestamp;
	else if (v_CounterArray[v_array_line].stop == 0 || v_CounterArray[v_array_line].stop < p_timestamp)
		v_CounterArray[v_array_line].stop = p_timestamp;

	if (p_value > 0 && p_value <= c_num_64K)
		++v_CounterArray[v_array_line].allc_64k;
	else if (p_value > c_num_64K && p_value <= c_num_128K)
		++v_CounterArray[v_array_line].allc_128k;
	else if (p_value > c_num_128K && p_value <= c_num_256K)
		++v_CounterArray[v_array_line].allc_256k;
	else if (p_value > c_num_256K && p_value <= c_num_512K)
		++v_CounterArray[v_array_line].allc_512k;
	else if (p_value > c_num_512K && p_value <= c_num_1024K)
		++v_CounterArray[v_array_line].allc_1024k;
	else if (p_value > c_num_1024K && p_value <= c_num_2048K)
		++v_CounterArray[v_array_line].allc_2048k;
	else if (p_value > c_num_2048K && p_value <= c_num_4096K)
		++v_CounterArray[v_array_line].allc_4096k;
	else if (p_value > c_num_4096K && p_value <= c_num_8192K)
		++v_CounterArray[v_array_line].allc_8192k;
	else if (p_value > c_num_8192K) {
		++v_CounterArray[v_array_line].allc_more;
	}
	if (p_value > v_CounterArray[v_array_line].allc_max)
		v_CounterArray[v_array_line].allc_max = p_value;
}

std::size_t OnLoadUnload::sumCounters(const std::size_t p_idx)
{
	std::size_t v_sum = 0;
	v_sum += v_CounterArray[p_idx].allc_64k;
	v_sum += v_CounterArray[p_idx].allc_128k;
	v_sum += v_CounterArray[p_idx].allc_256k;
	v_sum += v_CounterArray[p_idx].allc_512k;
	v_sum += v_CounterArray[p_idx].allc_1024k;
	v_sum += v_CounterArray[p_idx].allc_2048k;
	v_sum += v_CounterArray[p_idx].allc_4096k;
	v_sum += v_CounterArray[p_idx].allc_8192k;
	v_sum += v_CounterArray[p_idx].allc_more;
	return v_sum;
}

void OnLoadUnload::printReport(const std::size_t p_idx, std::ostream &p_stream)
{
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_64K << v_CounterArray[p_idx].allc_64k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_128K << v_CounterArray[p_idx].allc_128k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_256K << v_CounterArray[p_idx].allc_256k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_512K << v_CounterArray[p_idx].allc_512k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_1024K << v_CounterArray[p_idx].allc_1024k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_2048K << v_CounterArray[p_idx].allc_2048k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_4096K << v_CounterArray[p_idx].allc_4096k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_8192K << v_CounterArray[p_idx].allc_8192k << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_MORE << v_CounterArray[p_idx].allc_more << std::endl;
	p_stream << v_CounterArray[p_idx].memory_function << ALLOC_MAX << v_CounterArray[p_idx].allc_max / KBYTES << "k" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
	const std::ptrdiff_t c_time_diff = v_CounterArray[p_idx].stop - v_CounterArray[p_idx].start;
	if (c_time_diff != 0 && sumCounters(p_idx) != 0)
		p_stream << sumCounters(p_idx) / c_time_diff << " " << v_CounterArray[p_idx].memory_function << " calls/sec" << std::endl;
	else if (c_time_diff == 0 && sumCounters(p_idx) != 0)	/* If allocations fit one epoch tick */
		p_stream << sumCounters(p_idx) << " " << v_CounterArray[p_idx].memory_function << " calls/sec" << std::endl;
	else
		p_stream << "0 " << v_CounterArray[p_idx].memory_function << " calls/sec" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
}

long OnLoadUnload::computeTotalLoggingTime()
{
	return *std::max_element(&v_CounterArray[0].stop, &v_CounterArray[0].stop + (v_CounterArray.size() - 1)) -
		*std::min_element(&v_CounterArray[0].start, &v_CounterArray[0].start + (v_CounterArray.size() - 1));
}

void OnLoadUnload::printReportTotal(std::ostream &p_stream)
{
	p_stream << REPORT_HEADING << std::endl;
	p_stream << SEPARATION_LINE_1 << std::endl;
	if (v_CounterArray.size() > 0) {
		for (std::size_t i = 0; i < v_CounterArray.size(); ++i) {
			if (!v_CounterArray[i].memory_function.empty())
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
	if (!v_innerMalloc.load(std::memory_order_acquire))	/* Do not log own recursive or IO malloc calls */
		MemoryLoggerFunctions::GetInstance().fillArrayEntry(FUNC_1, size, MemoryLoggerFunctions::GetInstance().Now());
	if (v_innerMalloc.load(std::memory_order_acquire))
		v_innerMalloc.store(false, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Malloc(size);
}

void *realloc(void *ptr, std::size_t size)
{
	MemoryLoggerFunctions::GetInstance().fillArrayEntry(FUNC_2, size, MemoryLoggerFunctions::GetInstance().Now());
	v_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Realloc(ptr, size);
}

void *calloc(std::size_t n, std::size_t size)
{
	if (v_innerCalloc.load(std::memory_order_acquire))	/* Requires calloc hack to stop recursion during dlsym inner calloc call */
		return v_static_alloc_buffer.data();
	MemoryLoggerFunctions::GetInstance().fillArrayEntry(FUNC_3, n * size, MemoryLoggerFunctions::GetInstance().Now());
	v_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions::GetInstance().m_Calloc(n, size);
}

}// extern C
