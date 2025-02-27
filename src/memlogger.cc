/**
 * Memory allocation calls simple logger
 */

#include "memlogger.h"

namespace {

template <typename P, typename T, typename L, typename Fl>
class MemoryLogger<P, T, L, Fl>::AdaptiveSpinMutex {
public:
	AdaptiveSpinMutex(Fl& p_lock) : m_lock(p_lock) {};
	AdaptiveSpinMutex(const AdaptiveSpinMutex&) = delete;
	~AdaptiveSpinMutex() = default;

	void lock() noexcept
	{
		T v_spin_count { 0 };

		while (MEMLOGGER_RELAXED_LOAD(m_lock) || MEMLOGGER_ACQUIRE_CAS(m_lock)) {
			++v_spin_count;
			if (v_spin_count < m_spin_pred << 1) continue;	/* m_spin_pred << 1 is eq m_spin_pred * 2 */
			std::this_thread::sleep_for(std::chrono::nanoseconds(1));
		}

		m_spin_pred += (v_spin_count - m_spin_pred) >> 3;	/* x >> 3 is eq x / 8 */
	}

	void unlock() noexcept
	{
		MEMLOGGER_RELEASE(m_lock);
	}
private:
	Fl& m_lock;
	std::atomic<T> m_spin_pred { 0 };
};

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::computePeakValue()
{
	for (T i = 0; i < m_CounterArray.size(); ++i) {
		L v_sum { 0 };
		{
			AdaptiveSpinMutex spmux(m_CounterArray[i].lock);
			std::lock_guard<AdaptiveSpinMutex> lock(spmux);
			v_sum = sumCounters(i);
		}
		if (v_sum - m_PeakValueArray[i].previous > m_PeakValueArray[i].peak)
			m_PeakValueArray[i].peak = v_sum - m_PeakValueArray[i].previous;
		m_PeakValueArray[i].previous = v_sum;
	}
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printReport()
{
	set_flag_on();
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

template <typename P, typename T, typename L, typename Fl>
inline T MemoryLogger<P, T, L, Fl>::get_page_size()
{
	static T pagesize { 0 };
	if (!pagesize) pagesize = T(sysconf(_SC_PAGE_SIZE));
	return pagesize;
}

template <typename P, typename T, typename L, typename Fl>
inline L MemoryLogger<P, T, L, Fl>::roundup_to_page_size(const T p_size)
{
	return p_size + (get_page_size() - p_size % get_page_size());
}

/* Return steady clock since from boot */
template <typename P, typename T, typename L, typename Fl>
inline std::time_t MemoryLogger<P, T, L, Fl>::Now()
{
	const std::chrono::steady_clock::duration c_dtn = std::chrono::steady_clock::now().time_since_epoch();
	return c_dtn.count() * std::chrono::steady_clock::period::num / std::chrono::steady_clock::period::den;
}

template <typename P, typename T, typename L, typename Fl>
L MemoryLogger<P, T, L, Fl>::sumCounters(const T p_idx)
{
	L v_sum { 0 };
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

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::fillArrayEntry(const T p_idx, const T p_value)
{
	const L c_value = roundup_to_page_size(p_value);

	AdaptiveSpinMutex spmux(m_CounterArray[p_idx].lock);
	std::lock_guard<AdaptiveSpinMutex> lock(spmux);

	if (c_value > 0 && c_value <= m_c_num_64K)
		++m_CounterArray[p_idx].allc_64k;
	else if (c_value > m_c_num_64K && c_value <= m_c_num_128K)
		++m_CounterArray[p_idx].allc_128k;
	else if (c_value > m_c_num_128K && c_value <= m_c_num_256K)
		++m_CounterArray[p_idx].allc_256k;
	else if (c_value > m_c_num_256K && c_value <= m_c_num_512K)
		++m_CounterArray[p_idx].allc_512k;
	else if (c_value > m_c_num_512K && c_value <= m_c_num_1024K)
		++m_CounterArray[p_idx].allc_1024k;
	else if (c_value > m_c_num_1024K && c_value <= m_c_num_2048K)
		++m_CounterArray[p_idx].allc_2048k;
	else if (c_value > m_c_num_2048K && c_value <= m_c_num_4096K)
		++m_CounterArray[p_idx].allc_4096k;
	else if (c_value > m_c_num_4096K && c_value <= m_c_num_8192K)
		++m_CounterArray[p_idx].allc_8192k;
	else if (c_value > m_c_num_8192K && c_value < UINT_MAX)
		++m_CounterArray[p_idx].allc_more;

	if (c_value > m_CounterArray[p_idx].allc_max && c_value < UINT_MAX)
		m_CounterArray[p_idx].allc_max = c_value;

	const std::time_t c_timestamp = Now();
	if (!m_CounterArray[p_idx].start)		/* Save timestamp; let's inline it */
		m_CounterArray[p_idx].start = c_timestamp;
	else if (!m_CounterArray[p_idx].stop || m_CounterArray[p_idx].stop < c_timestamp)
		m_CounterArray[p_idx].stop = c_timestamp;
}

template <typename P, typename T, typename L, typename Fl>
const char* MemoryLogger<P, T, L, Fl>::decodeMemFunc(const T p_idx)
{
	switch (p_idx) {
		case static_cast<T>(Func_values::malloc_fvalue):
			return m_c_func1;
		case static_cast<T>(Func_values::realloc_fvalue):
			return m_c_func2;
		#ifdef COMPAT_OS
		case static_cast<T>(Func_values::calloc_fvalue):
			return m_c_func3;
		#endif
		case static_cast<T>(Func_values::free_fvalue):
			return m_c_func4;
		default:
			return "";
	}
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printReportByIdx(const T p_idx, std::ostream& p_stream)
{
	set_flag_on();
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
	const std::ptrdiff_t c_time_diff =
		!(m_CounterArray[p_idx].stop - m_CounterArray[p_idx].start) ? 1 : m_CounterArray[p_idx].stop - m_CounterArray[p_idx].start;
	p_stream << "Avg " << sumCounters(p_idx) / c_time_diff << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	p_stream << "Peak " << m_PeakValueArray[p_idx].peak << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printElapsedTime(std::ostream& p_stream)
{
	set_flag_on();
	const std::time_t c_sec = Now() - m_elapsed_start;
	const std::chrono::seconds c_sec2 = std::chrono::seconds(c_sec);

	p_stream << "Elapsed time: " << c_sec << " seconds ("
	<< std::setw(2) << std::setfill('0') << std::chrono::duration_cast<std::chrono::hours>(c_sec2).count() << ":"
	<< std::setw(2) << std::setfill('0') << std::chrono::duration_cast<std::chrono::minutes>(c_sec2).count() % 60 << ":"
	<< std::setw(2) << std::setfill('0') << c_sec2.count() % 60 << ")"
	<< std::endl;
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printReportTotal(std::ostream& p_stream)
{
	set_flag_on();
	p_stream << REPORT_HEADING << std::endl;
	p_stream << SEPARATION_LINE_1 << std::endl;
	for (T i = 0; i < m_CounterArray.size(); ++i) {
		if (m_CounterArray[i].start) {	/* If no memory calls registered, start is empty */
			if (!m_fname)
				printReportByIdx(i, p_stream);
			else {
				AdaptiveSpinMutex spmux(m_CounterArray[i].lock);
				std::lock_guard<AdaptiveSpinMutex> lock(spmux);
				printReportByIdx(i, p_stream);
			}
		} else p_stream << ERR_MSG_NF1 << decodeMemFunc(i) << ERR_MSG_NF2 << std::endl;
	}
	printElapsedTime(p_stream);
}

template <typename P, typename T, typename L, typename Fl>
inline P MemoryLogger<P, T, L, Fl>::malloc_mf_impl(T size)
{
	if (!get_flag())	/* Do not log own recursive malloc calls */
		fillArrayEntry(static_cast<T>(Func_values::malloc_fvalue), size);
	else set_flag_off();
	return m_Malloc(size);
}

template <typename P, typename T, typename L, typename Fl>
inline P MemoryLogger<P, T, L, Fl>::realloc_mf_impl(P ptr, T size)
{
	fillArrayEntry(static_cast<T>(Func_values::realloc_fvalue), size);
	set_flag_on();
	return m_Realloc(ptr, size);
}

#ifdef COMPAT_OS
template <typename P, typename T, typename L, typename Fl>
inline P MemoryLogger<P, T, L, Fl>::calloc_mf_impl(T n, T size)
{
	if (!m_Calloc)	/* Requires calloc replacement to stop recursion during dlsym inner calloc call */
		return malloc_internal(n * size);
	fillArrayEntry(static_cast<T>(Func_values::calloc_fvalue), n * size);
	set_flag_on();
	return m_Calloc(n, size);
}
#endif

template <typename P, typename T, typename L, typename Fl>
inline void MemoryLogger<P, T, L, Fl>::free_mf_impl(P ptr)
{
	if (!get_flag() && m_MallocUsable)	/* Do not log own recursive paired free calls and do not log free when malloc_usable_size not exist */
		fillArrayEntry(static_cast<T>(Func_values::free_fvalue), m_MallocUsable(ptr));
	else set_flag_off();
	m_Free(ptr);
}

}	/* namespace */

extern "C" {

void* malloc(std::size_t size)
{
	memoryLogger_type& mli = memoryLogger_type::GetInstance();
	return mli.malloc_mf_impl(size);
}

void* realloc(void* ptr, std::size_t size)
{
	memoryLogger_type& mli = memoryLogger_type::GetInstance();
	return mli.realloc_mf_impl(ptr, size);
}

#ifdef COMPAT_OS
void* calloc(std::size_t n, std::size_t size)
{
	memoryLogger_type& mli = memoryLogger_type::GetInstance();
	return mli.calloc_mf_impl(n, size);
}
#endif

void free(void* ptr)
{
	memoryLogger_type& mli = memoryLogger_type::GetInstance();
	mli.free_mf_impl(ptr);
}

}	/* extern C */
