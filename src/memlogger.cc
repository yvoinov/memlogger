/**
 * Memory allocation calls simple logger
 */
#include "memlogger.h"

namespace {

template <typename P, typename T, typename L>
class MemoryLogger<P, T, L>::AdaptiveSpinMutex {
	public:
		AdaptiveSpinMutex(std::atomic<bool>& p_lock) : m_lock(p_lock) {};
		AdaptiveSpinMutex(const AdaptiveSpinMutex&) = delete;
		~AdaptiveSpinMutex() = default;

		void lock() noexcept {
			T v_spin_count { 0 };

			while (m_lock.load(std::memory_order_relaxed) || m_lock.exchange(true, std::memory_order_acquire)) {
				++v_spin_count;
				if (v_spin_count < m_spin_pred << 1) continue;	/* m_spin_pred << 1 is eq m_spin_pred * 2 */
				#if !defined(__FreeBSD__)
				std::unique_lock<std::mutex> tlock(m_conditional_mutex);
				m_conditional_lock.wait_for(tlock, std::chrono::nanoseconds(1), [this]() { return !m_lock.load(std::memory_order_relaxed); });
				#else
				std::this_thread::sleep_for(std::chrono::nanoseconds(1));
				#endif
			}

			m_spin_pred += (v_spin_count - m_spin_pred) >> 3;	/* x >> 3 is eq x / 8 */
		}

		void unlock() noexcept {
			m_lock.store(false, std::memory_order_release);
			#if !defined(__FreeBSD__)
			m_conditional_lock.notify_one();
			#endif
		}
	private:
		std::atomic<bool>& m_lock;
		std::atomic<T> m_spin_pred { 0 };
		#if !defined(__FreeBSD__)
		std::mutex m_conditional_mutex;
		std::condition_variable m_conditional_lock;
		#endif
};

template <typename P, typename T, typename L>
inline T MemoryLogger<P, T, L>::get_page_size()
{
	static T pagesize { 0 };
	if (!pagesize) pagesize = T(sysconf(_SC_PAGE_SIZE));
	return pagesize;
}

template <typename P, typename T, typename L>
inline L MemoryLogger<P, T, L>::roundup_to_page_size(const T p_size)
{
	return p_size + (get_page_size() - p_size % get_page_size());
}

/* Return steady clock since from boot */
template <typename P, typename T, typename L>
inline std::time_t MemoryLogger<P, T, L>::Now()
{
	const std::chrono::steady_clock::duration c_dtn = std::chrono::steady_clock::now().time_since_epoch();
	return c_dtn.count() * std::chrono::steady_clock::period::num / std::chrono::steady_clock::period::den;
}

template <typename P, typename T, typename L>
L MemoryLogger<P, T, L>::sumCounters(const T p_idx)
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

template <typename P, typename T, typename L>
void MemoryLogger<P, T, L>::fillArrayEntry(const T p_idx, const T p_value)
{
	const L c_value = roundup_to_page_size(p_value);
	const std::time_t c_timestamp = Now();

	AdaptiveSpinMutex spmux(m_CounterArray[p_idx].lock);
	std::lock_guard<AdaptiveSpinMutex> lock(spmux);	/* Take row-level spinlock here */

	if (!m_CounterArray[p_idx].start)		/* Save timestamp; let's inline it */
		m_CounterArray[p_idx].start = c_timestamp;
	else if (!m_CounterArray[p_idx].stop || m_CounterArray[p_idx].stop < c_timestamp)
		m_CounterArray[p_idx].stop = c_timestamp;

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
}

template <typename P, typename T, typename L>
void MemoryLogger<P, T, L>::computePeakValue()
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

template <typename P, typename T, typename L>
const char* MemoryLogger<P, T, L>::decodeMemFunc(const T p_idx)
{
	switch (p_idx) {
		case Func_values::malloc_fvalue:
			return m_c_func1;
		case Func_values::realloc_fvalue:
			return m_c_func2;
		case Func_values::calloc_fvalue:
			return m_c_func3;
		default:
			return "";
	}
}

template <typename P, typename T, typename L>
void MemoryLogger<P, T, L>::printReport(const T p_idx, std::ostream &p_stream)
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
	if (c_time_diff && sumCounters(p_idx))
		p_stream << "Avg " << sumCounters(p_idx) / c_time_diff << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	else if (!c_time_diff && sumCounters(p_idx))		/* If allocations fit one epoch tick */
		p_stream << "Avg " << sumCounters(p_idx) << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	else
		p_stream << "0 " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	p_stream << "Peak " << m_PeakValueArray[p_idx].peak << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
}

template <typename P, typename T, typename L>
std::time_t MemoryLogger<P, T, L>::computeTotalLoggingTime()
{
	std::array<std::time_t, m_c_array_size> v_arr_min, v_arr_max;

	for (T i = 0; i < m_CounterArray.size(); ++i) {
		v_arr_min[i] = m_CounterArray[i].start;
		v_arr_max[i] = m_CounterArray[i].stop;
	};

	return *std::max_element(v_arr_max.cbegin(), v_arr_max.cend()) -
		*std::min_element(v_arr_min.cbegin(), v_arr_min.cend(),
		[](std::time_t a, std::time_t b) { if (!a) return false; if (!b) return true; return a < b; });
}

template <typename P, typename T, typename L>
void MemoryLogger<P, T, L>::printElapsedTime(std::ostream &p_stream)
{
	const std::time_t c_sec = computeTotalLoggingTime();
	const std::chrono::seconds c_sec2 = std::chrono::seconds(c_sec);

	p_stream << "Elapsed time: " << c_sec << " seconds ("
	<< std::setw(2) << std::setfill('0') << std::chrono::duration_cast<std::chrono::hours>(c_sec2).count() << ":"
	<< std::setw(2) << std::setfill('0') << std::chrono::duration_cast<std::chrono::minutes>(c_sec2).count() % 60 << ":"
	<< std::setw(2) << std::setfill('0') << c_sec2.count() % 60 << ")"
	<< std::endl;
}

template <typename P, typename T, typename L>
void MemoryLogger<P, T, L>::printReportTotal(std::ostream &p_stream)
{
	p_stream << REPORT_HEADING << std::endl;
	p_stream << SEPARATION_LINE_1 << std::endl;
	if (m_CounterArray.size() > 0) {
		for (T i = 0; i < m_CounterArray.size(); ++i) {
			if (!(m_CounterArray[i].start == 0))	/* If no memory calls registered, start is empty */
				printReport(i, p_stream);
			else p_stream << ERR_MSG_NF << std::endl;
		}

		printElapsedTime(p_stream);
	} else {
		std::cerr << ERR_MSG_A << std::endl;
		std::exit(EXIT_1);
	}
}

template <typename P, typename T, typename L>
void MemoryLogger<P, T, L>::printReport()
{
	if (!m_fname)
		printReportTotal();
	else {
		g_innerMalloc.store(true, std::memory_order_release);
		std::string v_OutputFile = std::string(m_fname);
		std::ofstream v_fd = std::ofstream(v_OutputFile, std::ios_base::trunc|std::ios_base::out);
		if (!v_fd.is_open()) {
			std::cerr << ERR_MSG_F + v_OutputFile << std::endl;
			return;
		}
		printReportTotal(v_fd);
		v_fd.close();
		g_innerMalloc.store(false, std::memory_order_release);
	}
}

template <typename P, typename T, typename L>
inline P MemoryLogger<P, T, L>::malloc_mf_impl(T size)
{
	if (!g_innerMalloc.load(std::memory_order_acquire))	/* Do not log own recursive malloc calls */
		fillArrayEntry(Func_values::malloc_fvalue, size);
	else
		g_innerMalloc.store(false, std::memory_order_release);
	return m_Malloc(size);
}

template <typename P, typename T, typename L>
inline P MemoryLogger<P, T, L>::realloc_mf_impl(P ptr, T size)
{
	fillArrayEntry(Func_values::realloc_fvalue, size);
	g_innerMalloc.store(true, std::memory_order_release);
	return m_Realloc(ptr, size);
}

template <typename P, typename T, typename L>
inline P MemoryLogger<P, T, L>::calloc_mf_impl(T n, T size)
{
	if (g_innerCalloc.load(std::memory_order_acquire))	/* Requires calloc hack to stop recursion during dlsym inner calloc call */
		return g_static_alloc_buffer.data();
	fillArrayEntry(Func_values::calloc_fvalue, n * size);
	g_innerMalloc.store(true, std::memory_order_release);
	return m_Calloc(n, size);
}

}	/* namespace */

extern "C" {

voidPtr_t malloc(uInt_t size)
{
	return memoryLogger_t::GetInstance().malloc_mf_impl(size);
}

voidPtr_t realloc(voidPtr_t ptr, uInt_t size)
{
	return memoryLogger_t::GetInstance().realloc_mf_impl(ptr, size);
}

voidPtr_t calloc(uInt_t n, uInt_t size)
{
	return memoryLogger_t::GetInstance().calloc_mf_impl(n, size);
}

}	/* extern C */
