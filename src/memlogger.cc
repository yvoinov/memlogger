/**
 * Memory allocation calls simple logger
 */

#include "memlogger.h"

namespace {

template <typename T>
class MemoryLoggerFunctions<T>::AdaptiveSpinMutex {
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

template <typename T>
inline std::size_t MemoryLoggerFunctions<T>::get_page_size()
{
	static T pagesize { 0 };
	if (!pagesize) pagesize = T(sysconf(_SC_PAGE_SIZE));
	return pagesize;
}

template <typename T>
inline std::size_t MemoryLoggerFunctions<T>::roundup_to_page_size(const T p_size)
{
	return p_size + (get_page_size() - p_size % get_page_size());
}

/* Return current time in seconds since epoch */
template <typename T>
inline long MemoryLoggerFunctions<T>::Now()
{
	const std::chrono::system_clock::duration c_dtn = std::chrono::system_clock::now().time_since_epoch();
	return c_dtn.count() * std::chrono::system_clock::period::num / std::chrono::system_clock::period::den;
}

template <typename T>
std::size_t MemoryLoggerFunctions<T>::sumCounters(const T p_idx)
{
	T v_sum = 0;
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

template <typename T>
void MemoryLoggerFunctions<T>::fillArrayEntry(const T p_idx, const T p_value)
{
	const T v_value = roundup_to_page_size(p_value);
	const long c_timestamp = Now();

	AdaptiveSpinMutex spmux(m_CounterArray[p_idx].lock);
	std::lock_guard<AdaptiveSpinMutex> lock(spmux);	/* Take row-level spinlock here */

	if (!m_CounterArray[p_idx].start)			/* Save timestamp; let's inline it */
		m_CounterArray[p_idx].start = c_timestamp;
	else if (!m_CounterArray[p_idx].stop || m_CounterArray[p_idx].stop < c_timestamp)
		m_CounterArray[p_idx].stop = c_timestamp;

	if (v_value > 0 && v_value <= m_c_num_64K)
		++m_CounterArray[p_idx].allc_64k;
	else if (v_value > m_c_num_64K && v_value <= m_c_num_128K)
		++m_CounterArray[p_idx].allc_128k;
	else if (v_value > m_c_num_128K && v_value <= m_c_num_256K)
		++m_CounterArray[p_idx].allc_256k;
	else if (v_value > m_c_num_256K && v_value <= m_c_num_512K)
		++m_CounterArray[p_idx].allc_512k;
	else if (v_value > m_c_num_512K && v_value <= m_c_num_1024K)
		++m_CounterArray[p_idx].allc_1024k;
	else if (v_value > m_c_num_1024K && v_value <= m_c_num_2048K)
		++m_CounterArray[p_idx].allc_2048k;
	else if (v_value > m_c_num_2048K && v_value <= m_c_num_4096K)
		++m_CounterArray[p_idx].allc_4096k;
	else if (v_value > m_c_num_4096K && v_value <= m_c_num_8192K)
		++m_CounterArray[p_idx].allc_8192k;
	else if (v_value > m_c_num_8192K)
		++m_CounterArray[p_idx].allc_more;

	if (v_value > m_CounterArray[p_idx].allc_max)
		m_CounterArray[p_idx].allc_max = v_value;
}

template <typename T>
void MemoryLoggerFunctions<T>::computePeakValue()
{
	T c_sum;
	for (T i = 0; i < m_CounterArray.size(); ++i) {
		{
			AdaptiveSpinMutex spmux(m_CounterArray[i].lock);
			std::lock_guard<AdaptiveSpinMutex> lock(spmux);
			c_sum = sumCounters(i);
		}
		if (c_sum - m_PeakValueArray[i] > m_PeakValueArray[i])
			m_PeakValueArray[i] = c_sum - m_PeakValueArray[i];
	}
}

template <typename T>
std::string MemoryLoggerFunctions<T>::decodeMemFunc(const T p_idx)
{
	switch (p_idx) {
		case FUNC_1_VALUE_1:
			return std::string(FUNC_1);
			break;
		case FUNC_2_VALUE_2:
			return std::string(FUNC_2);
			break;
		case FUNC_3_VALUE_3:
			return std::string(FUNC_3);
			break;
		default:
			return std::string("");
			break;
	}
}

template <typename T>
void MemoryLoggerFunctions<T>::printReport(const T p_idx, std::ostream &p_stream)
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
	p_stream << "Peak " << m_PeakValueArray[p_idx] << " " << decodeMemFunc(p_idx) << " calls/sec" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
}

template <typename T>
long MemoryLoggerFunctions<T>::computeTotalLoggingTime()
{
	return *std::max_element(&m_CounterArray[0].stop, &m_CounterArray[0].stop + (m_CounterArray.size() - 1)) -
		*std::min_element(&m_CounterArray[0].start, &m_CounterArray[0].start + (m_CounterArray.size() - 1));
}

template <typename T>
void MemoryLoggerFunctions<T>::printReportTotal(std::ostream &p_stream)
{
	p_stream << REPORT_HEADING << std::endl;
	p_stream << SEPARATION_LINE_1 << std::endl;
	if (m_CounterArray.size() > 0) {
		for (T i = 0; i < m_CounterArray.size(); ++i) {
			if (!(m_CounterArray[i].start == 0))	/* If no memory calls registered, start is empty */
				printReport(i, p_stream);
			else p_stream << ERR_MSG_NF << std::endl;
		}
		const long c_sec = computeTotalLoggingTime();
		const std::chrono::seconds c_sec2 = std::chrono::seconds(c_sec);
		p_stream << "Elapsed time: " << c_sec << " seconds ("
		<< std::setw(2) << std::setfill('0') << std::chrono::duration_cast<std::chrono::hours>(c_sec2).count() << ":"
		<< std::setw(2) << std::setfill('0') << std::chrono::duration_cast<std::chrono::minutes>(c_sec2).count() % 60 << ":"
		<< std::setw(2) << std::setfill('0') << c_sec2.count() % 60 << ")"
		<< std::endl;
	} else {
		std::cerr << ERR_MSG_A << std::endl;
		std::exit(EXIT_1);
	}
}

template <typename T>
void MemoryLoggerFunctions<T>::printReport()
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

template <typename T>
inline void *malloc_mf_impl(T size)
{
	if (!g_innerMalloc.load(std::memory_order_acquire))	/* Do not log own recursive malloc calls */
		MemoryLoggerFunctions<>::GetInstance().fillArrayEntry(FUNC_1_VALUE_1, size);
	if (g_innerMalloc.load(std::memory_order_acquire))
		g_innerMalloc.store(false, std::memory_order_release);
	return MemoryLoggerFunctions<>::GetInstance().m_Malloc(size);
}

template <typename P, typename T>
inline void *realloc_mf_impl(P ptr, T size)
{
	MemoryLoggerFunctions<>::GetInstance().fillArrayEntry(FUNC_2_VALUE_2, size);
	g_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions<>::GetInstance().m_Realloc(ptr, size);
}

template <typename T>
inline void *calloc_mf_impl(T n, T size)
{
	if (g_innerCalloc.load(std::memory_order_acquire))	/* Requires calloc hack to stop recursion during dlsym inner calloc call */
		return g_static_alloc_buffer.data();
	MemoryLoggerFunctions<>::GetInstance().fillArrayEntry(FUNC_3_VALUE_3, n * size);
	g_innerMalloc.store(true, std::memory_order_release);
	return MemoryLoggerFunctions<>::GetInstance().m_Calloc(n, size);
}

}	/* namespace */

extern "C" {

void *malloc(std::size_t size)
{
	return malloc_mf_impl(size);
}

void *realloc(void *ptr, std::size_t size)
{
	return realloc_mf_impl(ptr, size);
}

void *calloc(std::size_t n, std::size_t size)
{
	return calloc_mf_impl(n, size);
}

}	/* extern C */
