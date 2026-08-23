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
			if (v_spin_count < MEMLOGGER_RELAXED_LOAD(m_spin_pred) << 1) continue;	/* m_spin_pred << 1 is eq m_spin_pred * 2 */
			#if !defined(__FreeBSD__)
			std::unique_lock<std::mutex> tlock(m_conditional_mutex);
			m_conditional_lock.wait_for(tlock, std::chrono::nanoseconds(1), [this]() { return !MEMLOGGER_RELAXED_LOAD(m_lock); });
			#else
			std::this_thread::sleep_for(std::chrono::nanoseconds(1));
			#endif
		}

		m_spin_pred.fetch_add((v_spin_count - MEMLOGGER_RELAXED_LOAD(m_spin_pred)) >> 3, std::memory_order_relaxed);	/* x >> 3 is eq x / 8 */
	}

	void unlock() noexcept
	{
		#if !defined(__FreeBSD__)
		std::unique_lock<std::mutex> tlock(m_conditional_mutex);
		#endif
		MEMLOGGER_RELEASE(m_lock);
		#if !defined(__FreeBSD__)
		m_conditional_lock.notify_one();
		#endif
	}
private:
	Fl& m_lock;
	std::atomic<T> m_spin_pred { 0 };
	#if !defined(__FreeBSD__)
	std::mutex m_conditional_mutex;
	std::condition_variable m_conditional_lock;
	#endif
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
			if (m_hires_small_alloc) computeHiResPeakValue(i);
		}
		auto& v_pv_by_idx = m_PeakValueArray[i];	/* Can't be const */
		if (v_sum - v_pv_by_idx.previous > v_pv_by_idx.peak)
			v_pv_by_idx.peak = v_sum - v_pv_by_idx.previous;
		v_pv_by_idx.previous = v_sum;
	}
}


template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::computeHiResPeakValue(const T p_idx)
{
	const auto& v_ca_by_idx = m_HiResCounterArray[p_idx];
	auto& v_pv_by_idx = m_HiResPeakValueArray[p_idx];
	const L v_4_8 = v_ca_by_idx.allc_4_8;
	const L v_9_16 = v_ca_by_idx.allc_9_16;
	const L v_17_32 = v_ca_by_idx.allc_17_32;
	const L v_33_64 = v_ca_by_idx.allc_33_64;
	const L v_65_128 = v_ca_by_idx.allc_65_128;
	const L v_129_256 = v_ca_by_idx.allc_129_256;
	const L v_257_512 = v_ca_by_idx.allc_257_512;
	const L v_513_1024 = v_ca_by_idx.allc_513_1024;
	const L v_1025_2048 = v_ca_by_idx.allc_1025_2048;
	const L v_2049_4096 = v_ca_by_idx.allc_2049_4096;
	const L v_4097_8192 = v_ca_by_idx.allc_4097_8192;
	const L v_8193_16384 = v_ca_by_idx.allc_8193_16384;
	const L v_16385_32768 = v_ca_by_idx.allc_16385_32768;
	const L v_32769_65536 = v_ca_by_idx.allc_32769_65536;

	if (v_4_8 - v_pv_by_idx.previous_4_8 > v_pv_by_idx.peak_4_8) v_pv_by_idx.peak_4_8 = v_4_8 - v_pv_by_idx.previous_4_8;
	if (v_9_16 - v_pv_by_idx.previous_9_16 > v_pv_by_idx.peak_9_16) v_pv_by_idx.peak_9_16 = v_9_16 - v_pv_by_idx.previous_9_16;
	if (v_17_32 - v_pv_by_idx.previous_17_32 > v_pv_by_idx.peak_17_32) v_pv_by_idx.peak_17_32 = v_17_32 - v_pv_by_idx.previous_17_32;
	if (v_33_64 - v_pv_by_idx.previous_33_64 > v_pv_by_idx.peak_33_64) v_pv_by_idx.peak_33_64 = v_33_64 - v_pv_by_idx.previous_33_64;
	if (v_65_128 - v_pv_by_idx.previous_65_128 > v_pv_by_idx.peak_65_128) v_pv_by_idx.peak_65_128 = v_65_128 - v_pv_by_idx.previous_65_128;
	if (v_129_256 - v_pv_by_idx.previous_129_256 > v_pv_by_idx.peak_129_256) v_pv_by_idx.peak_129_256 = v_129_256 - v_pv_by_idx.previous_129_256;
	if (v_257_512 - v_pv_by_idx.previous_257_512 > v_pv_by_idx.peak_257_512) v_pv_by_idx.peak_257_512 = v_257_512 - v_pv_by_idx.previous_257_512;
	if (v_513_1024 - v_pv_by_idx.previous_513_1024 > v_pv_by_idx.peak_513_1024) v_pv_by_idx.peak_513_1024 = v_513_1024 - v_pv_by_idx.previous_513_1024;
	if (v_1025_2048 - v_pv_by_idx.previous_1025_2048 > v_pv_by_idx.peak_1025_2048) v_pv_by_idx.peak_1025_2048 = v_1025_2048 - v_pv_by_idx.previous_1025_2048;
	if (v_2049_4096 - v_pv_by_idx.previous_2049_4096 > v_pv_by_idx.peak_2049_4096) v_pv_by_idx.peak_2049_4096 = v_2049_4096 - v_pv_by_idx.previous_2049_4096;
	if (v_4097_8192 - v_pv_by_idx.previous_4097_8192 > v_pv_by_idx.peak_4097_8192) v_pv_by_idx.peak_4097_8192 = v_4097_8192 - v_pv_by_idx.previous_4097_8192;
	if (v_8193_16384 - v_pv_by_idx.previous_8193_16384 > v_pv_by_idx.peak_8193_16384) v_pv_by_idx.peak_8193_16384 = v_8193_16384 - v_pv_by_idx.previous_8193_16384;
	if (v_16385_32768 - v_pv_by_idx.previous_16385_32768 > v_pv_by_idx.peak_16385_32768) v_pv_by_idx.peak_16385_32768 = v_16385_32768 - v_pv_by_idx.previous_16385_32768;
	if (v_32769_65536 - v_pv_by_idx.previous_32769_65536 > v_pv_by_idx.peak_32769_65536) v_pv_by_idx.peak_32769_65536 = v_32769_65536 - v_pv_by_idx.previous_32769_65536;

	v_pv_by_idx.previous_4_8 = v_4_8;
	v_pv_by_idx.previous_9_16 = v_9_16;
	v_pv_by_idx.previous_17_32 = v_17_32;
	v_pv_by_idx.previous_33_64 = v_33_64;
	v_pv_by_idx.previous_65_128 = v_65_128;
	v_pv_by_idx.previous_129_256 = v_129_256;
	v_pv_by_idx.previous_257_512 = v_257_512;
	v_pv_by_idx.previous_513_1024 = v_513_1024;
	v_pv_by_idx.previous_1025_2048 = v_1025_2048;
	v_pv_by_idx.previous_2049_4096 = v_2049_4096;
	v_pv_by_idx.previous_4097_8192 = v_4097_8192;
	v_pv_by_idx.previous_8193_16384 = v_8193_16384;
	v_pv_by_idx.previous_16385_32768 = v_16385_32768;
	v_pv_by_idx.previous_32769_65536 = v_32769_65536;
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
	const auto& v_ca_by_idx = m_CounterArray[p_idx];
	v_sum += v_ca_by_idx.allc_64k;
	v_sum += v_ca_by_idx.allc_128k;
	v_sum += v_ca_by_idx.allc_256k;
	v_sum += v_ca_by_idx.allc_512k;
	v_sum += v_ca_by_idx.allc_1024k;
	v_sum += v_ca_by_idx.allc_2048k;
	v_sum += v_ca_by_idx.allc_4096k;
	v_sum += v_ca_by_idx.allc_8192k;
	v_sum += v_ca_by_idx.allc_more;
	return v_sum;
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::fillArrayEntryHiRes(const T p_idx, const T p_value)
{
	auto& v_ca_by_idx = m_HiResCounterArray[p_idx];
	if (p_value >= 4 && p_value <= m_c_num_hires_8)
		++v_ca_by_idx.allc_4_8;
	else if (p_value <= m_c_num_hires_16)
		++v_ca_by_idx.allc_9_16;
	else if (p_value <= m_c_num_hires_32)
		++v_ca_by_idx.allc_17_32;
	else if (p_value <= m_c_num_hires_64)
		++v_ca_by_idx.allc_33_64;
	else if (p_value <= m_c_num_hires_128)
		++v_ca_by_idx.allc_65_128;
	else if (p_value <= m_c_num_hires_256)
		++v_ca_by_idx.allc_129_256;
	else if (p_value <= m_c_num_hires_512)
		++v_ca_by_idx.allc_257_512;
	else if (p_value <= m_c_num_hires_1024)
		++v_ca_by_idx.allc_513_1024;
	else if (p_value <= m_c_num_hires_2048)
		++v_ca_by_idx.allc_1025_2048;
	else if (p_value <= m_c_num_hires_4096)
		++v_ca_by_idx.allc_2049_4096;
	else if (p_value <= m_c_num_hires_8192)
		++v_ca_by_idx.allc_4097_8192;
	else if (p_value <= m_c_num_hires_16384)
		++v_ca_by_idx.allc_8193_16384;
	else if (p_value <= m_c_num_hires_32768)
		++v_ca_by_idx.allc_16385_32768;
	else if (p_value <= m_c_num_hires_65536)
		++v_ca_by_idx.allc_32769_65536;
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::fillArrayEntry(const T p_idx, const T p_value)
{
	const L c_value = roundup_to_page_size(p_value);
	auto& v_ca_by_idx = m_CounterArray[p_idx];	/* Can't be const */

	AdaptiveSpinMutex spmux(v_ca_by_idx.lock);
	std::lock_guard<AdaptiveSpinMutex> lock(spmux);

	if (m_hires_small_alloc) fillArrayEntryHiRes(p_idx, p_value);

	if (c_value > 0 && c_value <= m_c_num_64K)
		++v_ca_by_idx.allc_64k;
	else if (c_value > m_c_num_64K && c_value <= m_c_num_128K)
		++v_ca_by_idx.allc_128k;
	else if (c_value > m_c_num_128K && c_value <= m_c_num_256K)
		++v_ca_by_idx.allc_256k;
	else if (c_value > m_c_num_256K && c_value <= m_c_num_512K)
		++v_ca_by_idx.allc_512k;
	else if (c_value > m_c_num_512K && c_value <= m_c_num_1024K)
		++v_ca_by_idx.allc_1024k;
	else if (c_value > m_c_num_1024K && c_value <= m_c_num_2048K)
		++v_ca_by_idx.allc_2048k;
	else if (c_value > m_c_num_2048K && c_value <= m_c_num_4096K)
		++v_ca_by_idx.allc_4096k;
	else if (c_value > m_c_num_4096K && c_value <= m_c_num_8192K)
		++v_ca_by_idx.allc_8192k;
	else if (c_value > m_c_num_8192K && c_value < UINT_MAX)
		++v_ca_by_idx.allc_more;

	if (c_value > v_ca_by_idx.allc_max && c_value < UINT_MAX)
		v_ca_by_idx.allc_max = c_value;

	const std::time_t c_timestamp = Now();
	if (!v_ca_by_idx.start)		/* Save timestamp; let's inline it */
		v_ca_by_idx.start = c_timestamp;
	else if (!v_ca_by_idx.stop || v_ca_by_idx.stop < c_timestamp)
		v_ca_by_idx.stop = c_timestamp;
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
		case static_cast<T>(Func_values::reallocarray_fvalue):
			return m_c_func6;
		default:
			return "";
	}
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printHiResReportByIdx(const T p_idx, std::ostream& p_stream)
{
	set_flag_on();
	const auto& v_ca_by_idx = m_HiResCounterArray[p_idx];
	const auto& v_pv_by_idx = m_HiResPeakValueArray[p_idx];
	const std::time_t c_time_diff = m_CounterArray[p_idx].stop - m_CounterArray[p_idx].start;
	const std::time_t c_interval = c_time_diff ? c_time_diff : 1;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_4_8 << v_ca_by_idx.allc_4_8 << " (Avg " << v_ca_by_idx.allc_4_8 / c_interval << ", Peak " << v_pv_by_idx.peak_4_8 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_9_16 << v_ca_by_idx.allc_9_16 << " (Avg " << v_ca_by_idx.allc_9_16 / c_interval << ", Peak " << v_pv_by_idx.peak_9_16 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_17_32 << v_ca_by_idx.allc_17_32 << " (Avg " << v_ca_by_idx.allc_17_32 / c_interval << ", Peak " << v_pv_by_idx.peak_17_32 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_33_64 << v_ca_by_idx.allc_33_64 << " (Avg " << v_ca_by_idx.allc_33_64 / c_interval << ", Peak " << v_pv_by_idx.peak_33_64 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_65_128 << v_ca_by_idx.allc_65_128 << " (Avg " << v_ca_by_idx.allc_65_128 / c_interval << ", Peak " << v_pv_by_idx.peak_65_128 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_129_256 << v_ca_by_idx.allc_129_256 << " (Avg " << v_ca_by_idx.allc_129_256 / c_interval << ", Peak " << v_pv_by_idx.peak_129_256 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_257_512 << v_ca_by_idx.allc_257_512 << " (Avg " << v_ca_by_idx.allc_257_512 / c_interval << ", Peak " << v_pv_by_idx.peak_257_512 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_513_1024 << v_ca_by_idx.allc_513_1024 << " (Avg " << v_ca_by_idx.allc_513_1024 / c_interval << ", Peak " << v_pv_by_idx.peak_513_1024 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_1025_2048 << v_ca_by_idx.allc_1025_2048 << " (Avg " << v_ca_by_idx.allc_1025_2048 / c_interval << ", Peak " << v_pv_by_idx.peak_1025_2048 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_2049_4096 << v_ca_by_idx.allc_2049_4096 << " (Avg " << v_ca_by_idx.allc_2049_4096 / c_interval << ", Peak " << v_pv_by_idx.peak_2049_4096 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_4097_8192 << v_ca_by_idx.allc_4097_8192 << " (Avg " << v_ca_by_idx.allc_4097_8192 / c_interval << ", Peak " << v_pv_by_idx.peak_4097_8192 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_8193_16384 << v_ca_by_idx.allc_8193_16384 << " (Avg " << v_ca_by_idx.allc_8193_16384 / c_interval << ", Peak " << v_pv_by_idx.peak_8193_16384 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_16385_32768 << v_ca_by_idx.allc_16385_32768 << " (Avg " << v_ca_by_idx.allc_16385_32768 / c_interval << ", Peak " << v_pv_by_idx.peak_16385_32768 << ")" << std::endl;
	p_stream << decodeMemFunc(p_idx) << HIRES_ALLOC_32769_65536 << v_ca_by_idx.allc_32769_65536 << " (Avg " << v_ca_by_idx.allc_32769_65536 / c_interval << ", Peak " << v_pv_by_idx.peak_32769_65536 << ")" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printReportByIdx(const T p_idx, std::ostream& p_stream)
{
	set_flag_on();
	const auto& v_ca_by_idx = m_CounterArray[p_idx];
	p_stream << decodeMemFunc(p_idx) << ALLOC_64K << v_ca_by_idx.allc_64k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_128K << v_ca_by_idx.allc_128k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_256K << v_ca_by_idx.allc_256k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_512K << v_ca_by_idx.allc_512k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_1024K << v_ca_by_idx.allc_1024k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_2048K << v_ca_by_idx.allc_2048k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_4096K << v_ca_by_idx.allc_4096k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_8192K << v_ca_by_idx.allc_8192k << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_MORE << v_ca_by_idx.allc_more << std::endl;
	p_stream << decodeMemFunc(p_idx) << ALLOC_MAX << v_ca_by_idx.allc_max / KBYTES << "k" << std::endl;
	p_stream << SEPARATION_LINE_2 << std::endl;
	const std::ptrdiff_t c_time_diff =
		!(v_ca_by_idx.stop - v_ca_by_idx.start) ? 1 : v_ca_by_idx.stop - v_ca_by_idx.start;
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
	if (m_hires_small_alloc) {
		p_stream << HIRES_REPORT_HEADING << std::endl;
		p_stream << SEPARATION_LINE_1 << std::endl;
		for (T i = 0; i < m_CounterArray.size(); ++i) {
			auto& v_ca_by_idx = m_CounterArray[i];	/* Can't be const */
			if (v_ca_by_idx.start) printHiResReportByIdx(i, p_stream);
			else p_stream << ERR_MSG_NF1 << decodeMemFunc(i) << ERR_MSG_NF2 << std::endl;
		}
		p_stream << std::endl;
	}
	p_stream << REPORT_HEADING << std::endl;
	p_stream << SEPARATION_LINE_1 << std::endl;
	for (T i = 0; i < m_CounterArray.size(); ++i) {
		auto& v_ca_by_idx = m_CounterArray[i];	/* Can't be const */
		if (v_ca_by_idx.start) {		/* If no memory calls registered, start is empty */
			if (!m_fname)
				printReportByIdx(i, p_stream);
			else {
				AdaptiveSpinMutex spmux(v_ca_by_idx.lock);
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

template <typename P, typename T, typename L, typename Fl>
inline P MemoryLogger<P, T, L, Fl>::reallocarray_mf_impl(P ptr, T nmemb, T size)
{
	fillArrayEntry(static_cast<T>(Func_values::reallocarray_fvalue), nmemb * size);
	set_flag_on();
	return m_ReallocArray(ptr, nmemb, size);
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

void* reallocarray(void* ptr, std::size_t nmemb, std::size_t size)
{
	memoryLogger_type& mli = memoryLogger_type::GetInstance();
	return mli.reallocarray_mf_impl(ptr, nmemb, size);
}

}	/* extern C */
