/**
 * Memory allocation calls simple logger
 */

#include "memlogger.h"

namespace {

std::array<char, IO_BUFFER_SIZE> g_output_buffer;

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
void MemoryLogger<P, T, L, Fl>::computeHiResPeakValue(const T p_idx)
{
	auto& v_hires_by_idx = m_HiResCounterArray[p_idx];
	auto& v_pv_by_idx = m_HiResPeakValueArray[p_idx];

	for (T i = 0; i < m_c_hires_class_count; ++i) {
		L v_current { 0 };
		{
			AdaptiveSpinMutex spmux(v_hires_by_idx.lock);
			std::lock_guard<AdaptiveSpinMutex> lock(spmux);
			v_current = v_hires_by_idx.allc[i];
		}
		const L c_delta = v_current - v_pv_by_idx.previous[i];
		if (c_delta > v_pv_by_idx.peak[i])
			v_pv_by_idx.peak[i] = c_delta;
		v_pv_by_idx.previous[i] = v_current;
	}
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::computePeakValue()
{
	for (T i = 0; i < m_c_array_size; ++i) {
		L v_sum { 0 };
		{
			AdaptiveSpinMutex spmux(m_CounterArray[i].lock);
			std::lock_guard<AdaptiveSpinMutex> lock(spmux);
			v_sum = sumCounters(i);
		}
		if (m_hires_small_alloc) computeHiResPeakValue(i);
		auto& v_pv_by_idx = m_PeakValueArray[i];	/* Can't be const */
		if (v_sum - v_pv_by_idx.previous > v_pv_by_idx.peak)
			v_pv_by_idx.peak = v_sum - v_pv_by_idx.previous;
		v_pv_by_idx.previous = v_sum;
	}
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printReport()
{
	set_flag_on();
	if (!m_fname)
		printReportTotal();
	else {
		std::FILE* v_fd = std::fopen(m_fname, "w");
		if (!v_fd) {
			std::fprintf(stderr, "%s%s\n", ERR_MSG_F, m_fname);
			return;
		}
		std::setvbuf(v_fd, g_output_buffer.data(), _IOFBF, g_output_buffer.size());
		printReportTotal(v_fd);
		std::fclose(v_fd);
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
	const auto& c_ca_by_idx = m_CounterArray[p_idx];
	v_sum += c_ca_by_idx.allc_64k;
	v_sum += c_ca_by_idx.allc_128k;
	v_sum += c_ca_by_idx.allc_256k;
	v_sum += c_ca_by_idx.allc_512k;
	v_sum += c_ca_by_idx.allc_1024k;
	v_sum += c_ca_by_idx.allc_2048k;
	v_sum += c_ca_by_idx.allc_4096k;
	v_sum += c_ca_by_idx.allc_8192k;
	v_sum += c_ca_by_idx.allc_more;
	return v_sum;
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::fillArrayEntryHiRes(const T p_idx, const T p_value)
{
	auto& v_ca_by_idx = m_HiResCounterArray[p_idx].allc;
	T v_first { 0 };
	T v_last { m_c_hires_class_count };

	while (v_first < v_last) {
		const T v_middle = v_first + (v_last - v_first) / 2;
		if (p_value <= m_c_hires_classes[v_middle].limit)
			v_last = v_middle;
		else
			v_first = v_middle + 1;
	}

	++v_ca_by_idx[v_first];
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::fillArrayEntry(const T p_idx, const T p_value)
{
	if (m_hires_small_alloc &&
		p_value >= m_c_hires_min_size &&
		p_value <= m_c_hires_classes[m_c_hires_class_count - 1].limit) {
		AdaptiveSpinMutex spmux(m_HiResCounterArray[p_idx].lock);
		std::lock_guard<AdaptiveSpinMutex> lock(spmux);
		fillArrayEntryHiRes(p_idx, p_value);
	}

	const L c_value = roundup_to_page_size(p_value);
	auto& v_ca_by_idx = m_CounterArray[p_idx];	/* Can't be const */

	AdaptiveSpinMutex spmux(v_ca_by_idx.lock);
	std::lock_guard<AdaptiveSpinMutex> lock(spmux);

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
void MemoryLogger<P, T, L, Fl>::printHiResReportByIdx(const T p_idx, std::FILE* p_stream)
{
	set_flag_on();
	const auto& c_ca_by_idx = m_HiResCounterArray[p_idx].allc;
	const auto& c_pv_by_idx = m_HiResPeakValueArray[p_idx];
	const std::time_t c_time_diff = m_CounterArray[p_idx].stop - m_CounterArray[p_idx].start;
	const std::time_t c_interval = c_time_diff ? c_time_diff : 1;
	for (T i = 0; i < m_c_hires_class_count; ++i)
		std::fprintf(p_stream, "%s%s%" PRIu64 " (Avg %" PRIu64 ", Peak %" PRIu64 ")\n",
			decodeMemFunc(p_idx), m_c_hires_classes[i].label, c_ca_by_idx[i],
			c_ca_by_idx[i] / c_interval, c_pv_by_idx.peak[i]);
	std::fprintf(p_stream, "%s\n", SEPARATION_LINE_2);
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printReportByIdx(const T p_idx, std::FILE* p_stream)
{
	set_flag_on();
	const auto& c_ca_by_idx = m_CounterArray[p_idx];
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_64K, c_ca_by_idx.allc_64k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_128K, c_ca_by_idx.allc_128k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_256K, c_ca_by_idx.allc_256k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_512K, c_ca_by_idx.allc_512k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_1024K, c_ca_by_idx.allc_1024k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_2048K, c_ca_by_idx.allc_2048k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_4096K, c_ca_by_idx.allc_4096k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_8192K, c_ca_by_idx.allc_8192k);
	std::fprintf(p_stream, "%s%s%" PRIu64 "\n", decodeMemFunc(p_idx), ALLOC_MORE, c_ca_by_idx.allc_more);
	std::fprintf(p_stream, "%s%s%" PRIu64 "k\n", decodeMemFunc(p_idx), ALLOC_MAX, c_ca_by_idx.allc_max / KBYTES);
	std::fprintf(p_stream, "%s\n", SEPARATION_LINE_2);
	const std::ptrdiff_t c_time_diff = !(c_ca_by_idx.stop - c_ca_by_idx.start) ? 1 : c_ca_by_idx.stop - c_ca_by_idx.start;
	std::fprintf(p_stream, "Avg %" PRIu64 " %s calls/sec\n", sumCounters(p_idx) / c_time_diff, decodeMemFunc(p_idx));
	std::fprintf(p_stream, "Peak %" PRIu64 " %s calls/sec\n", m_PeakValueArray[p_idx].peak, decodeMemFunc(p_idx));
	std::fprintf(p_stream, "%s\n", SEPARATION_LINE_2);
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printElapsedTime(std::FILE* p_stream)
{
	set_flag_on();
	const std::time_t c_sec = Now() - m_elapsed_start;
	const std::chrono::seconds c_sec2 = std::chrono::seconds(c_sec);

	std::fprintf(p_stream, "Elapsed time: %" PRIdMAX " seconds (%02" PRIdMAX ":%02" PRIdMAX ":%02" PRIdMAX ")\n",
		static_cast<std::intmax_t>(c_sec),
		static_cast<std::intmax_t>(std::chrono::duration_cast<std::chrono::hours>(c_sec2).count()),
		static_cast<std::intmax_t>(std::chrono::duration_cast<std::chrono::minutes>(c_sec2).count() % 60),
		static_cast<std::intmax_t>(c_sec2.count() % 60));
}

template <typename P, typename T, typename L, typename Fl>
void MemoryLogger<P, T, L, Fl>::printReportTotal(std::FILE* p_stream)
{
	set_flag_on();
	if (m_hires_small_alloc) {
		std::fprintf(p_stream, "%s\n", HIRES_REPORT_HEADING);
		std::fprintf(p_stream, "%s\n", SEPARATION_LINE_1);
		for (T i = 0; i < m_HiResCounterArray.size(); ++i) {
			auto& v_hires_by_idx = m_HiResCounterArray[i];	/* Can't be const */
			if (m_CounterArray[i].start) {
				AdaptiveSpinMutex spmux(v_hires_by_idx.lock);
				std::lock_guard<AdaptiveSpinMutex> lock(spmux);
				printHiResReportByIdx(i, p_stream);
			} else std::fprintf(p_stream, "%s%s%s\n", ERR_MSG_NF1, decodeMemFunc(i), ERR_MSG_NF2);
		}
		std::fprintf(p_stream, "\n");
	}
	std::fprintf(p_stream, "%s\n", REPORT_HEADING);
	std::fprintf(p_stream, "%s\n", SEPARATION_LINE_1);
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
		} else std::fprintf(p_stream, "%s%s%s\n", ERR_MSG_NF1, decodeMemFunc(i), ERR_MSG_NF2);
	}
	printElapsedTime(p_stream);
	std::fflush(p_stream);
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
