/**
 * Malloc logger reporting tool
 */

#include "memlogger-report.h"

namespace {

/* Implementations */
void MemloggerReport::fillArrayEntry(std::string&& p_fname, const std::size_t p_value, const long p_timestamp)
{
	std::size_t v_array_line = 0;					/* Choose appropriate array line */
	if (p_fname == FUNC_2) v_array_line = 1;
	else if (p_fname == FUNC_3) v_array_line = 2;

	if (m_CounterArray[v_array_line].memory_function.empty())	/* Write function if not yet */
		m_CounterArray[v_array_line].memory_function = p_fname;

	if (m_CounterArray[v_array_line].start == 0)			/* Save timestamp; let's inline it */
		m_CounterArray[v_array_line].start = p_timestamp;
	else if (m_CounterArray[v_array_line].stop == 0 || m_CounterArray[v_array_line].stop < p_timestamp)
		m_CounterArray[v_array_line].stop = p_timestamp;

	if (p_value > 0 && p_value <= m_num_64K)
		++m_CounterArray[v_array_line].allc_64k;
	else if (p_value > m_num_64K && p_value <= m_num_128K)
		++m_CounterArray[v_array_line].allc_128k;
	else if (p_value > m_num_128K && p_value <= m_num_256K)
		++m_CounterArray[v_array_line].allc_256k;
	else if (p_value > m_num_256K && p_value <= m_num_512K)
		++m_CounterArray[v_array_line].allc_512k;
	else if (p_value > m_num_512K && p_value <= m_num_1024K)
		++m_CounterArray[v_array_line].allc_1024k;
	else if (p_value > m_num_1024K && p_value <= m_num_2048K)
		++m_CounterArray[v_array_line].allc_2048k;
	else if (p_value > m_num_2048K && p_value <= m_num_4096K)
		++m_CounterArray[v_array_line].allc_4096k;
	else if (p_value > m_num_4096K && p_value <= m_num_8192K)
		++m_CounterArray[v_array_line].allc_8192k;
	else if (p_value > m_num_8192K) {
		++m_CounterArray[v_array_line].allc_more;
		if (p_value > m_CounterArray[v_array_line].allc_max)
			m_CounterArray[v_array_line].allc_max = p_value;
	}
}

void MemloggerReport::processData()
{
	FileForReadWrite v_file(m_LogFile, std::ios_base::binary|std::ios_base::in);
	if (v_file.fd.is_open()) {
		std::vector<std::string> v_tokens;	/* Sequentially: function, size, timestamp */
		v_tokens.reserve(TOKENS_RESERVE_SIZE);	/* Reserve space for tokens; this speed up processing ~20% */
		std::string v_line;
		v_line.reserve(LINE_RESERVE_SIZE);
		while (std::getline(v_file.fd, v_line)) {
			if (v_line.empty()) continue;	/* Do not parse empty line */
			for (auto v_first = std::begin(v_line), v_last = std::end(v_line);;) {
				auto v_pos = std::find_first_of(v_first, v_last, std::begin(m_c_delim), std::end(m_c_delim));
				if (v_first != v_pos)
					v_tokens.emplace_back(std::string(v_first, v_pos));
				if (v_pos == v_last) break;
				v_first = std::next(v_pos);
			}
			try {
				if (v_tokens[0] == FUNC_1 || v_tokens[0] == FUNC_2 || v_tokens[0] == FUNC_3)
					fillArrayEntry(std::move(v_tokens[0]), std::stoul(v_tokens[1]), std::stol(v_tokens[2]));
				else continue;		/* If token not known, skip line */
			} catch(...) {
				continue;		/* In case of any exception, skip line */
			}
			v_tokens.clear();
		}
	} else {
		std::cerr << ERR_MSG_F + m_LogFile << std::endl;
		std::exit(EXIT_2);
	};
}

std::size_t MemloggerReport::sumCounters(const std::size_t p_idx)
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

void MemloggerReport::printReport(AsyncWriter& p_stream, const std::size_t p_idx)
{
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_64K << m_CounterArray[p_idx].allc_64k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_128K << m_CounterArray[p_idx].allc_128k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_256K << m_CounterArray[p_idx].allc_256k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_512K << m_CounterArray[p_idx].allc_512k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_1024K << m_CounterArray[p_idx].allc_1024k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_2048K << m_CounterArray[p_idx].allc_2048k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_4096K << m_CounterArray[p_idx].allc_4096k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_8192K << m_CounterArray[p_idx].allc_8192k << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_MORE << m_CounterArray[p_idx].allc_more << std::endl;
	p_stream << m_CounterArray[p_idx].memory_function << ALLOC_MAX << m_CounterArray[p_idx].allc_max / KBYTES << "k" << std::endl;
	p_stream << SEPARATION_LINE << std::endl;
	if (m_CounterArray[p_idx].stop - m_CounterArray[p_idx].start != 0 && sumCounters(p_idx) != 0)
		p_stream << sumCounters(p_idx) / (m_CounterArray[p_idx].stop - m_CounterArray[p_idx].start)
			<< " " << m_CounterArray[p_idx].memory_function << " calls/sec" << std::endl;
	else
		p_stream << "0 " << m_CounterArray[p_idx].memory_function << " calls/sec" << std::endl;
	p_stream << SEPARATION_LINE << std::endl;
}

long MemloggerReport::computeTotalLoggingTime()
{
	return *std::max_element(&m_CounterArray[0].stop, &m_CounterArray[0].stop + (m_CounterArray.size() - 1)) -
		*std::min_element(&m_CounterArray[0].start, &m_CounterArray[0].start + (m_CounterArray.size() - 1));
}

void MemloggerReport::printReportTotal(AsyncWriter& p_stream)
{
	if (m_CounterArray.size() > 0) {
		for (std::size_t i = 0; i < m_CounterArray.size(); ++i) {
			if (!m_CounterArray[i].memory_function.empty())
				printReport(p_stream, i);
			else
				p_stream << ERR_MSG_NF << std::endl;
		}
		p_stream << "Elapsed time: " << computeTotalLoggingTime() << " sec" << std::endl;
	} else {
		std::cerr << ERR_MSG_A << std::endl;
		std::exit(EXIT_1);
	}
}

void MemloggerReport::processArgs(int argc, char* argv[])
{
	std::vector<std::string> v_args(argv + 1, argv + argc);	/* Get args using constructor */
	for (auto& a : v_args) {
		std::transform(a.begin(), a.end(), a.begin(), [](unsigned char c) { return std::tolower(c); });
		if (a == "-v") {			/* -v - show version */
			std::cerr << "Version " << VERSION << std::endl;
			std::cerr << COPYRIGHT << std::endl;
			std::exit(EXIT_0);
		} else if (a == "-h" || a == "-?") {	/* -h|-? - print help and exit */
			const Help c_cli_help;
			std::cerr << c_cli_help;
			std::exit(EXIT_0);
		} else if (a[0] == '-' && a[1] == 'l' && a.length() > 2) {/* -l - specify log file to non-default */
			m_LogFile = a.substr(2, std::string::npos);
		} else if (a[0] == '-' && a[1] == 'f') {
			if (a.length() > 2)		/* -f - specify output file to non-default */
				m_OutputFile = a.substr(2, std::string::npos);
			m_OutputConsole = false;
		} else {
			std::cerr << ERR_MSG_O + a << std::endl;
			std::exit(EXIT_3);
		};
	};
	if (!m_OutputConsole) FileForReadWrite v_out_f(m_OutputFile);	/* Truncate file on first run */
}

}	/* namespace */

int main(int argc, char* argv[])
{
	std::ios::sync_with_stdio(false);		/* Disable stdio/streams syncing */
	std::cin.tie(nullptr);				/* Untie cin from cout */

	if (argc > 1)
		MemloggerReport::GetInstance().processArgs(argc, argv);

	MemloggerReport::GetInstance().processData();

	if (MemloggerReport::GetInstance().m_OutputConsole) {
		AsyncWriter v_out_stream;
		MemloggerReport::GetInstance().printReportTotal(v_out_stream);
	} else {
		FileForReadWrite v_out_f(MemloggerReport::GetInstance().m_OutputFile, std::ios_base::app|std::ios_base::out);
		if (!v_out_f.fd.is_open()) {
			std::cerr << ERR_MSG_F + MemloggerReport::GetInstance().m_OutputFile << std::endl;
			std::exit(EXIT_2);
		}
		AsyncWriter v_out_stream(v_out_f.fd);
		MemloggerReport::GetInstance().printReportTotal(v_out_stream);
	}

	return 0;
}
