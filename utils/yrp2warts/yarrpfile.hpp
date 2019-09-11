/****************************************************************************
 * Copyright (c) 2016-2019 Justin P. Rohrer <jprohrer@tancad.org> 
 * All rights reserved.  
 *
 * Program:     $Id: yarrpfile.hpp $
 * Description: Process Yarrp output
 *
 * Attribution: R. Beverly, "Yarrp'ing the Internet: Randomized High-Speed 
 *              Active Topology Discovery", Proceedings of the ACM SIGCOMM 
 *              Internet Measurement Conference, November, 2016
 ***************************************************************************/

#ifndef YARRPFILE_INCLUDED
#define YARRPFILE_INCLUDED

//#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include "ipaddress.hpp"

using namespace std;
using namespace ip;

// from scamper/trace/scamper_trace.h
typedef enum {ICMP6 = 0x04, ICMP = 0x04, UDP6 = 0x05, UDP = 0x05, TCP6_SYN = 0x03, TCP_SYN = 0x03, TCP6_ACK = 0x06, TCP_ACK = 0x06} traceroute_t;

// from yarrp/src/trace.h
static vector<traceroute_t> traceroute_type = {ICMP6, ICMP, UDP6, UDP, TCP6_SYN, TCP_SYN, TCP6_ACK, TCP_ACK};

static unordered_map<string,traceroute_t> tracetype_names = { {"ICMP", ICMP}, {"ICMP6", ICMP6}, {"UDP", UDP}, {"UDP6", UDP6}, {"TCP_SYN", TCP_SYN}, {"TCP6_SYN", TCP6_SYN}, {"TCP_ACK", TCP_ACK}, {"TCP6_ACK", TCP6_ACK} };


struct yarrpRecord
{
	ipaddress target;
	uint32_t sec;
	uint32_t usec;
	uint8_t typ;
	uint8_t code;
	uint8_t ttl;
	ipaddress hop;
	uint32_t rtt;
	uint16_t ipid;
	uint16_t psize;
	uint16_t rsize;
	uint8_t rttl;
	uint8_t rtos;
	uint64_t count;
};

ostream& operator<< (ostream& os, const yarrpRecord& r)
{
    return os << r.target << ", " << r.sec << ", " << r.usec << ", " << uint16_t(r.typ) << ", " << uint16_t(r.code) << ", " << uint16_t(r.ttl) << ", " << r.hop << ", " << r.rtt << ", " << r.ipid << ", " << r.psize << ", " << r.rsize << ", " << uint16_t(r.rttl) << ", " << uint16_t(r.rtos) << ", " << r.count;
}
istream& operator>> (istream &in, yarrpRecord& r)
{
	uint16_t typ, code, ttl, rttl, rtos;
	in >> r.target >> r.sec >> r.usec >> typ >> code >> ttl >> r.hop >> r.rtt >> r.ipid >> r.psize >> r.rsize >> rttl >> rtos >> r.count;
	
	r.typ = typ;
	r.code = code;
	r.ttl = ttl;
	r.rttl = rttl;
	r.rtos = rtos;
	return in;
}

class yarrpFile
{
private:
	ifstream m_fh;
	istream *m_fhs;
	bool read_file;
	ipaddress m_source;
	bool m_usGranularity;
	uint8_t m_traceType;
	uint16_t m_maxTtl;
	uint16_t m_fillTtl;
	uint64_t m_fills;
	uint64_t m_pkts;
	string m_startTime;
	string m_endTime;
	uint8_t m_columns;
	bool readHeader();
	bool readTrailer();

public:
	yarrpFile() : m_usGranularity(false), m_columns(0) {};
	bool open(string fn);
	bool open(istream& input_stream);
	void close();
	bool nextRecord(yarrpRecord &r);
	ipaddress getSource() const;
	uint8_t getType() const;
	uint16_t getMaxTtl() const;
};

bool yarrpFile::open(string fn)
{
	cout << "Opening Yarrp file: " << fn << endl;
	m_fh.open(fn, ifstream::in);
	m_fhs = &m_fh;
	read_file = true;
	return readHeader();
}

bool yarrpFile::open(istream& input_stream)
{
	cout << "Opening input stream" << endl;
	ios_base::sync_with_stdio(false);
	m_fhs = &input_stream;
	read_file = false;
	return readHeader();
}

void yarrpFile::close()
{
	if (m_fh.is_open()) {
		m_fh.close();
	}
}

bool yarrpFile::readHeader()
{
	cout << "Reading Yarrp header" << endl;
	if (!m_fhs->good()) {
		cerr << "Input not good" << endl;
		return false;
	}
	string line;
	string hash;
	string param;
	int headerlines = 0;
	while (m_fhs->peek() == '#') {
		getline(*m_fhs, line);
		//cout << line << endl;
		replace(line.begin(), line.end(), ',', ' ');
		istringstream iss(line);
		iss >> hash >> param;
		if (param == "yarrp") {
			string ver;
			iss >> ver;
			if (ver == "v0.5") {
				cerr << "yrp2warts only works with version 0.6 or newer .yrp files!" << endl;
				return false;
			}
		}
		if (param == "Start:") {
			string dow, dom, month, year, tod, tz;
			//iss >> dow >> month >> dom >> tod >> year;
			iss >> dow >> dom >> month >> year >> tod >> tz;
			m_startTime = dow + " " + dom + " " + month + " " + year + " " + tod + " " + tz;
			//cout << m_startTime << endl;
		}
		if (param == "SourceIP:") {
			iss >> m_source;
			//cout << m_source << endl;
		}
		if (param == "Trace_Type:") {
			string type_name;
			iss >> type_name;
			m_traceType = tracetype_names[type_name];
			//cout << int(m_traceType) << endl;
		}
		//if (param == "Rate:") {}
		if (param == "Max_TTL:") {
			iss >> m_maxTtl;
			//cout << m_maxTtl << endl;
		}
		if (param == "Fill_Mode:") {
			iss >> m_fillTtl;
			//cout << m_maxTtl << " " << m_fillTtl << endl;
		}
		if (param == "RTT_Granularity:") {
			string trash, units;
			iss >> trash >> units;
			if (units == "us") {
				m_usGranularity = true;
			}
			//cout << m_usGranularity << endl;
		}
		if (param == "Output_Fields:") {
			string trash;
			m_columns = 0;
			while (iss >> trash) {
				m_columns++;
			}
			//cout << int(m_columns) << endl;
		}
		headerlines++;
	}
	if (headerlines > 0) {
		return true;
	}
	return false;
}

bool yarrpFile::readTrailer()
{
	cout << "Reading Yarrp trailer" << endl;
	if (!m_fh.good()) {
		return false;
	}
	string line;
	string hash;
	string param;
	int trailerlines = 0;
	while (m_fhs->peek() == '#') {
		getline(*m_fhs, line);
		//cout << line << endl;
		istringstream iss(line);
		iss >> hash >> param;
		if (param == "End:") {
			string dow, dom, month, year, tod, tz;
			iss >> dow >> dom >> month >> year >> tod >> tz;
			m_endTime = dow + " " + dom + " " + month + " " + year + " " + tod + " " + tz;
			//cout << m_endTime << endl;
		}
		if (param == "Fills:") {
			iss >> m_fills;
			//cout << m_fills << endl;
		}
		if (param == "Pkts:") {
			iss >> m_pkts;
			//cout << m_pkts << endl;
		}
		trailerlines++;
	}
	if (trailerlines > 0) {
		return true;
	}
	return false;
}

bool yarrpFile::nextRecord(yarrpRecord &r)
{
	string line;
	if (read_file) {
		if (!m_fh.good()) {
			return false;
		}
		if (m_fh.peek() == '#') {
			readTrailer();
			return false;
		}
		getline(m_fh, line);
	}
	else {
		if (!m_fhs->good()) {
			return false;
		}
		if (m_fhs->peek() == '#') {
			readTrailer();
			return false;
		}
		getline(*m_fhs, line);
	}
	//replace(line.begin(), line.end(), ',', ' ');
	istringstream iss(line);
	iss >> r;
	return true;
}

ipaddress yarrpFile::getSource() const
{
	return m_source;
}

uint8_t yarrpFile::getType() const
{
	return m_traceType;
}

uint16_t yarrpFile::getMaxTtl() const
{
	return m_maxTtl;
}

#endif