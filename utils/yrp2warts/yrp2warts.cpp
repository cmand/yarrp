/****************************************************************************
 * Copyright (c) 2016-2019 Justin P. Rohrer <jprohrer@tancad.org> 
 * All rights reserved.  
 *
 * Program:     $Id: yrp2warts.cpp $
 * Description: Convert Yarrp output files (https://www.cmand.org/yarrp) to 
 *              warts files (https://www.caida.org/tools/measurement/scamper/)
 *              indent -i4 -nfbs -sob -nut -ldi1 yrp2warts.cpp
 *
 * Attribution: R. Beverly, "Yarrp'ing the Internet: Randomized High-Speed 
 *              Active Topology Discovery", Proceedings of the ACM SIGCOMM 
 *              Internet Measurement Conference, November, 2016
 ***************************************************************************/
 
#include <unordered_map>
#include <sys/time.h>
#include <iomanip>
#include <memory>
#include "ipaddress.hpp"
#include "yarrpfile.hpp"
extern "C" {
	#include "scamper_file.h"
	#include "scamper_addr.h"
	#include "scamper_list.h"
	#include "scamper_trace.h"
}

using namespace std;
using namespace ip;

string infile_name = "";
string outfile_name = "";
bool read_stdin = false;

void usage(char *prog) {
	cout << "Usage:" << endl
		 << " $ " << prog << " -i input.yrp -o output.warts" << endl
		 << " $ bzip2 -dc input.yrp.bz2 | " << prog << " -s -o output.warts" << endl
		 << "  -i, --input             Input Yarrp file" << endl
		 << "  -o, --output            Output Warts file (.warts)" << endl
		 << "  -s, --stdin             Read piped input from STIDN" << endl
		 << "  -h, --help              Show this message" << endl
		 << endl;
	exit(-1);
}

void parse_opts(int argc, char **argv) {
	if (argc <= 3) {
		usage(argv[0]);
	}
	char c;
	int opt_index = 1;
	while (opt_index < argc-1) {
		c = argv[opt_index][1];
		switch (c) {
		  case 'i':
			infile_name = argv[++opt_index];
			break;
		  case 'o':
			outfile_name = argv[++opt_index];
			break;
		  case 's':
			read_stdin = true;
			break;
		  case 'h':
		  default:
			usage(argv[0]);
		}
		opt_index++;
	}
}

struct yrpStats {
	ipaddress vantage_point;
	uint8_t tracetype;
	uint16_t maxttl;
	double t_min;
	double t_max;
};

struct hop {
	ipaddress addr;
	uint32_t sec;
	uint32_t usec;
	uint32_t rtt;
	uint16_t ipid;
	uint16_t psize;
	uint16_t rsize;
	uint8_t ttl;
	uint8_t rttl;
	uint8_t rtos;
	//uint16_t icmp_tc;
	uint8_t icmp_type;
	uint8_t icmp_code;
	//uint8_t hopflags = 0x10;
	hop& operator= (const yarrpRecord &r)
	{
		addr = r.hop;
		sec = r.sec;
		usec = r.usec;
		rtt = r.rtt;
		ipid = r.ipid;
		psize = r.psize;
		rsize = r.rsize;
		ttl = r.ttl;
		rttl = r.rttl;
		rtos = r.rtos;
		//icmp_tc = 11;  // [TODO] FixMe
		icmp_type = r.typ;
		icmp_code = r.code;
		return *this;
	}
};

ostream& operator<< (ostream& os, const hop& h)
{
    return os << h.addr << " " << h.sec << " " << h.usec << " " << h.rtt << " " << h.ipid << " " << h.psize << " " << h.rsize << " " << uint16_t(h.ttl) << " " << uint16_t(h.rttl) << " " << uint16_t(h.rtos) << " " << uint16_t(h.icmp_type) << " " << uint16_t(h.icmp_code);	// << " " << uint16_t(h.hopflags);
}

bool operator<(const hop& h1, const hop& h2) {
	return h1.ttl < h2.ttl;
}

bool operator==(const hop& h1, const hop& h2) {
	return h1.ttl == h2.ttl;
}

scamper_addr* ip2scamper_addr(ipaddress &ip) {
	uint8_t sat = 0;
	void *addr;
	if (ip.version() == 4) {
		sat = SCAMPER_ADDR_TYPE_IPV4;
		//shared_ptr<uint32_t> ipv4 = ip.get4();
		//addr = ipv4.get();
		addr = ip.get4().get();
	}
	else if (ip.version() == 6) {
		sat = SCAMPER_ADDR_TYPE_IPV6;
		//shared_ptr<array<uint8_t,16> > ipv6 = ip.get6();
		//addr = ipv6.get();
		addr = ip.get6().get();
	}
	else {
		//cerr << ip << endl;
		cerr << "Not an IP address!" << endl;
		exit(1);
	}
	scamper_addr *sa;
	if ((sa = scamper_addr_alloc(sat, addr)) == NULL) {
		cerr << "Could not convert address!" << endl;
		exit(1);
	}
	//sa->type = ip.version();
	//sa->addr = ip.get().c_str();
	//sa->addr = &ip.get()[0];
	return sa;
}

yrpStats yarrp_proc(string yarrpfile, unordered_map<ipaddress, vector<hop> > &traces) {
	yarrpFile yrp;
	yarrpRecord r;
	yrpStats s;
	s.t_min = 0;
	s.t_max = 0;
	if (read_stdin) {
		if (!yrp.open(std::cin)) {
			cerr << "Failed to open input stream" << endl;
			exit(1);
		}
		std::cin.tie(nullptr);
	}
	else {
		if (!yrp.open(yarrpfile)) {
			cerr << "Failed to open input file: " << yarrpfile << endl;
			exit(1);
		}
	}
	double timestamp = 0.0;
	uint64_t yrp_count = 0;
	while (yrp.nextRecord(r)) {
		//cout << r << endl;
		hop this_hop;
		this_hop = r;
		//cout << "addr: " << this_hop.addr << " rtt: " << this_hop.rtt << " ipid: " << this_hop.ipid << " psize: " << this_hop.psize << " rsize: " << this_hop.rsize << " ttl: " << uint16_t(this_hop.ttl) << " rttl: " << uint16_t(this_hop.rttl) << " rtos: " << uint16_t(this_hop.rtos) << " icmp_type: " << uint16_t(this_hop.icmp_type) << " icmp_code: " << uint16_t(this_hop.icmp_code) << endl;	//" hopflags: " << uint16_t(this_hop.hopflags) << endl;
		//cout << this_hop << endl;
		//traces[r.target][r.ttl] = this_hop;
		//if (traces[r.target].size() < 255) {
			traces[r.target].push_back(this_hop);	// scamper_trace must be <= 255 hops long
		//}
		timestamp = r.sec + (r.usec / 1000000.0);
		//timestamps[r.target] = timestamp;
		//cout << timestamps[r.target] << endl;
		if (s.t_min <= 0) { s.t_min = timestamp; }
		//if (s.t_max <= 0) { s.t_max = timestamps[r.target]; }
	    if (timestamp < s.t_min) { s.t_min = timestamp; }
	    if (timestamp > s.t_max) { s.t_max = timestamp; }
		yrp_count++;
	}
	s.vantage_point = yrp.getSource();
	s.tracetype = yrp.getType();
	s.maxttl = yrp.getMaxTtl();
	cout << "Processed " << yrp_count << " Yarrp records" << endl;
	return s;
}

void useage ()
{
	cout << "$ ./yrp2warts <.yrp input file> <.warts output file>" << endl;
}

int main(int argc, char* argv[])
{
	ios_base::sync_with_stdio(false);
	parse_opts(argc, argv);
	unordered_map<ipaddress, vector<hop> > traces;
	//unordered_map<ipaddress, double> timestamps;
	yrpStats stats = yarrp_proc(infile_name, traces);
	cout << "Created " << traces.size() << " traces" << endl;
	cout << "Opening output file " << outfile_name << endl;
	scamper_file *outfile = NULL;
    if ((outfile = scamper_file_open(&outfile_name[0], 'w', (char *)"warts")) == NULL) {
		cerr << "Failed to open output file: " << outfile_name << endl;
		return -1;
	}
	scamper_list *list = scamper_list_alloc(1, "yarrp", "yarrp list", "yarrp-1");
	cout << "Writing cycle start" << endl;
	scamper_cycle *cycle = scamper_cycle_alloc(list);
	cycle->id = 1;
	cycle->start_time = stats.t_min;
	cycle->stop_time = stats.t_max;
	uint64_t target_count = 0;
	uint8_t max_dup_ttl_cnt = 0;
	if (scamper_file_write_cycle_start(outfile, cycle) != 0) { return -1; }
	//scamper_cycle_free(cycle);
	for (unordered_map<ipaddress, vector<hop> >::iterator iter = traces.begin(); iter != traces.end(); ++iter) {
		ipaddress target = iter->first;
		vector<hop> hops = iter->second;
		sort(hops.begin(), hops.end());
		if (hops.size() > 255){
			hops.resize(255);	// scamper_trace can't write > 256 hops
		}
		//vector<hop>::iterator thishop = unique(hops.begin(), hops.end());
		vector<hop>::iterator thishop = hops.begin();
		//hops.resize(distance(hops.begin(), thishop));
		//cout << "Processing trace to " << target << endl;
		uint16_t probehop;
		/*if (hops.size() > stats.maxttl) {
			probehop = hops.size();
		}
		else {
			probehop = stats.maxttl;
		}*/
		probehop = hops.size();
		//cout << "This trace has " << probehop << " hops." << endl;
		double trace_timestamp = 0x1.fffffffffffffp+1023;
		struct timeval tv;
		uint8_t last_ttl = 0;
		uint16_t dup_ttl_cnt = 1;
		for (thishop = hops.begin(); thishop != hops.end(); ++thishop) {
			/*if (thishop->ttl > probehop) {
				probehop = thishop->ttl;
			}*/
			if (thishop->ttl == last_ttl) {
				dup_ttl_cnt++;
			}
			last_ttl = thishop->ttl;
			//hop thishop = *iter;
			double hop_timestamp = thishop->sec + (thishop->usec / 1000000.0);
			if (hop_timestamp < trace_timestamp) {
				trace_timestamp = hop_timestamp;
				tv.tv_sec = thishop->sec;
				tv.tv_usec = thishop->usec;
			}
			//cout << setprecision (17) << hop_timestamp << " " << trace_timestamp << endl;
		}
		if (dup_ttl_cnt > max_dup_ttl_cnt) {
			//cout << "There were " << dup_ttl_cnt << " duplicate TTLs." << endl;
			max_dup_ttl_cnt = dup_ttl_cnt;
		}
		scamper_trace *trace = scamper_trace_alloc();
		trace->list = list;
		//trace->cycle = cycle;
		trace->src = ip2scamper_addr(stats.vantage_point);
		trace->dst = ip2scamper_addr(target);
		//double ts = timestamps[target];
		//cout << setprecision (17) << ts << endl;
		trace->start = tv;
		trace->hop_count = probehop;
		trace->probec = stats.maxttl;
		trace->type = stats.tracetype;
		trace->attempts = 1;
		trace->firsthop = 1;
		trace->sport = 1234;
		trace->dport = 80;
		//cout << "Allocating trace" << endl;
		scamper_trace_hops_alloc(trace, probehop);
		uint16_t hopcnt = 0;
		for (vector<hop>::iterator thishop = hops.begin(); thishop != hops.end(); ++thishop) {
			//cout << uint16_t(thishop->ttl) << ", ";
			//cout << thishop->addr << ", ";
			trace->hops[hopcnt] = scamper_trace_hop_alloc();
			trace->hops[hopcnt]->hop_addr = ip2scamper_addr(thishop->addr);
			struct timeval rttv;
			rttv.tv_sec = (uint32_t) (thishop->rtt / 1000000.0);
			rttv.tv_usec = thishop->rtt - (rttv.tv_sec * 1000000);
			trace->hops[hopcnt]->hop_rtt = rttv;
			//trace->hops[hopcnt]->hop_flags = thishop.hopflags;
			trace->hops[hopcnt]->hop_flags = 0x10;
			trace->hops[hopcnt]->hop_probe_id = 0;
			trace->hops[hopcnt]->hop_probe_ttl = thishop->ttl;
			trace->hops[hopcnt]->hop_probe_size = thishop->psize;
			trace->hops[hopcnt]->hop_reply_ttl = thishop->rttl;
			trace->hops[hopcnt]->hop_reply_tos = thishop->rtos;
			trace->hops[hopcnt]->hop_reply_size = thishop->rsize;
			trace->hops[hopcnt]->hop_reply_ipid = thishop->ipid;
			trace->hops[hopcnt]->hop_icmp_type = thishop->icmp_type;
			trace->hops[hopcnt]->hop_icmp_code = thishop->icmp_code;
			hopcnt++;
		}
		//cout << endl << "Writing trace" << endl;
		if (scamper_file_write_trace(outfile, trace) != 0) { return -1; }
		//cout << "Trace written" << endl;
		//scamper_trace_free(trace);
		target_count++;
	}
	cout << "Writing cycle stop" << endl;
    if (scamper_file_write_cycle_stop(outfile, cycle) != 0) { return -1; }
	//cout << "Free cycle" << endl;
	//scamper_cycle_free(cycle);
	//cout << "Free list" << endl;
	//scamper_list_free(list);
	//cout << "Closing .warts file";
	//scamper_file_close(outfile);
	return 0;
}
