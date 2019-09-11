/****************************************************************************
 * Copyright (c) 2016-2019 Justin P. Rohrer <jprohrer@tancad.org> 
 * All rights reserved.  
 *
 * Program:     $Id: ipaddress.hpp $
 * Description: Class to store an IPv4 or IPv6 address
 *
 ***************************************************************************/

#ifndef IPADDRESS_INCLUDED
#define IPADDRESS_INCLUDED

#include <iostream>
#include <string>
#include <array>
#include <arpa/inet.h>

//using namespace std;
namespace ip
{

/*struct free_deleter
{
    template <typename T>
    void operator()(T *p) const {
        //free(const_cast<remove_const_t<T>*>(p));
    }
};*/

class ipaddress
{
private:
	//unique_ptr<in_addr, free_deleter> m_v4addr;
	//unique_ptr<in6_addr, free_deleter> m_v6addr;
	//shared_ptr<in_addr> m_v4addr;
	std::shared_ptr<uint32_t> m_v4addr;
	//shared_ptr<uint32_t> m_v4addr;
	//shared_ptr<in6_addr> m_v6addr;
	std::shared_ptr<std::array<uint8_t,16> > m_v6addr;

public:
	//ipaddress() : m_v4addr(NULL), m_v6addr(NULL) {};
	ipaddress() {};
	//ipaddress(string addr) : m_v4addr(NULL), m_v6addr(NULL)
	ipaddress(std::string addr)
	{
		set(addr);
	}
	int8_t set(std::string addr)
	{
		if (addr.length() > 15 || addr.find(':') != std::string::npos) {
			//m_v6addr = (in6_addr *) malloc(sizeof(in6_addr));
			//m_v6addr.reset((in6_addr *) malloc(sizeof(in6_addr)));
			//m_v6addr = make_unique<in6_addr>();
            //m_v6addr = unique_ptr<in6_addr, free_deleter>((in6_addr *) malloc(sizeof(in6_addr)), free_deleter());
            //m_v6addr = unique_ptr<in6_addr, free_deleter>(new in6_addr, free_deleter());
			//m_v6addr = shared_ptr<in6_addr>((in6_addr *) malloc(sizeof(in6_addr)), free);
			//m_v6addr = make_shared<in6_addr>();
			m_v6addr = std::make_shared<std::array<uint8_t,16> >();
			in6_addr temp6_addr;
			int result = inet_pton(AF_INET6, addr.c_str(), &temp6_addr);
			//cout << "set: ";
			for (int i = 0; i<16; i++) {
				m_v6addr->at(i) = temp6_addr.s6_addr[i];
				//cout << int(m_v6addr->at(i));
			}
			//cout << endl;
			//free(temp6_addr);
			return result;
		}
		//m_v4addr = (in_addr *) malloc(sizeof(in_addr));
		//m_v4addr.reset((in_addr *) malloc(sizeof(in_addr)));
		//m_v4addr = make_unique<in_addr>();
        //m_v4addr = unique_ptr<in_addr, free_deleter>((in_addr *) malloc(sizeof(in_addr)), free_deleter());
        //m_v4addr = unique_ptr<in_addr, free_deleter>(new in_addr, free_deleter());
		//m_v4addr = shared_ptr<in_addr>((in_addr *) malloc(sizeof(in_addr)), free);
		//m_v4addr = make_shared<in_addr>();
		in_addr temp_addr;
		int result = inet_pton(AF_INET, addr.c_str(), &temp_addr);
		m_v4addr = std::make_shared<uint32_t>(temp_addr.s_addr);
		return result;
	}
	uint8_t version() const
	{
		if (m_v4addr) {
			return 4;
		}
		if (m_v6addr) {
			return 6;
		}
		return 0;
	}
	std::string tostr() const
	{
		if (m_v4addr) {
			in_addr temp_addr;
			temp_addr.s_addr = *m_v4addr;
			char addrstring[INET_ADDRSTRLEN];
			return std::string(inet_ntop(AF_INET, &temp_addr, addrstring, INET_ADDRSTRLEN));
		}
		if (m_v6addr) {
			in6_addr temp6_addr;
			//cout << "get: ";
 			for (int i = 0; i<16; i++) {
				temp6_addr.s6_addr[i] = m_v6addr->at(i);
				//cout << int(temp6_addr.s6_addr[i]);
			}
			//cout << endl;
			char addr6string[INET6_ADDRSTRLEN];
			return std::string(inet_ntop(AF_INET6, &temp6_addr, addr6string, INET6_ADDRSTRLEN));
		}
		return std::string();
	}
	std::size_t hash() const
	{
		if (m_v4addr) {
			return std::hash<uint32_t>()(*m_v4addr);
		}
		if (m_v6addr) {
			//return std::hash<std::array<uint8_t,16> >()(*m_v6addr);
			uint64_t mangle_h = (*m_v6addr)[8];
			uint64_t mangle_l = (*m_v6addr)[0];
			for (int i=1; i<8; i++) {
				mangle_h <<= 8;
				mangle_h ^= (*m_v6addr)[i+8];
				mangle_l <<= 8;
				mangle_l ^= (*m_v6addr)[i];
			}
			return std::hash<uint64_t>()(mangle_h ^ mangle_l);
		}
		return 0;
	}
	/*template <typename T>
	const shared_ptr<T>* get() const
	{
		if (m_v4addr) {
			return m_v4addr;
		}
		if (m_v6addr) {
			return m_v6addr;
		}
		cerr << "No addr set" << endl;
		exit(1);
	}*/
	std::shared_ptr<uint32_t> get4() const
	{
		if (m_v4addr) {
			return m_v4addr;
		}
		std::cerr << "No v4 addr set" << std::endl;
		exit(1);
	}
	std::shared_ptr<std::array<uint8_t,16> > get6() const
	{
		if (m_v6addr) {
			return m_v6addr;
		}
		std::cerr << "No v6 addr set" << std::endl;
		exit(1);
	}
/*	ipaddress& operator= (const ipaddress &ip)
	{
		if (ip.m_v4addr) {
			if (m_v6addr) {
				m_v6addr.release();
			}
			m_v4addr = unique_ptr<in_addr, free_deleter>((in_addr *) malloc(sizeof(in_addr)), free_deleter());
			m_v4addr->s_addr = ip.m_v4addr->s_addr;
		}
		if (ip.m_v6addr) {
			if (m_v4addr) {
				m_v4addr.release();
			}
			m_v6addr = unique_ptr<in6_addr, free_deleter>((in6_addr *) malloc(sizeof(in6_addr)), free_deleter());
			m_v6addr->s6_addr = ip.m_v6addr->s6_addr;
		}
		return *this;
	} */
	//friend ostream& operator<< (ostream& os, const ipaddress& ip);
	//friend istream& operator>> (istream &in, ipaddress &ip);
	friend bool operator> (const ipaddress &ip1, const ipaddress &ip2);
	friend bool operator< (const ipaddress &ip1, const ipaddress &ip2);
	bool operator== (const ipaddress &other) const
	{
		if (m_v4addr && other.m_v4addr) {
			return *m_v4addr == *other.m_v4addr;
		}
		if (m_v6addr && other.m_v6addr) {
			return *m_v6addr == *other.m_v6addr;
		}
		return false;
	}
};

std::ostream& operator<< (std::ostream& os, const ipaddress& ip)
{
	return os << ip.tostr();
}

std::istream& operator>> (std::istream &in, ipaddress &ip)
{
	std::string addr;
	in >> addr;
	ip.set(addr);
	return in;
}

bool operator> (const ipaddress &ip1, const ipaddress &ip2)
{
	if (ip1.m_v4addr && ip2.m_v4addr) {
		//cout << "Compare> v4" << endl;
    	return *ip1.m_v4addr > *ip2.m_v4addr;
	}
	if (ip1.m_v6addr && ip2.m_v6addr) {
		//cout << "Compare> v6" << endl;
		//return ip1.m_v6addr->s6_addr > ip2.m_v6addr->s6_addr;
		return *ip1.m_v6addr > *ip2.m_v6addr;
	}
	return false;
}
  
bool operator< (const ipaddress &ip1, const ipaddress &ip2)
{
	if (ip1.m_v4addr && ip2.m_v4addr) {
		//cout << "Compare< v4" << endl;
		//cout << *ip2.m_v4addr << endl;
		//cout << *ip1.m_v4addr << endl;
    	return *ip1.m_v4addr < *ip2.m_v4addr;
	}
	if (ip1.m_v6addr && ip2.m_v6addr) {
		//cout << "Compare< v6" << endl;
		//return ip1.m_v6addr->s6_addr < ip2.m_v6addr->s6_addr;
		return *ip1.m_v6addr < *ip2.m_v6addr;
	}
	return false;
}
}	// End namespace ip

namespace std {
template <>
struct hash<ip::ipaddress>
{
	std::size_t operator()(const ip::ipaddress& ip) const
	{
		using std::size_t;
		using std::hash;
		using std::string;
		
		//return (hash<string>()(ip.tostr()));
		return ip.hash();
	}
};
}	// End namespace std

#endif
