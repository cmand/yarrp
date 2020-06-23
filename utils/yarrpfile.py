#!/usr/bin/env python
#
# Copyright (c) 2016-2019, Robert Beverly
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AN
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Program:      $Id: yarrpfile.py 1551 2015-02-11 14:14:09Z rbeverly $
# Author:       Robert Beverly <rbeverly@cmand.org>
# Description:  Python class to process Yarrp output
#
import bz2
import gzip

# from yarrp/src/trace.h
traceroute_type = ["ICMP6", "ICMP", "UDP6", "UDP", "TCP6_SYN", "TCP_SYN", "TCP6_ACK", "TCP_ACK"]

# from scamper/trace/scamper_trace.h
tracetypemap = {'ICMP' : 0x04, 'ICMP6' : 0x04, 
                'UDP'  : 0x05, 'UDP6'  : 0x05,
                'TCP_SYN' : 0x03, 'TCP6_SYN' : 0x03,
                'TCP_ACK' : 0x06, 'TCP6_ACK' : 0x06 }

class Yarrp:
  def __init__(self, yarrpfile, verbose=False):
    self.yarrpfile = yarrpfile
    self.verbose = verbose
    self.vantage_point = "undefined"
    self.us_granularity = False
    self.tracetype = None
    self.maxttl = -1
    self.columns = 0
    self.fillttl = 0
    self.fills = 0
    self.packets = 0
    self.start = "unknown"
    self.end = "unknown"
    self.open()

  def open(self):
    # try reading as a bz2 file
    try:
      self.fd = bz2.BZ2File(self.yarrpfile, 'rb')
      self.fd.read(1)
      self.fd = bz2.BZ2File(self.yarrpfile, 'rb')
      return
    except IOError, e:
      pass
    # try reading as a gzip file
    try:
      self.fd = gzip.open(self.yarrpfile, 'rb')
      self.fd.read(1)
      self.fd = gzip.open(self.yarrpfile, 'rb')
      return
    except IOError, e:
      pass
    # try reading as uncompressed
    self.fd = open(self.yarrpfile, 'rb')

  def next(self):
    assert(self.fd)  
    line = self.fd.readline()
    if len(line) == 0:
      return False
    if line[0] == '#' and line.find(':') != -1:
      try:
        (key, value) = line[2:].strip().split(': ')
        #print "Key:", key, "Value:", value
        if key == "Trace_Type":
          self.tracetype = tracetypemap[value]
        if key == "SourceIP":
          self.vantage_point = value
        if key == "RTT_Granularity":
          if value == "us":
            self.us_granularity = True
          else:
            self.us_granularity = False
        if key == "Max_TTL":
          self.maxttl = int(value)
        if key == "Start":
          self.start = value
        if key == "Fill_Mode":
          self.filttl = int(value)
        if key == "Fills":
          self.fills = int(value)
        if key == 'Pkts':
          self.packets = int(value)
      except Exception, e:
        print "Error (next):", e 
        print "line:", line
        pass
      return self.next()
    fields = line.strip().split()
    r = dict()
    if not self.columns: self.columns = len(fields)
    if len(fields) != self.columns:
      return False
    try:
      # new format
      if self.columns == 14:
          (r['target'], r['sec'], r['usec'], r['typ'], r['code'], 
           r['ttl'], r['hop'], r['rtt'], r['ipid'], r['psize'], 
           r['rsize'], r['rttl'], r['rtos'], r['count']) = fields
      for field in ['sec', 'usec', 'typ', 'code', 'ttl', 'rttl', 'rtt', 'psize', 'rsize', 'ipid', 'rtos']:
        r[field] = int(r[field])
      if 'count' in r:
        r['count'] = int(r['count'])
      # Ugh, occassionally the recorded rtt is impossible...
      rtt = r['rtt']
      if self.us_granularity == True: 
        rtt = rtt/1000.0
      if rtt < 0 or rtt > 4294967295: rtt = 0
      r['rtt'] = rtt
    except ValueError, e:
      print "ERR:", e, ":", line, "expecting:", self.columns
    return r
