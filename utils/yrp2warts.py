#!/usr/bin/env python
#
# Copyright (c) 2016-2018, Robert Beverly
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
# Program:      $Id: yrp2warts.py $
# Author:       Robert Beverly <rbeverly@cmand.org>
# Description:  Convert yarrp output to binary warts
#
import struct
import operator
import socket
import math
import argparse
import sys
import time
from datetime import datetime
from yarrpfile import Yarrp
try:
  from sc_warts_writer import WartsWriter, WartsTrace
except:
  print "Requires sc_warts_writer.py from https://github.com/cmand/scamper/"
  sys.exit(-1)

try:
  import networkx as nx
except:
  pass

neighborhood = dict()

def yarrp_proc(yarrpfile, traces, timestamps, subnet=None):
  # if we're converting a subset of the targets within the yrp trace
  (net, mask) = (None, None)
  (t_min, t_max) = (-1, -1)
  if (subnet):
    (s,mask) = subnet.split('/')
    mask = 2**int(mask) - 1
    net = dottedQuadToNum(s) 
 
  yarrp = Yarrp(yarrpfile)
  while True:
    result = yarrp.next()
    if not result: break
    if not inNet(result['target'], net, mask):
      continue
    if result['target'] not in traces:
      traces[result['target']] = dict()
    # encode icmp type and code
    icmp_type_code = (result['typ'] << 8) + result['code']
    traces[result['target']][int(result['ttl'])] = {'addr' : result['hop'], 'rtt' : result['rtt'],
                                                    'ipid' : result['ipid'], 'probesize' : result['psize'],
                                                    'replysize' : result['rsize'], 'probettl' : result['ttl'],
                                                    'replyttl' : result['rttl'], 'tos' : result['rtos'],
                                                    'icmp' : icmp_type_code, 'hopflags' : 0x10}
                                                    # hopflags (SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
    timestamps[result['target']] = result['sec'] + (result['usec']/1000000.0)
    if t_min <= 0: t_min = timestamps[result['target']]
    if t_max <= 0: t_max = timestamps[result['target']]
    if timestamps[result['target']] < t_min: t_min = timestamps[result['target']]
    if timestamps[result['target']] > t_max: t_max = timestamps[result['target']]
  return (yarrp.vantage_point, yarrp.tracetype, yarrp.maxttl, t_min, t_max)


# make_hops function that takes the networkx neighborhood graph to fill
# in missing hops of the neighborhood 
def make_hops_nbr(hops, G):
  maxttl = max(hops)
  minttl = min(hops)
  path = None
  first_nbr_hop = None
  if G.has_node(hops[minttl][2]):
    first_nbr_hop = hops[minttl][2]
    print "Found path to TTL=min node."
  if 8 in hops:
    if G.has_node(hops[8][2]):
      first_nbr_hop = hops[8][2]
      print "Found path to TTL=8 node."

  if first_nbr_hop:
    print "computing shortest path to:", first_nbr_hop
    try:
      path = nx.shortest_path(G, source='src', target=first_nbr_hop)
      print "got path:", path
    except nx.NetworkXNoPath, e:
      print e
  return (path, maxttl)

def dottedQuadToNum(ip):
  "convert decimal dotted quad string to long integer"
  return struct.unpack('I',socket.inet_aton(ip))[0]

def inNet(ip, subnet, mask):
  if not subnet:
    return True
  nip = dottedQuadToNum(ip)
  if (nip & mask == subnet): 
    return True
  else:
    return False

def construct_nbrhood(inyrp):
  #import matplotlib.pyplot as plt
  G = nx.Graph()
  traces = dict()
  timestamps = dict()
  yarrp_proc(inyrp, traces, timestamps)
  for target in traces:
    #print "Target:", target
    hops = traces[target]
    (last_hop, last_ttl) = ('src', 0)
    for ttl in sorted(hops):
      #print "\t", ttl, hops[ttl]['addr']
      if hop not in neighborhood:
        neighborhood[hop] = hops[ttl]
      G.add_node(hop)
      if last_ttl == ttl - 1:
        G.add_edge(last_hop, hop)
      (last_hop, last_ttl) = (hop, ttl)
  return G
  #nx.draw(G, with_labels=True)
  #plt.savefig("go.pdf")

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--input", required=True, help="input yarrp file")
  parser.add_argument("-o", "--output", required=True, help="output warts file")
  parser.add_argument("-s", "--subnet", help="subnets to convert")
  parser.add_argument("-n", "--neighborhood", help="neighborhood yarrp file")
  args = parser.parse_args()

  if args.neighborhood:
    print "Reconstructing neighborhood"
    G = construct_nbrhood(args.neighborhood)
  
  # read and collect yarrp results into:
  # - traces[target][ttl] = hop_vals
  traces = dict()
  timestamps = dict()
  (vantage_point, tracetype, maxttl, t_min, t_max) = yarrp_proc(args.input, traces, timestamps, args.subnet)

  # open warts output
  w = WartsWriter(args.output)
  w.write_list(1, 1, 'yarrp')
  w.write_cycle(1, 1, 1, int(t_min))
  processed = 0
  print ">>", datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
  tr = WartsTrace()

  # write each collected trace
  for target in traces:
    hops = traces[target]
    probehop = len(hops) if len(hops) > maxttl else maxttl
    if max(hops) > probehop: probehop = max(hops)
    probehop = max(hops) if max(hops) > probehop else probehop
    tr.add({'listid' : 1, 'srcport' : 1234, 'dstport' : 80,
             'srcaddr' : vantage_point, 'dstaddr' : target,
             'timeval' : timestamps[target], 'attempts' : 1,
             'tracetyp' : tracetype, 'probehop' : probehop,
             'probesent' : maxttl, 'firsttl' : 1})

    if not args.neighborhood:
      for ttl in sorted(hops): 
        tr.add_reply(hops[ttl])
    else:
      (path, maxttl) = make_hops_nbr(hops, G)
      for ttl in range(1,maxttl+1):
        if ttl in hops:
          tr.add_reply(hops[ttl])
        elif path:
          if ttl < len(path):
            hop = path[ttl]
        else:
          continue
    w.write_object(tr)
    processed+=1

  # finish
  w.write_cycle_stop(1, int(t_max))
  print ">> Processed: %d targets" % processed
  print ">>", datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":
  main()
