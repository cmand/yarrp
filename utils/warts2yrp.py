#!/usr/bin/env python3
#
# Copyright (c) 2018, Robert Beverly
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
# Program:      $Id: warts2yrp.py $
# Author:       Robert Beverly <rbeverly@cmand.org>
# Description:  Convert binary warts to yarrp output
#
import argparse
import sys
import time
from datetime import datetime
try:
  from sc_warts import WartsReader
except:
  print("Requires sc_warts.py from https://github.com/cmand/scamper/")
  sys.exit(-1)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--input", required=True, help="input warts file")
  parser.add_argument("-o", "--output", required=True, help="output yrp file")
  args = parser.parse_args()

  w = WartsReader(args.input, verbose=False)
  fd = open(args.output, 'w')

  print(">>", datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
  # target, sec, usec, type, code, ttl, hop, rtt, ipid, psize, rsize, rttl, rtos, count
  count = 0
  while True:
    (flags, hops) = w.next()
    if flags == False: break
    #print flags
    target = flags['dstaddr']
    n = flags['probesent']
    for hop in hops:
      count+=1
      (sec, usec) = (0,0)
      (typ, code) = (hop['icmp-type'], hop['icmp-code'])
      router = hop['addr']
      (ttl, rttl) = (hop['probettl'], hop['replyttl'])
      (ipid, rtt) = (hop['ipid'], hop['rtt'])
      (psize, rsize) = (hop['probesize'], hop['replysize'])
      rtos = hop['tos']
      yrpline = [target, sec, usec, typ, code, ttl, router, rtt, ipid, psize, rsize, rttl, rtos, count]
      line = " ".join([str(x) for x in yrpline])
      fd.write(line + "\n")
    probes_with_no_response = flags['probesent'] - len(hops)
    count += probes_with_no_response 

  fd.close()
  print(">> Processed: %d probes" % count)
  print(">>", datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))

if __name__ == "__main__":
  main()
