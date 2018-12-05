#!/usr/bin/env python
#
# Copyright (c) 2015-2018, Robert Beverly
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
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
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
# Program:      $Id: sc_warts_writer.py $
# Author:       Robert Beverly <rbeverly@cmand.org>
# Description:  Write binary warts capture files per warts.5
#
import struct
import socket
from math import ceil
import sys
from os.path import isfile
from bz2 import BZ2File

obj_type = {'NONE' : 0x00, 'LIST' : 0x01, 'CYCLE' : 0x03, 
            'STOP' : 0x04, 'TRACE' : 0x06, 'PING' : 0x07, 
            'MAGIC' : 0x1205}

def pack_uint32_t(b):
  return (struct.pack('!I', b))

def pack_uint16_t(b):
  return (struct.pack('!H', b))

def pack_uint8_t(b):
  return (struct.pack('B', b))

def is_ipv6(addr):
  try: 
    socket.inet_pton(socket.AF_INET, addr)
    return False
  except socket.error, e:
    return True

def pack_referenced_address(addrid):
  return (struct.pack('!BI', 0, addrid))

def pack_unreferenced_address(addr):
  if is_ipv6(addr):
    buf = pack_uint8_t(16)
    buf += pack_uint8_t(0x02) # ipv6
    buf += socket.inet_pton(socket.AF_INET6, addr)
  else:
    buf = pack_uint8_t(4)
    buf += pack_uint8_t(0x01) # ipv4
    buf += socket.inet_pton(socket.AF_INET, addr)
  return buf

def pack_timestamp(val):
  sec = int(val)
  usec = (val - sec) * 1000000.0
  buf = pack_uint32_t(sec) + pack_uint32_t(usec)
  return buf

class WartsBaseObject(object):
  def __init__(self, objtype=obj_type['NONE']):
    self.typ = objtype
    self.buf = ""
    self.setflags = dict()
    self.referenced_addresses = dict()
    self.last_referenced_address_id = -1
    self.reply = None
    self.flags = []

  def add(self, flags):
    for flag in flags:
      self.setflags[flag] = flags[flag]  
    self.make_flags()

  def add_reply(self, flags):
    if not self.reply: 
      if self.typ == obj_type['TRACE']:
        self.reply = WartsTraceHop()
      elif self.typ == obj_type['PING']:
        self.reply = WartsPingReply()
      self.reply.update_ref(self.referenced_addresses, self.last_referenced_address_id)
    self.reply.add(flags)
    self.reply.count+=1

  def update_ref(self, _referenced_address, _last_referenced_address_id):
    self.referenced_addresses = _referenced_address
    self.last_referenced_address_id = _last_referenced_address_id

  def reset(self):
    self.buf = ""
    self.setflags = dict()
    self.referenced_addresses = dict()
    self.last_referenced_address_id = -1
    if self.reply:
      del self.reply
      self.reply = None

  def pack_address(self, addr):
    if addr in self.referenced_addresses:
      #print "returning RA", self.referenced_addresses[addr], "for:", addr
      return pack_referenced_address(self.referenced_addresses[addr])
    else:
      self.last_referenced_address_id+=1 
      #print "creating new addrid:", self.last_referenced_address_id, "for:", addr
      self.referenced_addresses[addr] = self.last_referenced_address_id
      return pack_unreferenced_address(addr)
 
  def make_flags(self):
    #print "total flags:", len(self.flags)
    num_flag_bytes = int(ceil(len(self.flags) / 7.0))
    #print "flag bytes:", num_flag_bytes
    flags = [0]*num_flag_bytes
    flag_buffer = ""
    for i in range(num_flag_bytes-1):
      flags[i] = 0x80
    for num, flag in enumerate(self.flags):
      (flag_name, flag_method) = flag
      if flag_name in self.setflags:
        block = num / 7
        flags[block] += 2**(num % 7) 
        try:
          b = flag_method(self.setflags[flag_name])
        except Exception, e:
          print "threw:", e, "on:", flag_name, "using:", flag_method
          exit(-1)
        hb = [hex(ord(z)) for z in b]
        #print "Writing Flag:", num, "name:", flag_name, "value:", self.setflags[flag_name], "bytes:", hb
        flag_buffer += b
    for b in flags:
      #print "Flag Byte:", hex(b)
      self.buf += pack_uint8_t(b)
    self.buf += pack_uint16_t(len(flag_buffer))
    self.buf += flag_buffer

  def finalize(self):
    pass


class WartsPing(WartsBaseObject):
  def __init__(self):
    super(WartsPing, self).__init__(obj_type['PING'])
    self.flags = [
     ('listid', pack_uint32_t),
     ('cycleid', pack_uint32_t),
     ('srcipid', None),
     ('dstipid', None),
     ('timeval', pack_timestamp),
     ('stopreas', pack_uint8_t),
     ('stopdata', pack_uint8_t),
     ('datalen', pack_uint16_t),
     ('data', pack_uint8_t),
     ('pcount', pack_uint16_t),
     ('size', pack_uint16_t),
     ('wait', pack_uint8_t),
     ('ttl', pack_uint8_t),
     ('rcount', pack_uint16_t),
     ('psent', pack_uint16_t),
     ('method', pack_uint8_t),
     ('sport', pack_uint16_t),
     ('dport', pack_uint16_t),
     ('userid', pack_uint32_t),
     ('srcaddr', self.pack_address),
     ('dstaddr', self.pack_address),
     ('flags', pack_uint8_t),
     ('tos', pack_uint8_t),
     ('tsps', None),
     ('icmpsum', pack_uint16_t),
     ('pmtu', pack_uint16_t),
     ('timeout', pack_uint8_t),
     ('waitus', pack_uint32_t),
    ]

  def finalize(self):
    if self.reply:
      self.buf += pack_uint16_t(self.reply.count)
      self.buf += self.reply.buf
    else:
      self.buf += pack_uint16_t(0)
    return self.buf

class WartsPingReply(WartsBaseObject):
  def __init__(self):
    super(WartsPingReply, self).__init__(obj_type['PING'])
    self.count = 0
    self.flags = [
     ('dstipid', None),
     ('flags', pack_uint8_t),
     ('replyttl', pack_uint8_t),
     ('replysize', pack_uint16_t),
     ('icmp', pack_uint16_t),
     ('rtt', pack_uint32_t),
     ('probeid', pack_uint16_t),
     ('replyipid', pack_uint16_t),
     ('probeipid', pack_uint16_t),
     ('replyproto', pack_uint8_t),
     ('tcpflags', pack_uint8_t),
     ('addr', self.pack_address),
     ('v4rr', self.pack_address),
     ('v4ts', self.pack_address),
     ('replyipid32', pack_uint32_t),
     ('tx', pack_timestamp),
     ('tsreply', pack_uint32_t), # broken; should read 12B
    ]


class WartsTrace(WartsBaseObject):
  def __init__(self):
    super(WartsTrace, self).__init__(obj_type['TRACE'])
    self.flags = [
     ('listid', pack_uint32_t),
     ('cycleid', pack_uint32_t),
     ('srcipid', None),
     ('dstipid', None),
     ('timeval', pack_timestamp),
     ('stopreas', pack_uint8_t),
     ('stopdata', pack_uint8_t),
     ('traceflg', pack_uint8_t),
     ('attempts', pack_uint8_t),
     ('hoplimit', pack_uint8_t),
     ('tracetyp', pack_uint8_t),
     ('probesiz', pack_uint16_t),
     ('srcport', pack_uint16_t),
     ('dstport', pack_uint16_t),
     ('firsttl', pack_uint8_t),
     ('iptos', pack_uint8_t),
     ('timeout', pack_uint8_t),
     ('loops', pack_uint8_t),
     ('probehop', pack_uint16_t),
     ('gaplimit', pack_uint8_t),
     ('gaprch', pack_uint8_t),
     ('loopfnd', pack_uint8_t),
     ('probesent', pack_uint16_t),
     ('minwait', pack_uint8_t),
     ('confid', pack_uint8_t),
     ('srcaddr', self.pack_address),
     ('dstaddr', self.pack_address),
     ('usrid', pack_uint32_t),
    ]

  def finalize(self):
    if self.reply:
      self.buf += pack_uint16_t(self.reply.count)
      self.buf += self.reply.buf
    else:
      self.buf += pack_uint16_t(0)
    # end of hop records indicated by 0x0000
    self.buf += pack_uint16_t(0)
    return self.buf

class WartsTraceHop(WartsBaseObject):
  def __init__(self):
    super(WartsTraceHop, self).__init__(obj_type['TRACE'])
    self.count = 0
    self.flags = [
     ('addrid', None),
     ('probettl', pack_uint8_t),
     ('replyttl', pack_uint8_t),
     ('hopflags', pack_uint8_t),
     ('probeid', pack_uint8_t),
     ('rtt', pack_uint32_t),
     ('icmp', pack_uint16_t),       # type, code
     ('probesize', pack_uint16_t),
     ('replysize', pack_uint16_t),
     ('ipid', pack_uint16_t),
     ('tos', pack_uint8_t),
     ('mtu', pack_uint16_t),
     ('qlen', pack_uint16_t),
     ('qttl', pack_uint8_t),
     ('tcpflags', pack_uint8_t),
     ('qtos', pack_uint8_t),
     ('icmpext', None),
     ('addr', self.pack_address),
    ]


class WartsWriter():
  def __init__(self, wartsfile, append=False, overwrite=True, compress=False):
    self.append = append
    self.fd = None
    # ensure we don't clobber existing files, if overwrite=False
    if (not overwrite) and (isfile(wartsfile)):
      self.append = True
    flags = 'wb'
    if self.append: flags = 'ab'
    if wartsfile.find('.bz2') != -1: compress=True
    if compress:
      self.fd = BZ2File(wartsfile, flags)
    else:
      self.fd = open(wartsfile, flags)

  def __del__(self):
    if self.fd: self.fd.close()

  @staticmethod 
  def append_string(buf, s):
    return buf + s + '\0'
 
  @staticmethod 
  def make_header(obj):
    head = struct.pack('!HHI', obj_type['MAGIC'], obj.typ, len(obj.buf))
    return head

  def write_header(self, buf, typ):
    head = struct.pack('!HHI', obj_type['MAGIC'], typ, len(buf))
    self.fd.write(head + buf)
 
  def write_list(self, wlistid, listid, lname):
    # don't overwrite list header, if appending
    if not self.append:
      content = struct.pack('!II', wlistid, listid)
      content = WartsWriter.append_string(content, lname)
      content += struct.pack('B', 0) # no flags
      self.write_header(content, obj_type['LIST'])

  def write_cycle(self, wcycle, listid, cycleid, start):
    # don't overwrite cycle header, if appending
    if not self.append:
      content = struct.pack('!IIII', wcycle, listid, cycleid, start)
      content += struct.pack('B', 0) # no flags
      self.write_header(content, obj_type['CYCLE'])

  def write_cycle_stop(self, cycleid, stop):
    if not self.append:
      content = struct.pack('!II', cycleid, stop)
      content += struct.pack('B', 0) # no flags
      self.write_header(content, obj_type['STOP'])

  def write_object(self, obj):
    obj.finalize()
    head = struct.pack('!HHI', obj_type['MAGIC'], obj.typ, len(obj.buf))
    self.fd.write(head + obj.buf)
    obj.reset()

  def write_blob(self, blob): 
    self.fd.write(blob)
