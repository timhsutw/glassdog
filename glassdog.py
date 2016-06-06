#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import struct
import argparse
import json
import hashlib
import string
from datetime import datetime
from datetime import timedelta

from collections import defaultdict


import traceback

PROGRAM = 'glassdog'
DESCRIPTION = 'Glassdog - A Yara Rule Generator'
VERSION = '0.0.2'

PATTERN_HEADER_VERSION = 'Version'
PATTERN_HEADER_FILENAME = 'FileName'

class Sample(object):
   
   def __init__(self,filename=None):
      self.data = None
      self.name = None
      self.sha256 = None

      if filename is not None:
         self.load(filename)

   def load(self, filename):
      try:
        # print filename
         with open(filename) as f:
            self.data = f.read()
            self.sha256 = hashlib.sha256(self.data).hexdigest()
           # print self.sha256
            self.name = filename
            f.close()
      except Exception, e:
         traceback.print_exc()
         return None
      if len(self.data) < 8:
         return None
      
      return self.data


def default_filter_hex(pattern, value):
   if value == 0:
      return False
   string = struct.pack(pattern.packchar, value)
   hexstr = string.encode('hex')
   if hexstr.count('00') > pattern.size/2:
      return False
   return True

def default_filter_strings(pattern, value):
   if len(value) < 4 or len(value) > 16:
      return False      
   hexstr = value.encode('hex')
   if hexstr.count('20') > len(value)/2:
         return False

   return True
   

class Patterns(object):

   def __init__(self, sample=None, size=8, type='hex', filter=default_filter_hex):
      
      self.sample = sample
      self.rulename = None
      self.sample_filename = None
      self.sample_sha256 = None
      self.header = None
      self.time_cost = 0
      self.time_cost_total = 0
      self.search_count = 0
      self.match_count = 0
      self.remove_count = 0
      self.count = 0
      self.pattern = defaultdict(list)
      self.sorted_pattern = None
      self.type = type
      self.filter = filter
      self.size = size
      self.packchar = 'Q'

      if sample is None:
         return
      self.sample_filename = sample.name
      self.sample_sha256 = sample.sha256
      
         
      if self.type == 'hex':
         if self.size != 4 and self.size != 8:
            self.size = 8
         if self.size == 4:
            self.packchar = 'I'
         if self.size == 8:
            self.packchar = 'Q'
         
         self.hex()

      if self.type == 'strings':
         self.filter = default_filter_strings
         self.strings()

#   def default_filter_hex(self, value):
#      if value == 0:
#         return False
#      string = struct.pack(self.packchar, value)
#      hexstr = string.encode('hex')
#      if hexstr.count('00') > self.size/2:
#         return False
#      return True
#
#   def default_filter_strings(self, value):
#      return True
   

   def hex(self):

      i = 0
      while i < len(self.sample.data)-self.size-1:
         d = self.sample.data[i:i+self.size]
         c, = struct.unpack(self.packchar,d)
         
         if self.filter is not None and self.filter(self, c) is False:
            i += 1
            continue

         if c in self.pattern:
            # add value (count)
            self.pattern[c][0][1] += 1
         else:
            self.pattern[c].append([i, 1])
            self.match_count = self.match_count + 1
         i = i + 1
      self.search_count += 1

      
   def strings(self):

      print 'strings mode'
      control_chars = string.maketrans('', '')[:32]
      i = 0
      s = ''
      start = False
      while i < len(self.sample.data)-1:
         c = self.sample.data[i]
         if c in string.printable and not c in control_chars:
            if start is False:
               start = True
            s += c
            i += 1
            continue

         else:
            if start is True:
               start = False
               if self.filter is not None and self.filter(self, s) is False:
                  s = ''
                  i += 1
                  continue

               if len(s) < 2:
                  s = ''
                  i += 1
                  continue
               if s in self.pattern:
                  self.pattern[s][0][1] += 1
               else:
                  self.pattern[s].append([i, 1])
                  self.match_count = self.match_count + 1
               s = ''
               i += 1
            else:
               i += 1
               continue

      self.search_count += 1

   def __getattr__(self, key):
      if key == 'data':
         return self.pattern
      raise AttributeError(key)

   def load(self, filename):
      try:
         with open(filename,'r') as f:
            self.header = json.loads(f.read())
            self.sample_filename = self.header["FileName"]
            self.search_count = self.header["SampleCount"]
            self.size = self.header["PatternSize"]
            self.type = self.header["PatternType"]
            data = self.header["Pattern"]
            for value in data:
               offset = data[value][0][0]
               count = data[value][0][1]
               index = value
               if self.type == 'hex':
                  index = long(value)
               self.pattern[index].append([offset, count])
               self.count = self.count + 1

            self.match_count = self.count
            return True
      
      except Exception as err:
         traceback.print_exc()

         print 'Error while loading %s : %s' % (filename, str(err))
         return False

   def save(self, filename):

      save_pattern = defaultdict(list)
      for value in self.pattern:
         if self.pattern[value] == []:
            continue
         for pdata in self.pattern[value]: 
            save_pattern[value].append(pdata)
            
      self.header = { "Version" : VERSION, 
                      "FileName" : self.sample_filename, 
                      "PatternSize" : self.size,
                      "SampleCount" : self.search_count, 
                      "SampleSHA256" : self.sample_sha256,
                      "PatternType" : self.type,
                      "Pattern" : save_pattern
                     }
      try:
         with open(filename,'w+') as f:
            f.write(json.dumps(self.header))
            f.close()
         return True

      except:
         return False


   def get_sort_key(self, value):
      for pdata in self.pattern[value]:
         return pdata[1]

   def sort(self):

      self.sorted_pattern = defaultdict(list)
      sort_list = sorted(self.pattern, key=self.get_sort_key, reverse=True)
      index = 0
      for value in sort_list:
         for pdata in self.pattern[value]: 
            self.sorted_pattern[index].append([value,pdata])
         index += 1
      return self.sorted_pattern

   def copy(self):

      pattern = Patterns(self.sample, filter=default_filter)
      for value in self.pattern:
         for pdata in self.pattern[value]:
            pattern.pattern[value].append(pdata)
      return pattern

   def merge(self, source):

      pass

   def search(self, sample, increase=False):
      self.start_time = datetime.now()
      self.remove_count = 0
      index = 0

      if self.type == 'hex':
         while index < len(sample.data)-self.size-1:
            try:
               d = sample.data[index:index+self.size]
               value, = struct.unpack(self.packchar,d)
#            if self.pattern[value]:
               if value in self.pattern:
                  if increase is True:
                     self.pattern[value][0][1] += 1
                  else:
                     del self.pattern[value]
                     self.match_count = self.match_count - 1
                     self.remove_count += 1
            except Exception as err:
               print str(err)
            index = index + 1
      
      if self.type == 'strings':
         control_chars = string.maketrans('', '')[:32]
         i = 0
         s = ''
         start = False
         while i < len(self.sample.data)-1:
            try:
               c = self.sample.data[i]
               if c in string.printable and not c in control_chars:
                  if start is False:
                     start = True
                  s += c
                  i += 1
                  continue
               else:
                  if start is True:
                     start = False
                     if self.filter is not None and self.filter(self, s) is False:
                        s = ''
                        i += 1
                        continue

                     if s in self.pattern:
                        if increase is True:
                           self.pattern[s][0][1] += 1
                        else:
                           del self.pattern[s]
                           self.match_count = self.match_count - 1
                           self.remove_count += 1
                           s = ''
                           i += 1
                  else:
                     i += 1
                     continue
            except Exception as err:
               traceback.print_exc()
               print str(err)

      dt = datetime.now() - self.start_time
      self.time_cost = (dt.days * 24 * 60 * 60 + dt.seconds) * 10000 + dt.microseconds 
      self.time_cost_total += self.time_cost
      self.search_count = self.search_count + 1
      
class Rule(object):

   def __init__(self, pattern=None, name=None):
      self.name = name
      self.pattern = pattern
      self.data = self.pattern.sort()

   def max(self, num):
      index = 0
      result_pattern = []
      if num > len(self.data):
         num = len(self.data)
      while index < num:
         for pdata in self.data[index]:
            if self.pattern.type == 'hex':
               string = struct.pack(self.pattern.packchar, pdata[0]).encode('hex')
            else:
               string = pdata[0]
            result_pattern.append(string)
         index += 1
      return result_pattern

   def average(self, num):
      pass

   def equal(self, num):
      index = 0
      count = 0
      value = self.pattern.search_count
      result_pattern = []
      if num > len(self.data):
         num = len(self.data)
      while index < len(self.data) and count < num:
         for pdata in self.data[index]:
            if pdata[1][1] == value:
               if self.pattern.type == 'hex':
                  string = struct.pack(self.packchar, pdata[0]).encode('hex')
               else:
                  string = pdata[0]
               result_pattern.append(string)
               count +=1
         index += 1
      return hex_pattern

   def analyze(self, num, handler=None):
      if handler is None:
         return self.max(num)
      return handler(num)

   def yara(self, result_pattern, filename=None):
      
      output = 'rule ' + self.name + '\n'
      output += '{' + '\n'
      output += '    meta:\n'
      output += '       author = "%s"\n' % DESCRIPTION 
      output += '       sha256 = "%s"\n' % self.pattern.sample_sha256
      output += '       glassdog = "%s"\n' % VERSION
      output += '       date = "%s"\n' % datetime.strftime(datetime.now(), '%Y-%m-%d')
      output += '    strings:\n'
      pattern_count = 0
      if self.pattern.type == 'hex':
         for s in result_pattern:
            length = len(s)
            index = 0
            output += '      $pattern%d = { ' % pattern_count
            while index < length/2:
               p = s[index*2:index*2+2]
               output += p      
               output += ' '
               index += 1
            output += '}\n'
            pattern_count += 1
      if self.pattern.type == 'strings':
         for s in result_pattern:
            length = len(s)
            index = 0
            output += '      $pattern%d = ' % pattern_count
            output += '\"' + s + '\"'
            output += '\n'
            pattern_count += 1

      output += '    condition:\n'
      if pattern_count > 5:
         match_count = pattern_count - 1
      else:
         match_count = pattern_count
      output += '        %d of them\n' % match_count
      output += '}\n'

      if filename is None:
         print output
      else:
         try:
            with open(filename,'w+') as f:
               f.write(output)
               f.close()
         except:
            return False
      
      return True

   def snort(self):
      pass
   def dump(self):
      
      index = 0
      while index < len(self.data):
         for pdata in self.data[index]:
            #offset = struct.pack('I', pdata[1][0])
            if self.pattern.type == 'hex':
               string = struct.pack(self.pattern.packchar, pdata[0]).encode('hex')
            else:
               string = pdata[0]
            print '%d:%s:%x:%d' %(index, string, pdata[1][0], pdata[1][1]) 
         index += 1 

if __name__ ==  '__main__':

   parser = argparse.ArgumentParser(prog=PROGRAM, 
                                    description=DESCRIPTION + '    version: ' + VERSION)
   parser.add_argument("-L", metavar='filename', help="Load pattern file")
   parser.add_argument("-S", metavar='filename', help="Save pattern/rule file")
   parser.add_argument("-y", metavar='yara_rulename', help="Yara Rule name")
   parser.add_argument("-r", metavar='select_rule', help="Select rule (max, equal, average)")
   parser.add_argument("-s", action="store_true", help="strings")
   parser.add_argument("-p", metavar='pattern_size', help="Pattern size (4 or 8 for Hex)")
   parser.add_argument("-v", action="store_true", help="More detail")
   parser.add_argument("-i", action="store_true", help="Increase mode ")
   parser.add_argument("-D", action="store_true", help="Dump pattern")
   parser.add_argument('target', nargs='*', help='Sample file(s)')
   
   if len(sys.argv) < 2:
      parser.parse_args('-h'.split())
      sys.exit(-1)

   args = parser.parse_args()
   glassdog = {}
   glassdog['loadfile'] = args.L
   glassdog['savefile'] = args.S
   if args.s is True:
      glassdog['type'] = 'strings'
   else:
      glassdog['type'] = 'hex'
   glassdog['yararulename'] = args.y
   glassdog['select_rule'] = args.r
   glassdog['verbose'] = args.v
   glassdog['target'] = args.target
   glassdog['dump'] = args.D
   glassdog['increase'] = args.i
   if args.p is not None:
      glassdog['patternsize'] = int(args.p)
   else:
      glassdog['patternsize'] = 8

   pattern = None
   sample = None

   print '%s   Version: %s' % (DESCRIPTION, VERSION)

   if glassdog['loadfile'] is not None:
      print 'Load patterns from %s' % glassdog['loadfile']
      pattern = Patterns()
      pattern.load(glassdog['loadfile'])
      print 'Found %d patterns' % pattern.count

   elif len(args.target) > 0:
      print 'Get patterns from %s' % glassdog['target'][0]
      sample = Sample(args.target[0])
      if sample.data is None:
         print 'Error: unable to get patterns!'
         sys.exit(-2)
      pattern = Patterns(sample, size=glassdog['patternsize'], type=glassdog['type'])
   
   if len(glassdog['target']) > 0:
      if sample:
         i = 1
      else:
         i = 0
      while i < len(glassdog['target']):
         print 'Analyzing [%s]' % args.target[i]
         target = Sample(args.target[i])
         if target.data is None:
            i += 1
            continue
         pattern.search(target, glassdog['increase'])
         del target
         if glassdog['verbose'] is True and pattern.remove_count > 0:
            print 'Remove %d patterns' % pattern.remove_count
         i += 1
   if pattern is None:
      sys.exit(-2)

   if glassdog['verbose'] is True:
      print 'Total time cost = %s' % str(timedelta(microseconds=pattern.time_cost_total))

   if glassdog['yararulename'] is not None:

      rule = globals()['Rule'](pattern, glassdog['yararulename'])
      if glassdog['select_rule'] is None:
         hex_pattern = rule.analyze(5)
      else:
         try:
            func = getattr(rule, glassdog['select_rule'])
         except:
            print 'Error:No "%s" rule found' % glassdog['select_rule']
            sys.exit(-2)
         hex_pattern = rule.analyze(5, func)
      print hex_pattern
   if glassdog['dump'] is True:
      rule.dump()
         
   if glassdog['savefile'] is not None:
      
      if glassdog['yararulename'] is None and pattern is not None:
         print 'Save %d patterns to %s' % (pattern.match_count, glassdog['savefile'])
         pattern.save(glassdog['savefile'])
      if glassdog['yararulename'] is not None:
         rule.yara(hex_pattern, filename=glassdog['savefile'])
