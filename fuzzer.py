import argparse
from ptrace import debugger
import random
import signal
import os
import json
import sys

from tracer import Tracer
from mutator import Mutator
from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection

corpus_path = "corpus/"
log_path = "logs/"
test_case_path = "cases/"

def make_printable(x):
  return ["{:02x}".format(ord(chr(c))) for c in x] 

def generate_readable_log(content):
  ret = ""
  ret += "SIGSEV from input data with content:\n" 
  ret += "+----------------------------------------------------+\n"

  n_blocks = len(content) // 8
  for i in range(n_blocks+1): 
    if i == n_blocks:
      ret += " ".join(content[(i*8):])
    else:
      ret += " ".join(content[(i*8):((i+1)*8)]) + "\n"

  return ret
  
def print_log(content):
  log = generate_readable_log(content)
  print(log)

def write_log_readable(content, out_file):
  log = generate_readable_log(content)
  with open(out_file, "a") as f:
    f.write(log + "\n")

def log_fuzzer(state, out_file):
  pass

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--corpus", help="path to sample files", required=True)
  parser.add_argument("--logfile", help="default name for logfile (gets saved to logs folder)", default="mylog.log")
  parser.add_argument("--no-print", help="dont print log info while running", action="store_false", dest="log")
  parser.add_argument("target", help="program to fuzz")
  parser = parser.parse_args()

  corpus = parser.corpus
  target = parser.target
  show_log_info = parser.log
  log_file = parser.logfile
  keep_fuzzing = True

  mutator = Mutator(corpus)  
  tracer = Tracer(target)
  #corpus = get_corpus(corpus)

 
  for filename, content in mutator:
    crash = tracer.run(filename)

    trace = crash["breakpoints"]

    mutator.add(content, trace)

    if crash["crash"]:
      print(f"[*] crash detected from {corpus_file} at address {hex(crash['addr'])}")
      content = open(test_path, "rb").read()
      printable_content = make_printable(bytearray(content))

      if show_log_info:
        print_log(printable_content)
      write_log_readable(printable_content, os.path.join(log_path, log_file))
 
