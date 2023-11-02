import argparse
from ptrace import debugger
import random
import signal
import os
import json

corpus_path = "corpus/"
log_path = "logs/"
test_case_path = "cases/"
seed = 1337

state = {}
crash_addresses = []
#TODO: store current fuzzer state and restore
#TODO: coverage 

def fuzz(target, data):
  #data_content = bytearray(open(data, "rb").read())
  crash = {}
  pid = debugger.child.createChild([target, data], no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  event = dbg.waitProcessEvent()  

  if event.signum == signal.SIGSEGV.value:
    ip = proc.getInstrPointer()

    for mapping in proc.readMappings():
      if ip in mapping:
        address = ip-mapping.start

    proc.detach()
    if address not in crash_addresses:
      crash_addresses.append(address)

      crash["addr"] = address
      crash["crash"] = True
    else:
      crash["addr"] = None
      crash["crash"] = False 
    return crash
   
  crash["addr"] = None 
  crash["crash"] = False
  return crash 

def mutate(data):
  idx = random.choice(range(len(data)))
  # just bit flipping
  data[idx]  ^= random.choice([2**0, 2**1, 2**2, 2**3, 2**4, 2**5, 2**6, 2**7])

  path = os.path.join(test_case_path, "test_case")
  with open(path, "wb") as f:
    f.write(data)

  return path

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

def get_corpus(corpus_path):
  ret = {}
  for filename in os.listdir(corpus_path):
    filepath = os.path.join(corpus_path, filename)
    if os.path.isfile(filepath):
      ret[filename] = bytearray(open(filepath, "rb").read())
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

  corpus = get_corpus(corpus)
  dbg = debugger.PtraceDebugger()
  random.seed(seed)

  while keep_fuzzing:
    corpus_file = random.choice(list(corpus.keys()))
    data = corpus[corpus_file]
    test_path = mutate(data)
    crash = fuzz(target, test_path)

    if crash["crash"]:
      print(f"[*] crash detected from {corpus_file} at address {hex(crash['addr'])}")
      content = open(test_path, "rb").read()
      printable_content = make_printable(bytearray(content))

      if show_log_info:
        print_log(printable_content)
      write_log_readable(printable_content, os.path.join(log_path, log_file))
 
