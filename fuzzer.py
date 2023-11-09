import argparse
from ptrace import debugger
import random
import signal
import os
import json
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection

corpus_path = "corpus/"
log_path = "logs/"
test_case_path = "cases/"
seed = 1337
init_addr = 0x1000  # need to find using pyelftools

dbg = debugger.PtraceDebugger()
random.seed(seed)

state = {}
crash_addresses = []
#TODO: store current fuzzer state and restore
#TODO: coverage 
#TODO: get acutal address in vmmap

def get_base(vmmap, target):
  for m in vmmap:
    if "x" in m.permissions and m.pathname.endswith(os.path.basename(target)):
      return m.start

def adjust_init(target, breakpoints):
  content = bytearray(open(target, "rb").read())
  addresses = list(breakpoints.values())
  print(addresses)
  id_sequence = content[addresses[0]:addresses[0]+10]

  pid = debugger.child.createChild([target, "corpus/sample.txt"], no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  base = get_base(proc.readMappings(), target)   
 
  for i in range(0x0, 0x1000):
    current_bytes = proc.readBytes(base + i, 10) 
    if current_bytes == id_sequence:
      init_offset = addresses[0] - i
      break

  breakpoints = {k: breakpoints[k]-init_offset for k in breakpoints}

def fuzz(target, data, breakpoints):
  crash = {}
  hit_breakpoints = []
  pid = debugger.child.createChild([target, data], no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  base = get_base(proc.readMappings(), target)

  for bp in breakpoints:
    proc.createBreakpoint(base + breakpoints[bp])

  while True:
    proc.cont()
    event = proc.waitEvent()  

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

    elif event.signum == signal.SIGTRAP.value:        # TODO: does not hit sigtrap
      #print("Hit breakpoint {:08x}".format(proc.getInstrPointer()))
      hit_breakpoints.append(proc.getInstrPointer())
    elif isinstance(event, debugger.ProcessExit):
      proc.detach()
      break
    else:
      pass


  crash["addr"] = None 
  crash["crash"] = False
  crash["breakpoints"] = hit_breakpoints
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

  breakpoints = {}

  e = ELFFile(open(target, "rb"))
  sym = e.get_section_by_name(".symtab")
  if not sym:
    print("Currently the fuzzer only supports non stripped binary. Your binary does not have a symbol table, sorry...")
    sys.exit()

  for symbol in sym.iter_symbols():
    if symbol.name == "" or symbol.entry["st_value"] == 0 or symbol.entry["st_info"]["type"] != "STT_FUNC":
      continue

    breakpoints[symbol.name] = symbol.entry["st_value"]


  breakpoints = {k: breakpoints[k] for k in sorted(breakpoints, key=lambda x: breakpoints[x])}
  adjust_init(target, breakpoints)

  corpus = get_corpus(corpus)

  while keep_fuzzing:
    corpus_file = random.choice(list(corpus.keys()))
    data = corpus[corpus_file]
    test_path = mutate(data)
    crash = fuzz(target, test_path, breakpoints)

    if crash["crash"]:
      print(f"[*] crash detected from {corpus_file} at address {hex(crash['addr'])}")
      content = open(test_path, "rb").read()
      printable_content = make_printable(bytearray(content))

      if show_log_info:
        print_log(printable_content)
      write_log_readable(printable_content, os.path.join(log_path, log_file))
 
