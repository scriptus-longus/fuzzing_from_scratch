import argparse
from ptrace import debugger
import random
import signal
import os

corpus_path = "corpus/"
log_path = "logs/"

# TODO: input corpus

def fuzz(target, data):
  #data_content = bytearray(open(data, "rb").read())
  pid = debugger.child.createChild([target, data], no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  try:
    sig = dbg.waitSignals()
  except:
    return False

  if sig.signum == signal.SIGSEGV.value:   # TODO: better signal handling
    proc.detach()
    return True
  return False

def mutate(data):
  idx = random.choice(range(len(data)))
  # just bit flipping
  data[idx]  ^= random.choice([2**0, 2**1, 2**2, 2**3, 2**4, 2**5, 2**6, 2**7])
  #print(data)

  path = os.path.join(corpus_path, "test_case")
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

def print_log(content):
  log = generate_readable_log(content)
  print(log)

def write_log_readable(content, out_file):
  log = generate_readable_log(content)
  with open(out_file, "a") as f:
    f.write(log + "\n")

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--test", help="test case file", required=True)
  parser.add_argument("--logfile", help="default name for logfile (gets saved to logs folder)", default="mylog.log")
  parser.add_argument("--no-print", help="dont print log info while running", action="store_false", dest="log")
  parser.add_argument("target", help="program to fuzz")
  parser = parser.parse_args()

  filename = parser.test
  target = parser.target
  show_log_info = parser.log
  log_file = parser.logfile
  keep_fuzzing = True

  data = bytearray(open(filename, "rb").read())
  dbg = debugger.PtraceDebugger()

  while keep_fuzzing:
    test_data = mutate(data)
    crash = fuzz(target, test_data)

    if crash:
      print("[*] crash detected")
      content = make_printable(bytearray(open(test_data, "rb").read()))
      if show_log_info:
        print_log(content)
      write_log_readable(content, os.path.join(log_path, log_file))

 
