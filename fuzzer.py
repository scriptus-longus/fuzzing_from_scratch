import argparse
import signal
import os
import json
import sys
import pickle

from tracer import Tracer
from tracer import Breakpoint
from mutator import Mutator

corpus_path = "corpus/"
log_path = "logs/"
test_case_path = "cases/"
mutator_state_file ="mutator_state.sta"
seed = 1337
keep_running = True

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

def signal_handler(signum, frame):
   print("exiting...")
   log_fuzzer_state({"mutator": mutator, "tracer": tracer}) 
   keep_running = False
   sys.exit(0)

def log_fuzzer_state(state):
  corpus_log = {k: list(state["mutator"].corpus[k]) for k in state["mutator"].corpus}

  mutator_log = {"corpus": corpus_log, "known_points": state["mutator"].known_points}
  breakpoint_log = {}

  for bp in tracer.breakpoints:
    breakpoint_log[bp] = [tracer.breakpoints[bp].addr, tracer.breakpoints[bp].instr]

  tracer_log = {"breakpoints": breakpoint_log, "crashes": tracer.unique_crashes}

  mutator_file = open(os.path.join(log_path, "mutator.sta"), "w")
  tracer_file = open(os.path.join(log_path, "tracer.sta"), "w")
  json.dump(mutator_log, mutator_file)
  json.dump(tracer_log, tracer_file)
   
  
def restore_fuzzer_state(folder, mutator, tracer):
  mutator_state = json.loads(open(os.path.join(folder, "mutator.sta"), "r").read()) 
  tracer_state = json.loads(open(os.path.join(folder, "tracer.sta"), "r").read())

  corpus = {k: bytearray(mutator_state["corpus"][k]) for k in mutator_state["corpus"]}
  known_points = [tuple(x) for x in mutator_state["known_points"]]
 
  breakpoints = {}
 
  for bp in tracer_state["breakpoints"]:
    breakpoints[bp] = Breakpoint(tracer_state["breakpoints"][bp][0], tracer_state["breakpoints"][bp][0])
 
  crashes = tracer_state["crashes"]

  mutator.corpus = corpus
  mutator.known_points = known_points
  tracer.unique_crashes = crashes
  tracer.breakpoints = breakpoints
 

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--corpus", help="path to sample files", required=True)
  parser.add_argument("--case_path", help="folder to save test cases to")  
  parser.add_argument("--logfile", help="default name for logfile (gets saved to logs folder)", default="mylog.log")
  parser.add_argument("--logfolder", help="name of folder to save logfiles", default="logs") 
  parser.add_argument("--pickup", help="folder with fuzzer state to pick up from", default=None) 
  parser.add_argument("--no-print", help="dont print log info while running", action="store_false", dest="log")
  parser.add_argument("--seed", help="set seed for random") # TEST
  parser.add_argument("target", help="program to fuzz")
  parser = parser.parse_args()

  corpus = parser.corpus
  target = parser.target
  show_log_info = parser.log
  log_path = parser.logfolder
  log_file = parser.logfile
  seed = parser.seed or seed
  pickup_folder = parser.pickup
  test_case_path = paraser.case_path

  keep_fuzzing = True

  mutator = Mutator(corpus, test_case_path=test_case_path, seed=seed)  
  tracer = Tracer(target)

  if pickup_folder:
    restore_fuzzer_state(pickup_folder, mutator, tracer)
  
  signal.signal(signal.SIGINT, signal_handler)
 
  for filename, content in mutator:
    if not keep_running:
      break

    crash = tracer.run(filename)
    trace = crash["breakpoints"]

    mutator.add(content, trace)


    if crash["crash"]:
      print(f"[*] crash detected from at address {hex(crash['addr'])}")
      printable_content = make_printable(bytearray(content))

      if show_log_info:
        print_log(printable_content)
    
      write_log_readable(printable_content, os.path.join(log_path, log_file))



 
