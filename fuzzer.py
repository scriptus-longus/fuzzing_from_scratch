import argparse
from ptrace import debugger
import random
import signal

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

  with open("sample/test_case", "wb") as f:
    f.write(data)

  return "sample/test_case"


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--test", help="test case file", required=True)
  parser.add_argument("target", help="program to fuzz")
  parser = parser.parse_args()

  filename = parser.test
  target = parser.target
  keep_fuzzing = True

  data = bytearray(open(filename, "rb").read())
  dbg = debugger.PtraceDebugger()

  while keep_fuzzing:
    test_data = mutate(data)
    crash = fuzz(target, test_data)

    if crash:
      print(f"SIGSEV from input data {test_data} with content: ")
      print(f"+----------------------------------------------------+")
      content = bytearray(open(test_data, "rb").read())
      print(str(content))
      print()
  
    
