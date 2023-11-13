import sys
import os
import signal
from ptrace import debugger
from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection

class Tracer:
  def __init__(self, program):
    self.program = program
    self.dbg = debugger.PtraceDebugger()
    self.elf_file = ELFFile(open(program, "rb"))
    self.init_addr = 0x1000
    self.breakpoints = {}

    self._find_breakpoint()

  def _get_base(self, vmmap):
    for m in vmmap:
      if "x" in m.permissions and m.pathname.endswith(os.path.basename(self.program)):
        return m.start

  def _adjust_init(self):
    content = bytearray(open(self.program, "rb").read())
    addresses = list(self.breakpoints.values())
    id_sequence = content[addresses[0]:addresses[0]+10]

    pid = debugger.child.createChild([self.program, "corpus/sample.txt"], no_stdout=True, env=None) # TODO: change staic file
    proc = self.dbg.addProcess(pid, True)
    base = self._get_base(proc.readMappings())   
 
    for i in range(0x0, self.init_addr):
      current_bytes = proc.readBytes(base + i, 10) 
      if current_bytes == id_sequence:
        init_offset = addresses[0] - i
        break

    return {k: self.breakpoints[k]-self.init_addr for k in self.breakpoints}

  def _find_breakpoint(self):
    sym = self.elf_file.get_section_by_name(".symtab")

    if not sym:
      print("Currently the fuzzer only supports non stripped binary. Your binary does not have a symbol table, sorry...")
      sys.exit()

    for symbol in sym.iter_symbols():
      if symbol.name == "" or symbol.entry["st_value"] == 0 or symbol.entry["st_info"]["type"] != "STT_FUNC":
        continue

      self.breakpoints[symbol.name] = symbol.entry["st_value"]


    self.breakpoints = {k: self.breakpoints[k] for k in sorted(self.breakpoints, key=lambda x: self.breakpoints[x])}
    self.breakpoints = self._adjust_init()


  def run(self, data):
    crash = {}
    hit_breakpoints = []
    pid = debugger.child.createChild([self.program, data], no_stdout=True, env=None)
    proc = self.dbg.addProcess(pid, True)
    base = self._get_base(proc.readMappings())

    for bp in self.breakpoints:
      proc.createBreakpoint(base + self.breakpoints[bp])

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
        hit_breakpoints.append(proc.getInstrPointer() - base)
      elif isinstance(event, debugger.ProcessExit):
        proc.detach()
        break
      else:
        pass

    crash["addr"] = None 
    crash["crash"] = False
    crash["breakpoints"] = hit_breakpoints
    return crash 
    
