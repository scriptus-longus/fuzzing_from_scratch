import sys
import os
import signal
from ptrace import debugger
from elftools.elf.elffile import ELFFile
from elftools.elf.elffile import SymbolTableSection

class Breakpoint:
  def __init__(self, addr, instr):
    self.addr = addr
    self.instr = instr

class Tracer:
  def __init__(self, program):
    self.program = program
    self.dbg = debugger.PtraceDebugger()
    self.elf_file = ELFFile(open(program, "rb"))
    self.init_addr = 0x1000
    self.breakpoints = {}
    self.unique_crashes = []

    self._find_breakpoint()

  def _get_base(self, vmmap):
    for m in vmmap:
      if "x" in m.permissions and m.pathname.endswith(os.path.basename(self.program)):
        return m.start

  def _adjust_init(self):
    content = bytearray(open(self.program, "rb").read())
    addresses = list(self.breakpoints.values())
    id_sequence = content[addresses[0].addr:addresses[0].addr+10]

    pid = debugger.child.createChild([self.program, "corpus/sample.txt"], no_stdout=True, env=None) # TODO: change staic file
    proc = self.dbg.addProcess(pid, True)
    base = self._get_base(proc.readMappings())   
 
    for i in range(0x0, self.init_addr):
      current_bytes = proc.readBytes(base + i, 10) 
      if current_bytes == id_sequence:
        init_offset = addresses[0].addr - i
        break

    for bp in list(self.breakpoints.values()):
      bp.addr -= self.init_addr

    return self.breakpoints 

  def _find_breakpoint(self):
    sym = self.elf_file.get_section_by_name(".symtab")

    content = bytearray(open(self.program, "rb").read())

    if not sym:
      print("Currently the fuzzer only supports non stripped binary. Your binary does not have a symbol table, sorry...")
      sys.exit()

    for symbol in sym.iter_symbols():
      if symbol.name == "" or symbol.entry["st_value"] == 0 or symbol.entry["st_info"]["type"] != "STT_FUNC":
        continue

      #print(symbol.entry["st_size"])
      addr = symbol.entry["st_value"]
      instr = content[addr]
      self.breakpoints[symbol.name] = Breakpoint(addr, instr)


    self.breakpoints = {k: self.breakpoints[k] for k in sorted(self.breakpoints, key=lambda x: self.breakpoints[x].addr)}
    self.breakpoints = self._adjust_init()

  def _insert_breakpoint(self, proc, bp):
    proc.writeBytes(bp.addr, b"\xCC")

  def _restore_breakpoint(self, proc, bp):
    proc.writeBytes(bp.addr, bytes(bp.instr))

  def run(self, data):
    crash = {}
    hit_breakpoints = []
    pid = debugger.child.createChild([self.program, data], no_stdout=True, env=None)
    proc = self.dbg.addProcess(pid, True)
    base = self._get_base(proc.readMappings())

    for bp in list(self.breakpoints.values()):
      #bp.addr += base
      proc.createBreakpoint(base + bp.addr)
      #self._insert_breakpoint(proc, bp)

    while True:
      proc.cont()
      event = proc.waitEvent()  

      if event.signum == signal.SIGSEGV.value:
        ip = proc.getInstrPointer()

        for mapping in proc.readMappings():
          if ip in mapping:
            address = ip-mapping.start

        proc.detach()
        if address not in self.unique_crashes:
          self.unique_crashes.append(address)

          crash["addr"] = address
          crash["crash"] = True
          crash["breakpoints"] = [(x,y) for x, y in zip(hit_breakpoints[:-1], hit_breakpoints[1:])]
        else:
          crash["addr"] = None
          crash["crash"] = False 
          crash["breakpoints"] = [(x,y) for x, y in zip(hit_breakpoints[:-1], hit_breakpoints[1:])]
        return crash

      elif event.signum == signal.SIGTRAP.value:        # TODO: does not hit sigtrap
        #print("Hit breakpoint {:08x}".format(proc.getInstrPointer()))
        ip_addr = proc.getInstrPointer()
        hit_breakpoints.append(ip_addr - base)
        #print(f"ip is at {ip_addr}")

        #for bp in list(self.breakpoints.values()):
        #  print(bp.addr, bp.instr)
        #  if bp.addr == ip_addr:
        #    self._restore_breakpoint(proc, bp)

      elif isinstance(event, debugger.ProcessExit):
        proc.detach()
        break
      else:
        pass

    crash["addr"] = None 
    crash["crash"] = False
    crash["breakpoints"] = [(x,y) for x, y in zip(hit_breakpoints[:-1], hit_breakpoints[1:])]
    return crash 
    
