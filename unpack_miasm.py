# system
import sys, struct, time, datetime
from ntpath import basename
# miasm
from miasm.os_dep.win_api_x86_32            import ACCESS_DICT_INV
from miasm.jitter.emulatedsymbexec          import EmulatedSymbExec
from miasm.jitter.jitcore_python            import JitCore_Python
# miasm additions
from sandbox_win64                          import Sandbox_Win64
from win_api_x86_64                         import *

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

class UnpackerException(Exception):
  pass

class ESETrackMemory(EmulatedSymbExec):
  """Emulated symb exec with memory access tracking"""
  def mem_read(self, expr_mem):
      value = super(ESETrackMemory, self).mem_read(expr_mem)
      #if int(expr_mem.arg) not in range(0x130000, 0x140000):
      print(f'READ {expr_mem}: {value}')
      return value

  def mem_write(self, dest, data):
      #if int(dest.arg) not in range(0x130000, 0x140000):
      print(f'WRITE {dest}: {data}')
      return super(ESETrackMemory, self).mem_write(dest, data)

def kernel32_FreeLibrary(jitter):
  ret_ad, args = jitter.func_args_stdcall([])
  jitter.func_ret_stdcall(ret_ad, 1)

def kernel32_VirtualQuery(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ad", "lpbuffer", "dwl"])
    all_mem = jitter.vm.get_all_memory()
    found = None
    for basead, m in all_mem.items():
        if basead <= args.ad < basead + m['size']:
            found = args.ad, m
            break
    if not found:
        raise ValueError('cannot find mem', hex(args.ad))
    s = struct.pack('QQQQQQQ',
                    args.ad,
                    basead,
                    ACCESS_DICT_INV[m['access']],
                    m['size'],
                    0x1000,
                    ACCESS_DICT_INV[m['access']],
                    0x01000000)
    jitter.vm.set_mem(args.lpbuffer, s)
    jitter.func_ret_stdcall(ret_ad, args.dwl)
    return

tickcount = 0x01234567
def kernel32_GetTickCount64(jitter):
    global tickcount
    ret_ad, _ = jitter.func_args_stdcall(0)
    tickcount += 0x18
    jitter.func_ret_stdcall(ret_ad, tickcount)

def kernel32_GetCurrentProcess(jitter):
  ret_ad, args = jitter.func_args_stdcall([])
  o = struct.pack('Q', 0xFFFFFFFFFFFFFFFF)
  jitter.func_ret_stdcall(ret_ad, -1)

def kernel32_QueryPerformanceCounter(jitter):
  ret_ad, args = jitter.func_args_stdcall(["lpPerformanceCount"])
  bogus_perfcounter = (int)(time.clock()*1000000)&0xFFFFFFFFFFFFFFFF
  print('bogus_perfcounter: ' + hex(bogus_perfcounter))
  s = struct.pack('Q', bogus_perfcounter)
  jitter.vm.set_mem(args.lpPerformanceCount, s)
  jitter.func_ret_stdcall(ret_ad, 1)

def msvcr110__initterm_both(jitter):
  raise UnpackerException('Reached initterm')
  #ret_ad, args = jitter.func_args_stdcall(['Pa', 'Pb'])
  #jitter.func_ret_stdcall(ret_ad, 0)

def ntdll_NtQueryInformationProcess(jitter):
    '''
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
    ProcessDebugObjectHandle = 0x1E
    '''
    ret_ad, args = jitter.func_args_stdcall(['ProcessHandle',
                                             "ProcessInformationClass",
                                             "ProcessInformation",
                                             "ProcessInformationLength",
                                             "ReturnLength"])
    if args.ProcessInformationClass == 0x1E:
        # SYSTEM_PERFORMANCE_INFORMATION
        o = struct.pack('Q', 0x0)
        o += "\x00" * (args.ProcessInformationLength-8 if args.ProcessInformationLength>8 else 0)
        o = o[:args.ProcessInformationLength]
        jitter.vm.set_mem(args.ProcessInformation, o)
        if args.ReturnLength:
          retlen = struct.pack('Q', 0x8)
          print('wrote return len back: ' + str([hex(ord(c)) for c in retlen]))
          jitter.vm.set_mem(args.ReturnLength, retlen)
        print('returned: ' + str([hex(ord(c)) for c in o]))
    else:
        jitter.func_ret_stdcall(ret_ad, -1)
        raise ValueError('unknown sysinfo class ' + hex(args.ProcessInformationClass))
    jitter.func_ret_stdcall(ret_ad, 0)

class systeminfo:
    oemId = 0
    dwPageSize = 0x1000
    lpMinimumApplicationAddress = 0x10000
    lpMaximumApplicationAddress = 0x7ffeffff
    dwActiveProcessorMask = 0x1
    numberOfProcessors = 0x1
    ProcessorsType = 586
    dwAllocationgranularity = 0x10000
    wProcessorLevel = 0x6
    ProcessorRevision = 0xf0b

    def pack(self):
      return struct.pack('IIQQQIIIHH',
        self.oemId,
        self.dwPageSize,
        self.lpMinimumApplicationAddress,
        self.lpMaximumApplicationAddress,
        self.dwActiveProcessorMask,
        self.numberOfProcessors,
        self.ProcessorsType,
        self.dwAllocationgranularity,
        self.wProcessorLevel,
        self.ProcessorRevision)


def WincoreSysinfo_GetSystemInfo(jitter):
  ret_ad, args = jitter.func_args_stdcall(["sys_ptr"])
  sysinfo = systeminfo()
  jitter.vm.set_mem(args.sys_ptr, sysinfo.pack())
  jitter.func_ret_stdcall(ret_ad, 0)

win64_methods = { \
                'api-ms-win-core-processthreads-l1-1-2_GetCurrentProcessId': kernel32_GetCurrentProcessId, \
                'api-ms-win-core-processthreads-l1-1-2_GetCurrentThreadId': kernel32_GetCurrentThreadId, \
                'api-ms-win-core-sysinfo-l1-2-1_GetSystemTimeAsFileTime': kernel32_GetSystemTimeAsFileTime, \
                'api-ms-win-core-memory-l1-1-3_VirtualProtectFromApp':kernel32_VirtualProtect, \
                'api-ms-win-core-sysinfo-l1-2-1_GetSystemInfo':WincoreSysinfo_GetSystemInfo, \
                'api-ms-win-core-memory-l1-1-3_VirtualQuery':kernel32_VirtualQuery, \
                'api-ms-win-core-sysinfo-l1-2-1_GetTickCount64':kernel32_GetTickCount64, \
                'kernel32_GetTickCount64':kernel32_GetTickCount64, \
                'api-ms-win-core-profile-l1-1-0_QueryPerformanceCounter':kernel32_QueryPerformanceCounter, \
                'kernel32_QueryPerformanceCounter':kernel32_QueryPerformanceCounter, \
                'kernel32_FreeLibrary':kernel32_FreeLibrary, \
                'msvcr110__initterm':msvcr110__initterm_both, \
                'msvcr110__initterm_e':msvcr110__initterm_both, \
                'api-ms-win-crt-runtime-l1-1-0__initterm_e':msvcr110__initterm_both, \
                'ntdll_NtQueryInformationProcess':ntdll_NtQueryInformationProcess, \
                'kernel32_GetCurrentProcess':kernel32_GetCurrentProcess, \
                }

def stop_run(jitter):
  raise UnpackerException('Reached Real EntryPoint')

def main():
  # Use our memory tracker
  JitCore_Python.SymbExecClass = ESETrackMemory
  # Parse arguments
  parser = Sandbox_Win64.parser(description="PE sandboxer")
  parser.add_argument("filename", help="PE Filename")
  options = parser.parse_args()
  # Load NT header
  options.load_hdr = True
  options.align_s = False
  options.jitter = "llvm"
  #options.jitter = "python"
  options.dependencies = True
  options.use_seh = True
  print(options)
  sb = Sandbox_Win64(options.filename, options, custom_methods=win64_methods)
  # TODO Mark the end of the run
  #sb.jitter.add_breakpoint(0xFFEEFFEE, stop_run)
  # Run until we blow up on some init call
  print('Start at ' + str(time.ctime()))
  start = time.time()
  try:
    # Eventually run TLS callbacks here
    # Run at entrypoint
    entrypoint = sb.pe.rva2virt(sb.pe.Opthdr.AddressOfEntryPoint)
    print('STARTING at '  + hex(entrypoint))
    sb.run(entrypoint)
  except UnpackerException as e:
    print('STOPPING at 0x%x: %s' % (sb.jitter.pop_uint64_t(), str(e)))
  stop = time.time()
  print('total runtime: ' + str(datetime.timedelta(seconds=stop-start)))
  print(sb.pe.SHList)
  # Ovewrite all PE sections
  for s in sb.pe.SHList:
    print('%s: %x-%x (%x bytes)' % (s.name, s.offset, s.offset+s.size, s.size))
    livedata = sb.jitter.vm.get_mem(sb.pe.rva2virt(s.addr), s.rawsize)
    # Overwrite section data
    s.data = livedata
  # TODO Fix OEP here
  #sb .pe.Opthdr.AddressOfEntryPoint = 0xFFEEFFEE
  newpe = bytearray(sb.pe.get_bytes_no_crc())
  # Copy the DOS stub manuall as it is skipped by pefile
  newpe[len(sb.pe.Doshdr):sb.pe.Doshdr.lfanew] = sb.pe[len(sb.pe.Doshdr):sb.pe.Doshdr.lfanew]
  with open(basename(options.filename[:-4]) + '_unpacked_wheader.exe', 'wb') as f:
    import pdb; pdb.set_trace()
    f.write(bytes(newpe))
  print('done')

if __name__ == "__main__":
  main()
