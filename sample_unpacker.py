from sys import argv
from os import remove
from winappdbg import Debug, HexDump, win32, HardwareBreakpoint, Process
from pefile import PE, SECTION_CHARACTERISTICS, DLL_CHARACTERISTICS

dbg  = None
process = None
filePath = None
threads = []

def fixup_file():
    pe = PE(filePath)
    for section in pe.sections:
        print 'Processing section: ' + section.Name.rstrip(' \t\r\n\0')
        # Read live section
        livesection = process.read(process.get_image_base()+section.VirtualAddress, section.SizeOfRawData)
        # Replace the text section with the data read from the live process
        pe.set_bytes_at_rva(section.VirtualAddress, livesection)
        # Make section RWX
        section.Characteristics |= SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] \
                                    | SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] \
                                    | SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']
    # Replace the entry point
    pe.OPTIONAL_HEADER.AddressOfEntryPoint += 0x14
    print "Set new binary's entrypoint to: " + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    # Write the new file
    newFile = filePath[:-4] + '_unpacked.exe'
    pe.write(newFile)
    print 'Wrote new file: ' + newFile
    # Kill the process
    dbg.kill_all()
    print 'ALL DONE'

def hw_break_at(tid, address):
        print 'Setting HW breakpoint at ' + hex(address)
        hwbp = dbg.define_hardware_breakpoint(tid, address, Debug.BP_BREAK_ON_EXECUTION, Debug.BP_WATCH_BYTE, True, None)
        dbg.enable_hardware_breakpoint(tid, address)

def events_handler(event):
    code = event.get_event_code()
    thread = event.get_thread()
    if code == win32.CREATE_PROCESS_DEBUG_EVENT:
        # Get the main thread
        tid = thread.get_tid()
        # Break after unpacking call
        hw_break_at(tid, process.get_entry_point()+0x9)
    elif code == win32.EXCEPTION_BREAKPOINT:
        # Get the current instruction pointer
        ip = thread.get_pc()
        # Print some info
        print '[%u] Hit breakpoint at %s' % (thread.get_tid(), hex(ip))
    elif code == win32.EXCEPTION_DEBUG_EVENT:
        if event.get_exception_code() == win32.EXCEPTION_SINGLE_STEP:
            print '[%u] Hit HW breakpoint at %s' % (thread.get_tid(), hex(thread.get_pc()))
            fixup_file()
    elif code == win32.EXIT_PROCESS_DEBUG_EVENT:
        print 'Debuggee process exited'
        # Delete the temp file
        remove(filePath)
        print 'Deleted the temp file'
    else:
        #print event
        pass

def create_noaslr_copy(originalFilePath):
    newPath = originalFilePath[:-4] + '_noaslr.exe'
    pe = PE(originalFilePath)
    pe.OPTIONAL_HEADER.DllCharacteristics &= \
        ~DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']
    pe.write(newPath)
    print 'Created temp no-aslr version of exe: ' + newPath
    return newPath

def main():
    if len(argv) > 1:
        global dbg, process, filePath
        # Make copy of file
        filePath = create_noaslr_copy(argv[1])
        # Debug the original exe
        dbg = Debug(events_handler)
        process = dbg.execv([filePath] + argv[2:], bBreakOnEntryPoint=True)
        dbg.loop()
    else:
        print argv[0] + '[EXE] [PARAMS]'
    return

if __name__ == '__main__':
    main()
