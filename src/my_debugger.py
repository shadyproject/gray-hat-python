from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}

        #determine and store the default page size for the system
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

    def load(self, path_to_exe):
        #dwCreation flag detemines how to create the process
        #set creation_flag = CREATE_NEW_CONSOLE if you want 
        #to see the calculator GUI
        creation_flags = DEBUG_PROCESS

        #instantiate structs
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        #allow the started process to be shown in a seperate window
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        #initialize the cb variablke in the STARTUPINFO struct
        startupinfo.cb = sizeof(startupinfo)

        process_did_start = kernel32.CreateProcessA(path_to_exe, 
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_information))

        if process_did_start: 
            print "[*] We have successfully launched the process!"
            print "[*] PID: %d" % process_information.dwProcessId

            #obtain a handle to the process
            self.h_process = self.open_process(process_information.dwProcessId)

        else:
            err = kernel32.GetLastError()
            print "[*] Error 0x%08x." % err

    def read_process_memory(self, address, length):
        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)

        if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
            return False
        else:
            data += read_buf.raw
            return data

    def write_process_memory(self, address, data):
        count = c_ulong(0)
        length = len(data)

        c_data = c_char_p(data[count.value:])

        if not kernel32.WritePRocessMemory(self.h_process, address, c_data, length, byref(count)):
            return False
        else:
            return True

    def set_bp(self, address):
        if not self.breakpoints.has_key(address):
            try:
                #store the origina byte
                original_byte = self.read_process_memory(address, 1)

                #write the INT3 opcode
                self.write_process_memory(address, "\xCC")

                #register the breakpoint in our internal list
                self.breakpoints[address] = (address, original_byte)
            except:
                return False
        return True

    def set_hw_bp(self, address, length, condition):
        #make sure our length is valid
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1; #0 based index

        #check for valid condition
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        #check for available slots
        if not self.hardware_breakpoints.has_key(0):
            available = 0
        elif not self.hardware_breakpoints.has_key(1):
            available = 1
        elif not self.hardware_breakpoints.has_key(2):
            available = 2
        elif not self.hardware_breakpoints.has_key(3):
            available = 3
        else:
            return False

        #set the debug register in every thread
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            #enable the correct flag in DR7 register
            context.Dr7 |= 1 << (available * 2)

            #save the address of the breakpoint in the free register
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 == address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address

            #set the breakpoint condition
            context.Dr7 |= condition << ((available * 4) + 16)

            #set the length
            context.Dr7 |= length << ((available * 4) + 18)

            #set thread context with teh break set
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

            #update internal hw breakpoint array at the used slot index
            self.hardware_breakpoints[available] = (address, length, condition)

        return True

    def del_hw_bp(self, slot):
        #Disable the breakpoint for all active threads
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            #reset the flags to remove the breakpoint
            context.Dr7 &= ~(1 << (slot * 2))

            #zero out the address
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000

            #Remove the condition flag
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            #remove the length flag
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            #reset the threads context with the breakpoint removed
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))

        #remove the breakpoint from the internal list
        del self.hardware_breakpoints[slot]

        return True


    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process

    def attach(self, pid):
        self.h_process = self.open_process(pid)
        
        #attempt to call the process
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print "[*] Unable to attach to process."
            err = kernel32.GetLastError()
            print "0x%08x" % err

    def run(self):
        #poll for debugger events
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            #obtain thread and context information
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(self.h_thread)

            print "Event Code: %d Thread ID: %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)

            #if the event code is an exception, we want to examine it further
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                #grab the exception code
                exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                if exception == EXCEPTION_ACCESS_VIOLATION:
                    print "Access violation detected"
                #call our internal handler if there is a breakpoint
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif exception == EXCEPTION_GUARD_PAGE:
                    print "Guard Page access detected"
                elif exception == EXCEPTION_SINGLE_STEP:
                    self.exception_handler_single_step()

            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

    def exception_handler_single_step(self):
        #determine if this single step even occured in reaction to a hardware breakpoint and grab the hit breakpoint
        #according to intel docs, we should be able to check for the BSD flag in Dr6 but it appearst hat Windows isn't properly 
        #propagating the flag
        if (self.context.Dr6 & 0x1) and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif (self.context.Dr6 & 0x2) and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif (self.context.Dr6 & 0x4) and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif (self.context.Dr6 & 0x8) and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            #this wasn't an INT1 generated by a hardware breakpoint
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        if self.del_hw_bp(slot):
            continue_status = DBG_CONTINUE

        print "[*] Hardware breakpoint removed"
        return continue_status

    def exception_handler_breakpoint(self):
        print "[*] Inside the breakpoint handler."
        print "Exception Address: 0x%08x" % self.exception_address

        return DBG_CONTINUE

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print "[*] Finished debugging.  Exiting"
            return True
        else:
            print "There was an error detaching."
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if h_thread is not None:
            return h_thread
        else:
            print "[*] Could not obtain a valid thread handle."
            return False

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()

        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot is not None:
            #you have to set the size of the struct or the call will fail
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))

            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)

                success = kernel32.Thread32Next(snapshot, byref(thread_entry))

            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False

    def get_thread_context(self, thread_id=None, h_thread=None):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        #obtain a handle to the thread
        if h_thread is None:
            self.h_thread = self.open_thread(thread_id)

        if kernel32.GetThreadContext(self.h_thread, byref(context)):
            return context
        else:
            return False

    def func_resolve(self, dll, function):
        handle = kernel32.GetModuleHandleA(dll)
        address = kernel32.GetProcAddress(handle, function)

        kernel32.CloseHandle(handle)

        return address

