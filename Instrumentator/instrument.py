import lief
import os
import struct
import argparse

from random import randrange
from herpatcher.binary import Binary
from herpatcher.hchanges.hchange import AddInstructionChange,RemoveInstructionChange,ReplaceInstructionChange
from herpatcher.hdisasm.hasm import asm
from herpatcher.hanalysis.hcoherence_analysis import RIPDataCoherenceAnalysis
from herpatcher.hanalysis.hcoherence_analysis import SymbolCoherenceAnalysis
from herpatcher.hexception.cfg_exception import NodeNotFoundException


class FunctionAdder:
    def __init__(self,path_to_executable,executable_name,path_to_shared_library,output_file_name):
        

        self.path=path_to_executable
        self.file_name=executable_name
        self.out_file_name=output_file_name

        self.main_address=None
        self.instrumentation_address=None
        self.my_got_addr=None
        self.my_data_addr=None

        #First of all I've saved another file with the addition of mygot section, mydata section and relocation entry for __afl_area_ptr
        self.__add_library_and_relocation_entry__(
            lief.parse(self.path+self.file_name),
            path_to_shared_library)
        print("[+] Binary modified with new sections")
        print(f"     [-]My got address={hex(self.my_got_addr)}")
        print(f"     [-]My data address={hex(self.my_data_addr)}")


        self.binary=Binary(self.path+self.out_file_name)
        self.is_stripped=self.__check_if_stripped__()
        print(f"[+] The binary is {"stripped" if self.is_stripped else "not stripped"}")

        self.__find_addresses_of_constructor_functions__()
        if self.functions_addresses is not None:
            print("[+] The addresses of the functions are =")
            for f in self.functions_addresses:
                print(f"     [-] name={f["fname"]} start={hex(f["addresses"][0])} end={hex(f["addresses"][1])}")

        self.__find_addresses_of_main__()
        print(f"[+]\n     [-] The main address is {hex(self.main_address)}\n     [-] The instrumentation address is {hex(self.instrumentation_address)}")


        self.max_idx=1<<16

        self.__init_prev_instrumentation__()
        print("[+] The startup instrumentation has been inserted")


    def __add_library_and_relocation_entry__(self,elf,library_path):
        #
        # Add the dependency to libforkserver.so
        # Create the symbol for __afl_area_ptr and for address of the forkserver init call
        # Then I've created a relocation for these 2 symbols in such a way that are found in the libforkserver.so
        # Create 2 new sections. The first is used for relocations and the second for the data
        #
        elf.add_library("libforkserver.so")
        elf.add(lief.ELF.DynamicEntryRunPath(library_path)) 
        got_slot_addr=self.__create_mygot_section__(elf)
   
        afl_area_symbol=self.__create__afl_area_ptr_symbol__(elf)
        forkserver_start_symbol=self.__create__forkserver_start_ptr_symbol__(elf)
        self.__add_relocation__(got_slot_addr,afl_area_symbol,elf,forkserver_start_symbol)
        mydata_addr=self.__add_data_section__(elf)

        self.my_got_addr=got_slot_addr
        self.my_data_addr=mydata_addr

        elf.write(self.path+self.out_file_name)

    def __create_mygot_section__(self,elf):
        #
        # Create a new section that will contains the relocations
        # __afl_area_ptr is stored at .my_got
        # __forkserver_start_ptr is stored at .my_got+8
        #
        sec = lief.ELF.Section()
        sec.name    = ".my_got"
        sec.type    = lief.ELF.Section.TYPE.PROGBITS
        sec.flags   = lief.ELF.Section.FLAGS.ALLOC | lief.ELF.Section.FLAGS.WRITE
        sec.content = bytearray(16)
        sec.alignment = 8

        added_sec = elf.add(sec,loaded=True)
        return added_sec.virtual_address

    def __create__afl_area_ptr_symbol__(self,elf):
        sym = lief.ELF.Symbol()
        sym.name = "__afl_area_ptr"
        sym.type = lief.ELF.Symbol.TYPE.OBJECT
        sym.binding = lief.ELF.Symbol.BINDING.GLOBAL
        sym.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
        sym.value = 0
        sym.size = 8
        return elf.add_dynamic_symbol(sym)
    
    def __create__forkserver_start_ptr_symbol__(self,elf):
        sym = lief.ELF.Symbol()
        sym.name = "__forkserver_start_ptr"
        sym.type = lief.ELF.Symbol.TYPE.OBJECT
        sym.binding = lief.ELF.Symbol.BINDING.GLOBAL
        sym.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
        sym.value = 0
        sym.size = 8
        return elf.add_dynamic_symbol(sym)

    def __add_relocation__(self,got_addr,area_sym,elf,forkserver_start_ptr):
        #
        # Add the relocation entry for the __afl_area_ptr and __forkserver_start_ptr
        #
        area_rel = lief.ELF.Relocation(
            got_addr,
            lief.ELF.Relocation.TYPE.X86_64_GLOB_DAT,
            lief.ELF.Relocation.ENCODING.RELA
        )
        area_rel.purpose = lief.ELF.Relocation.PURPOSE.DYNAMIC
        area_rel.addend = 0
        area_rel.symbol = area_sym

        forkserver_start_rel=lief.ELF.Relocation(
            got_addr+8,
            lief.ELF.Relocation.TYPE.X86_64_GLOB_DAT,
            lief.ELF.Relocation.ENCODING.RELA
        )
        forkserver_start_rel.purpose = lief.ELF.Relocation.PURPOSE.DYNAMIC
        forkserver_start_rel.addend = 0
        forkserver_start_rel.symbol = forkserver_start_ptr

        elf.add_dynamic_relocation(area_rel)
        elf.add_dynamic_relocation(forkserver_start_rel)
    
    def __add_data_section__(self,elf):
        #
        # Create .mydata section
        # It will contains some parameters used 
        # .mydata+0x10 ==> index of previus basic block
        # .mydata+0x20 ==> saved address of shared memory
        # .mydata+0x30 ==> saved rax
        # .mydata+0x40 ==> saved rbx
        #
        section = lief.ELF.Section(".mydata")
        #This string is used only because AFL check for the presence of that string into the target binary
        filler=b"\x00"*100#This filler is used to set the dimension of the new nection
        section.content=list("__AFL_SHM_ID".encode("utf-8")+filler)
        #afl search within the target file if the __AFL_SHM_ID string is present
        #so i set the content of the new section to contain it. This is only for compatibility
        section.type = lief.ELF.Section.TYPE.PROGBITS
        section.flags = (
            lief.ELF.Section.FLAGS.ALLOC|
            lief.ELF.Section.FLAGS.WRITE
        )       
        elf.add(section,loaded=True)
        return elf.get_section(".mydata").virtual_address
#########################################################################################################
# End of the function needed to add sections and relocation
# Start of help function to analyze the binary
#########################################################################################################

    def __check_if_stripped__(self):
        return self.binary.header_manager._elf.get_section(".symtab") is None


    def __find_first_available_address__(self,addr):
        #
        # Given an address that correspond to the beginning of a function try to bypass the function preamble
        #
        preamble_instructions=['endbr64', 'endbr32', 'push', 'mov', 'sub'] 
        bb=self.binary.cfg.get_basic_block_containing(addr)
        for instr_addr in bb.instructions:
            instr=bb.instructions[instr_addr]
            if instr.op_code not in preamble_instructions:
                return instr_addr
            if instr.op_code == "mov" or instr.op_code =="sub":
                preamble_instructions.remove(instr.op_code)
        return None

    def __find_addresses_of_main__(self):
        #
        # Find the address of the main. It works both if the binary is stripped and not stripped
        #
        cfg = self.binary._disassembler._angr_cfg
        main_func = cfg.kb.functions.get('main')
        if main_func is None:
            print("Error in finding main")
            return None

        try:
            self.main_address=self.binary.cfg.get_basic_block_containing(main_func.addr).addr
        except NodeNotFoundException :
            self.main_address=main_func.addr - self.binary._disassembler._project.loader.main_object.mapped_base

        finally:
            self.instrumentation_address=self.__find_first_available_address__(
                self.main_address
            )

        
    def __find_addresses_of_constructor_functions__(self):
        #
        # Given some functions that we don't want to instrument try to find their address ranges
        #
        self.functions_addresses=[]
        if not self.is_stripped:
            self.functions_addresses=[]
            cfg=self.binary._disassembler._angr_cfg
            functions_name=["_start","deregister_tm_clones","register_tm_clones","__do_global_dtors_aux","frame_dummy"]
            for f_name in functions_name:
                func=cfg.kb.functions.get(f_name)
                if func is not None:
                    self.functions_addresses.append({
                        "fname":f_name,
                        "addresses":(func.addr,func.addr+func.size)})


    def __printProgressBar__ (self,iteration, total):
            if iteration%50==0:
                fill = '█'
                percent = ("{0:." + str(1) + "f}").format(100 * (iteration / float(total)))
                filledLength = int(80 * iteration // total)
                bar = fill * filledLength + '-' * (80 - filledLength)
                print(f'\r{""} |{bar}| {percent}%  {iteration} out of {total} {""}', end = "\r")
                # Print New Line on Complete
            if iteration == total: 
                print()

#########################################################################################################
# End of the help function needed to analyze the binary
# Start of functions used to instrument the initial isntructions
#########################################################################################################
    def __compute_init_instrumentation__(self):
        #
        # The initial instructions to be inserted at the beginning of the main are the following
        # push rsi
        # push rdi
        # |-----------> Since at the beginning of the main the only parameters used are argc,argv these are saved

        # mov rax, QWORD PTR[rip + offset_to_forkserver_start_ptr]
        # mov rax, [rax]
        # call rax
        # |-----------> Load the address of relocated __forkserver_start_ptr, dereference it until we find the actual address of the function and then call it

        # pop rdi
        # pop rsi
        # |-----------> Restore the initial state

        # mov WORD PTR[rip + offset_to_precedent_bb_saved], <random_number>
        # |-----------> Initialize the prev value into my section

        # mov rax, QWORD PTR[rip + offset_to_shared_memory_relocation]
        # mov rax, QWORD PTR [rax]
        # mov QWORD PTR[rip + offset_to_saved_shared_memory_address], rax
        # |-----------> Load the address of relocated __afl_area_ptr, dereference it until we find the actual address of the shared memory
        #
        prev_offset=self.my_data_addr+0x10-self.instrumentation_address-9 #the mov instruction need 9 bytes
        #To optimize the assembly and avoid many memory access, i write the address of the shared memory directly into my_data section at offset 0x20
        shared_offset=self.my_data_addr+0x20-self.instrumentation_address-7
        got_offset_sharedmem=self.my_got_addr-self.instrumentation_address-7 
        got_offset_forkserver=(self.my_got_addr+0x8)-self.instrumentation_address-7
        instructions=[ 
            "push rsi",
            "push rdi",
            f"mov rax, QWORD PTR [rip {"+" if got_offset_forkserver>0 else "-"} {hex(abs(got_offset_forkserver))}]",
            "mov rax, [rax]",
            "call rax",
            "pop rdi",
            "pop rsi",
            f"mov WORD PTR[rip {"+" if prev_offset>0 else "-"} {hex(abs(prev_offset))}], {randrange(self.max_idx)}",
            f"mov rax, QWORD PTR [rip {"+" if got_offset_sharedmem>0 else "-"} {hex(abs(got_offset_sharedmem))}]",
            "mov rax, QWORD PTR [rax]",
            f"mov QWORD PTR[rip {"+" if shared_offset>0 else "-"} {hex(abs(shared_offset))}], rax"
        ]
        instructions.reverse()
        return instructions


    def __init_prev_instrumentation__(self):
        length=0
        
        instructions=self.__compute_init_instrumentation__()
        l=len(instructions)
        for i in range(l):
            instruction=instructions[i]
            assembled=asm(instruction)
            length+=len(assembled)
            AddInstructionChange(self.instrumentation_address,assembled,[]).modify(
                self.binary.cfg
            )
            tmp=self.binary.header_manager.get_section(".mydata")
            if self.my_data_addr!=tmp.addr:
                #In this case it means that the segment is full and has been expanded
                #Expanding the .text segment cause my nection to shift
                self.my_data_addr=tmp.addr
                self.my_got_addr=self.binary.header_manager.get_section(".my_got").addr
                instructions=self.__compute_init_instrumentation__()
                assembled_instruction=asm(instructions[i])
                RemoveInstructionChange(self.instrumentation_address,[]).modify(self.binary.cfg)
                AddInstructionChange(self.instrumentation_address,assembled_instruction,[]).modify(
                    self.binary.cfg
                )
                print(f"        [!] Segment shift. New data location ={hex(self.my_data_addr)}, my got addr={hex(self.my_got_addr)} while instrumenting {hex(self.instrumentation_address)} of init instrumentation")

        
        print(f"     [-] Startup instrumentation size={hex(length)}")
        if not self.is_stripped:
            self.binary.header_manager._elf.get_symbol("main").size+=length
            self.binary.header_manager._elf.get_section(".text").size+=length

#########################################################################################################
# End of functions used to instrument the initial isntructions
# Start of edge coverage tracing instruction instrumentation functions
#########################################################################################################

    def __compute_instructions__(self,addr):
        #
        # The AFL shared update if in the form of
        # shared_map[prev^curr]++;
        # prev=cur>>1;

        # In each instrumentation point the instructions added to the binary are

        # mov QWORD PTR[rip + offset_to_saved_rax], rax                   |-> save the register
        # movzx rax, WORD PTR[rip + offset_to_precedent_bb_saved]         |-> move prev from memory to rax register
        # xor ax, <random_current>                                        |-> compute the xor between current and prev
        # add rax, QWORD PTR[rip + offset_to_saved_shared_memory_address] |-> since the shared map is an array, 
        #                                                                     the index to be incremented is 
        #                                                                     computed as 
        #                                                                     <address_of_first_element>
        #                                                                     +
        #                                                                     <prev^curr>
        # inc BYTE PTR[rax]                                               
        # mov WORD PTR[rip + offset_to_precedent_bb_saved],<right_shifted_curr>
        #                                                                 |-> prev=curr>>1, the right shift 
        #                                                                     is computed by the instrumentator
        #                                                                     and into the instrumented code
        #                                                                     is writted the shifted value
        # mov rax, QWORD PTR[rip + offset_to_saved_rax]"                  |-> restore rax

        #                                                                 
        # 
        current_idx=randrange(self.max_idx)#  Extract a index
        next_prev=current_idx>>1


        #move prev value into ax zeroing the others bits of rax
        prev_offset= self.my_data_addr+0x10-addr-8 #Since at my_data_addr there is the string I've written prev ad +0x10 offset
        prev_load=f" movzx rax, WORD PTR[rip {"+" if prev_offset>0 else "-"} {hex(abs(prev_offset))}]"

        #move the right shifted value of current into the memory region where prev is
        prev_save=f"mov WORD PTR[rip {"+" if (prev_offset-1)>0 else "-"} {hex(abs(prev_offset-1))}], {hex(next_prev)}"
        #prev_offset-1 is needed because the prev_load instruction needs 8 bytes, insted the mov needs 9 bytes

        #move in rbx the address of the shared memory that previusly was saved in my data region
        shared_offset=self.my_data_addr+0x20-addr-7 
        shared_load=f" add rax, QWORD PTR[rip {"+" if shared_offset>0 else "-"} {hex(abs(shared_offset))}]"

        #The rax and rbx registers are saved in my data region
        rax_save_offset=self.my_data_addr+0x30 -addr-7

        save_rax_instruction=f"mov QWORD PTR[rip {"+" if (rax_save_offset)>0 else "-"} {hex(abs(rax_save_offset))}], rax"
        restore_rax_instruction=f"mov rax, QWORD PTR[rip {"+" if (rax_save_offset)>0 else "-"} {hex(abs(rax_save_offset))}]"


        instructions=[

            save_rax_instruction,
            prev_load,
            "xor ax, "+hex(current_idx), #performing xor between the prev saved in ax and current that is in memory
            shared_load,
            "inc BYTE PTR[rax]", #Increment by one the hash map (shared bitmap)
            prev_save,
            restore_rax_instruction
        ]
        return [asm(instr) for instr in instructions]

    def __instrument_location__(self,addr,sym):
        #
        # Given an instrumentation address actually add the instructions at the address
        #
        length=0
        assembled_instructions=self.__compute_instructions__(addr)

        num_instrucitons=len(assembled_instructions)

        for i in range(num_instrucitons-1,-1,-1):
            assembled=assembled_instructions[i]
            length+=len(assembled)
            AddInstructionChange(addr,assembled,[]).modify(
                self.binary.cfg
            )

            #Check if the instrumentation has moved the next sections of the binary
            tmp=self.binary.header_manager.get_section(".mydata")
            if self.my_data_addr!=tmp.addr:
                self.my_data_addr=tmp.addr
                self.my_got_addr=self.binary.header_manager.get_section(".my_got").addr
                assembled_instructions=self.__compute_instructions__(addr)
                RemoveInstructionChange(addr,[]).modify(self.binary.cfg)
                AddInstructionChange(addr,assembled_instructions[i],[]).modify(
                    self.binary.cfg
                )
                print(f"        [!] Segment shift. New data location ={hex(self.my_data_addr)}, my got addr={hex(self.my_got_addr)} while instrumenting {hex(addr)} i={num_instrucitons-i-1} out of {num_instrucitons}")

        if not self.is_stripped and sym is not None:
            sym.size+=length#Increment the size of the function while the instructions are added
        return length

    def __actual_instrumentation__(self,instrument_locations):
        #
        # Order all the instrument locations passed as parameter 
        # Then reconstruct the address of the instrument location, check if at that address there is the beginning of a function and in that case try to bypass the preamble
        #
        instrument_locations=sorted(instrument_locations,key=lambda il:il["addr"])
        bbs=[(il["label"],il["symbol"]) for il in instrument_locations]
        total=len(bbs)
        i=0
        for label in bbs:
            bb=self.binary.cfg.get_block(label[0])
            instr_addr=bb.addr
            if bb.instructions[bb.addr].op_code=="endbr64" or bb.instructions[bb.addr].op_code=="endbr32":#In this case we have to avoid the preamble
                instr_addr=self.__find_first_available_address__(bb.addr)
        
            instr_length=self.__instrument_location__(instr_addr,label[1])
            i+=1
            #If the instrumented location is before main I've incremented the address of main
            if bb.addr<self.main_address:
                self.main_address+=instr_length
            self.__printProgressBar__(i,total)
            

    def __find_function_symbol__(self,instrumentation_address):
        #
        # Given an instrumentation address find its symbol
        #
        for sym in self.binary.header_manager._elf.symbols:
            if sym.type != lief.ELF.Symbol.TYPE.FUNC:
                continue
            start = sym.value
            end   = start + sym.size
            if start <= instrumentation_address < end:
                return sym
        return None

    

    def __check_if_already_in_queue__(self,queue,new_succ):
        labels=[succ[1].label for succ in queue]
        return new_succ.label in labels

    def __check_if_is_code_function__(self,successor,code_ranges):
        if code_ranges[0]<=successor.addr<=code_ranges[1]:#Ok we're in the .text section
            for f in self.functions_addresses:#Check if the successor falls into a constructor function (i.e. frame_dummy)
                if f["addresses"][0]<=successor.addr<f["addresses"][1]:
                    return False
            return True
        return False#If it doesn't fall into a .text region we return false


    def __extract_successors_of_a_block__(self,code_ranges,already_visited,queue,current):
        ret=[]
        successors=self.binary.cfg.successors(current)
        for successor in successors:
            if successor.label not in already_visited and not self.__check_if_already_in_queue__(queue,successor) and self.__check_if_is_code_function__(successor,code_ranges) :
                fun=self.binary._disassembler._angr_cfg.kb.functions.floor_func(successor.addr)
                if fun is None or "libc" not in fun.name:
                    ret.append(successor)

        return ret


    def __add_location_to_be_instrumented__(self,instrument_addresses,current):
        #If the biniary is not stripped we append also the symbol of the function
        if not self.is_stripped:
            sym=self.__find_function_symbol__(current.addr)

        instrument_addresses.append({
            "addr":current.addr,
            "label":current.label,
            "symbol":sym if not self.is_stripped else None})
        print(f'\r{""}    [-] {len(instrument_addresses)} locations found', end = "\r")


    def instrument_basic_blocks(self):
        instrument_addresses=[]
        #If the binary is not stripped the main ranges are obtained with the symbol

        text_section=self.binary.header_manager._elf.get_section(".text")
        code_range=(text_section.virtual_address,text_section.virtual_address+text_section.size)
        
        first_bb=self.binary.cfg.get_basic_block_containing(self.main_address)
        
        queue=[]
        already_visited=[first_bb.label]
        succs=self.__extract_successors_of_a_block__(code_range,already_visited,queue,first_bb)
        [queue.append((first_bb,s)) for s in succs]
        while len(queue)>0:
            #At position 0 there is the predecessor, in position 1 there is the current edge
            current_edge=queue.pop()
            #If the precedent basic block last instruction in a call this means that the edge has not to be considered
            
            current=current_edge[1]

            if current_edge[0].last_instruction[1].op_code != "call":
                #If the last instruction was not a call I instrument always
                self.__add_location_to_be_instrumented__(instrument_addresses,current)
                

            already_visited.append(current.label)
            
            successors=self.__extract_successors_of_a_block__(code_range,already_visited,queue,current)

            [queue.append((current,s)) for s in successors]

        print()
        print(f"[+] Found {len(instrument_addresses)} locations to be instrumented")
        self.__actual_instrumentation__(instrument_addresses)
        print(f"[+] Instrumented {len(instrument_addresses)} locations")

        print("[+] Starting the RIP Data Coherence Analysis")
        RIPDataCoherenceAnalysis().analyse(self.binary.cfg)
        self.binary.cfg.pop_and_execute()
        print("[+] RIP Data Coherence Analysis ended")
        print("[+] Starting the Symbol Coherence Analysis") 
        SymbolCoherenceAnalysis().analyse(self.binary.cfg)
        self.binary.cfg.pop_and_execute()
        print("[+] Symbol Coherence Analysis ended")
        self.binary.write(self.path+self.out_file_name)
        os.system(f"chmod +x {self.path+self.out_file_name}")
        
        print("[+] Written the patched binary in "+self.path+self.out_file_name)
        mism = self.check_header_offsets()
        if mism is not None:
            self.patch_header_offsets(mism)

    def check_header_offsets(self):
        binary = lief.parse(self.path+self.out_file_name)
        header = binary.header

        header_offset = header.program_header_offset

        mismatch = None

        for seg in binary.segments:
            if seg.type==lief.ELF.Segment.TYPE.PHDR :
                real_offset=seg.file_offset
                if real_offset != header_offset:
                    print(f"[+] Found a E_PHOFF mismatch. e_phoff={hex(header_offset)}, PT_PHDR={hex(real_offset)}")
                    mismatch=real_offset
                    break
        return mismatch




    def patch_header_offsets(self, mismatch):
        with open(self.path+self.out_file_name, "r+b") as f:
            data = bytearray(f.read())

            struct.pack_into("<Q", data, 0x20, mismatch)
            print(f"    [-] Fix e_phoff : new e_phoff= {hex(mismatch)}")
            f.seek(0)
            f.write(data)

def main(args):
    shared_library_path=os.path.dirname(__file__)+"/executables/"

    FunctionAdder(args.p[0],args.s[0],shared_library_path,args.o[0]).instrument_basic_blocks()


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("-p", nargs=1, help="System path where the executable is located")
    parser.add_argument("-s", nargs=1,help="input source file to be instrumented")
    parser.add_argument("-o", nargs=1, help="output instrumented file to be written")
    main(parser.parse_args())
