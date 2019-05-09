from idaapi import *
from idc import *

#text_seg = SegByName('.text')
#text_seg = idaapi.get_segm_by_name('.text')
#start = text_seg.startEA
#end = text_seg.endEA


print "[+] Start Create Function\n"

addr = ScreenEA()
print "Screen : 0x{:02x}".format(addr)

addr = SegStart(addr)
print "SegStart : 0x{:02x}".format(addr)

end_addr = SegEnd(addr)
print "SegEnd : 0x{:02x}".format(end_addr)


while True:
	
	flag = GetFlags(addr)

	if addr == BADADDR or addr >= end_addr:
		break

	if isAlign(flag):
		print ".align : 0x{:02x}".format(addr)
		addr = NextHead(addr)

	if not isCode(flag):
		print "MakeCode : 0x{:02x}".format(addr)
		MakeCode(addr)

	if not get_func(addr):
		print "MakeFunction : 0x{:02x}".format(addr)
		MakeFunction(addr)

	#print "addr : 0x{:02x}".format(addr)
	addr = NextHead(addr)

print "\n[-] End..."
print "[-] created by smlee"
