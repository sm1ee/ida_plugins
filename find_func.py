from idaapi import *
danger_funcs = ["lstrcpyW","sprintf", "strcmp","strncpy","system"]
for func in danger_funcs:
    addr = LocByName( func )
    if addr != BADADDR:
        cross_refs = CodeRefsTo( addr, 0 )
        print "Cross References to %s" % func
        print "-------------------------------"
        for ref in cross_refs:
            print "%08x" % ref
            SetColor( ref, CIC_ITEM, 0x0000ff)
 
print "End!"