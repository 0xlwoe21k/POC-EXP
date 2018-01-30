#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Dump dex file for IDA v7+
# (My IDA Python Plugin)
# python 3.6.3 32bit
# Created by B.S.
# 2018/01/25

import idaapi
import struct


def dumpdex(start, size, target):
    rawdex = idaapi.dbg_read_memory(start, size)
    fd = open(target, 'wb')
    fd.write(rawdex)
    fd.close()

def getdexsize(start):
    pos = start + 0x20
    # 在调试模式下才能获取到值
    mem = idaapi.dbg_read_memory(pos, 4)
    # 小端 <
    # natvie @ 和 = 或者无
    # native byteorder
    # 大端 > 和 !;
    # data from a sequence, network byteorder
    size = struct.unpack('<I', mem)[0]
    print('size is ' + str(hex(size)))
    print('size is 0x%08x') % (size)
    return int(size)

# -----------------------------------------------------------------------
def print_banner():
    # native byteorder
    buffer = struct.pack("ihb", 1, 2, 3)
    print repr(buffer)
    print struct.unpack("ihb", buffer)
    # data from a sequence, network byteorder
    data = [1, 2, 3]
    buffer = struct.pack("!ihb", *data)
    print repr(buffer)
    print struct.unpack("!ihb", buffer)
    banner = [
    "Python %s " % sys.version,
    "IDAPython" + (" 64-bit" if __EA64__ else "") + " v%d.%d.%d %s (serial %d) (c) The IDAPython Team <idapython@googlegroups.com>" % IDAPYTHON_VERSION,
    "\t\tDump Dex file for IDA v7+ \n\tCreated by B.S. on 2018/01/25 @python 3.6.3 32bit",
    ]
    #sepline = ('*' * (max([len(s) for s in banner])+1))
    sepline = ('❤' * 50)


    print(sepline)
    print("\n".join(banner))
    print(sepline)


# 输出脚本信息
print_banner()
start = AskAddr(GetRegValue("r0"), 'Input DexFile start in hex: ')
#start = AskAddr(0x00403360, 'Input DexFile start in hex: ')
print('start is ' + str(hex(start)))
print('start is 0x%08x') % (start)


size = AskLong(getdexsize(start), 'Input DexFile size in hex: ')


target = AskStr('c:/dump-0x%08x-%d.dex' % (start, size), 'Input the dump file path')


if size > 0 and start > 0x0 and target and AskYN(1, 'start is 0x%08x, size is %d, \ndump to %s' % (start, size, target)) == 1:
    dumpdex(start, size, target)
    print('Success to save as %s\nDump Finish!!! --Created by B.S.' % (target))

