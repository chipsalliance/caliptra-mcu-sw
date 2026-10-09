#!/usr/bin/env python3
"""Development UART entropy supplier. Install pyserial; no automatic command retries."""
import argparse
import os
import struct
import time
from functools import reduce
from operator import xor

class LinkReplyError(RuntimeError):
    """The UART reply was missing or failed protocol validation."""

def packet(op, data=0, code=0):
    b=bytes([0xa5,op,code])+struct.pack('<I',data)
    return b+bytes([reduce(xor,b),0x5a])

class Link:
    def __init__(self, port, baud):
        import serial
        self.s=serial.Serial(port,baud,timeout=2,write_timeout=2,rtscts=False,dsrdtr=False)
        self.s.reset_input_buffer()
    def call(self,op,data=0):
        self.s.write(packet(op,data));self.s.flush()
        response=self.s.read(9)
        if len(response)!=9 or response[0]!=0xa5 or response[-1]!=0x5a or response[1]!=(op|0x80) or reduce(xor,response[:7])!=response[7]:
            raise LinkReplyError('Missing/invalid reply; no retry sent. Check baud, cable and FPGA status.')
        if response[2]:raise RuntimeError(f'FPGA rejected op {op}: code {response[2]}')
        return struct.unpack('<I',response[3:7])[0]
    def resync(self,delay=0.05):
        time.sleep(delay)
        self.s.reset_input_buffer()
    def close(self):self.s.close()

def describe(value):
    return dict(mode='HOST' if value&1 else 'DEVELOPMENT',running=bool(value&2),
                empty=bool(value&4),full=bool(value&8),starved=bool(value&16),free_words=value>>16)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port',required=True,help='/dev/ttyUSB0 or COM5')
    p.add_argument('--baud',type=int,default=115200)
    p.add_argument('action',choices=['status','local','hold-host','feed'])
    args=p.parse_args();link=Link(args.port,args.baud)
    try:
        if args.action=='status':print(describe(link.call(1)));return
        if args.action=='local':
            link.call(2,0);time.sleep(0.01);link.call(4)
            print('DEVELOPMENT source enabled; subsystem restarted. NOT secure entropy.');return
        link.call(2,1);time.sleep(0.01)
        if args.action=='hold-host':print('HOST selected; subsystem held in reset.');return
        # Prefill before reset release. OS random bytes are development stimulus;
        # this transport/source chain is not a validated entropy system.
        for _ in range(256):link.call(3,int.from_bytes(os.urandom(4),'little'))
        link.call(4)
        print('HOST running; supplying OS random data. Ctrl-C holds subsystem in reset.')
        last=0
        while True:
            status=link.call(1);free=status>>16
            for _ in range(min(free,64)):
                link.call(3,int.from_bytes(os.urandom(4),'little'))
            if time.monotonic()-last>2:
                print(describe(status),flush=True);last=time.monotonic()
            if free==0:time.sleep(0.002)
    except KeyboardInterrupt:
        try:link.call(2,1);print('\nSubsystem held in HOST reset.')
        except Exception as e:print(f'Could not confirm reset: {e}')
    finally:link.close()

if __name__=='__main__':main()
