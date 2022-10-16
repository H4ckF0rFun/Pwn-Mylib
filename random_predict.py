from z3 import *

def solve(rs)->list:
    '''
    要求，根据 足够多的数求出初始的randtable
    '''
    init_table = [BitVec('rand_%d'%i,32) for i in range(31)]
    rand_table = [BitVec('rand_%d'%i,32) for i in range(31)]

    s = Solver()
    '''
    0 - 30
    far = r + 3
    生成过程
    r = (*fptr+*rptr)>>1
    *fptr = *fptr+*rptr
    fptr++,rptr++
    '''
    f = 3
    r = 0

    # rand_table[f] += rand_table[r]
    # r = (r + 1 ) % 31
    # f = (f + 1) % 31
    for i in range(len(rs)):
        s.add((((rand_table[f] + rand_table[r])>>1)&0x7fffffff) == rs[i])
        rand_table[f] += rand_table[r]
        r = (r + 1 ) % 31
        f = (f + 1) % 31

    init_t = []
    if s.check() == sat:
        print('solve success!')
        #print(s.model())
        for i in range(31):
            init_t.append(int('%s' % s.model()[init_table[i]]))
        return init_t
    return None


#生成第随机数
def generateRandom(ord,init):
    result = 0
    #copy table.
    table = []
    for t in init:
        table.append(t)
    
    f = 3
    r = 0

    for i in range(ord):
        result = ((table[f] + table[r])>>1)&0x7fffffff
        table[f] += table[r]
        r = (r + 1 ) % 31
        f = (f + 1) % 31
    return result
