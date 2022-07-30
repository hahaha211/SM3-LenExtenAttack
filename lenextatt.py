import time
import random


MAX = 2 ** 32
FRONTS = 8
v1 = 0x13579acefdb8642013579acefdb8642013579acefdb8642013579acefdb86420
t = [0x79cc4519, 0x7a879d8a]
table={'0':'0000','1':'0001','2':'0010','3':'0011','4':'0100','5':'0101','6':'0110','7':'0111',
       '8':'1000','9':'1001','a':'1010','b':'1011','c':'1100','d':'1101','e':'1110','f':'1111'}
 
#十六进制数对应字符转4bit二进制字符串
def Hex2Bin(hexs):
    bins=''
    for i in hexs:
        bins+=table[i]
    return bins

#十进制数转定长二进制字符串
def Int2Bin(octs, ra):
    bins = list(bin(octs)[2:])
    #补零
    for i in range(0, ra - len(bins)):
        bins.insert(0, '0')
    return ''.join(bins)

#循环左移
def LoopLeftShift(a, k):
    res = list(Int2Bin(a, 32))
    for i in range(0,k):
        temp = res.pop(0)
        res.append(temp)
    return int(''.join(res), 2)

#消息扩展函数
def msgExten(b):
    w = []
    w1 = []
    for i in range(16):
        temp = b[i * 32:(i + 1) * 32]
        w.append(int(temp, 2))
    for j in range(16, 68, 1):
        f1 = LoopLeftShift(w[j - 3], 15)
        f2 = LoopLeftShift(w[j - 13], 7)
        f3 = P1(w[j - 16] ^ w[j - 9] ^ f1)
        f4 = f3 ^ f2 ^ w[j - 6]
        w.append(f4)
    for j in range(64):
        f1 = w[j] ^ w[j + 4]
        w1.append(f1)
    return w, w1

#消息填充函数
##填充规则：补足为64字节的倍数，先填充一个'1',之后填'0',最后8字节填充消息的长度
def fillFunc(mess):
    mess = bin(mess)[2:]
    for i in range(4):
        if (len(mess) % 4 == 0):
            break
        else:
            mess = '0' + mess
    length = len(mess)
    k = 448 - (length + 1) % 512
    if (k < 0): 
        k += 512
    addM = '1' + '0' * k + Int2Bin(length, 64)
    mess += addM
    return mess

def IterFunc(mess,vi):
    n = int(len(mess) / 512)
    v = []
    v.append(Int2Bin(vi, 256))
    for i in range(n):
        w, w1 = msgExten(mess[512 * i:512 * (i + 1)])
        temp = CF(v[i], mess[512 * i:512 * (i + 1)], w, w1)
        temp = Int2Bin(temp, 256)
        v.append(temp)
    return v[n]

def P0(X):
    return X ^ LoopLeftShift(X, 9) ^ LoopLeftShift(X, 17)

def P1(X):
    return X ^ LoopLeftShift(X, 15) ^ LoopLeftShift(X, 23)

def T(j):
    if j <= 15:
        return t[0]
    else:
        return t[1]

def FFj(X, Y, Z, j):
    if j <= 15:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (X & Z) | (Y & Z)


def GGj(X, Y, Z, j):
    if j <= 15:
        return X ^ Y ^ Z
    else:
        return (X & Y) | (un(X) & Z)


def un(a):
    a = Int2Bin(a, 32)
    b = ''
    for i in a:
        if i == '0':
            b += '1'
        else:
            b += '0'
    return int(b, 2)

def CF(vi, bi, w, w1):
    A = []
    for i in range(8):
        temp = vi[32 * i:32 * (i + 1)]
        A.append(int(temp, 2))
    for j in range(64):
        f1 = LoopLeftShift(A[0], 12)
        f2 = LoopLeftShift(T(j), j % 32)
        SS1 = LoopLeftShift((f1 + A[4] + f2) % MAX, 7)
        f3 = LoopLeftShift(A[0], 12)
        SS2 = SS1 ^ f3
        TT1 = (FFj(A[0], A[1], A[2], j) + A[3] + SS2 + w1[j]) % MAX
        TT2 = (GGj(A[4], A[5], A[6], j) + A[7] + SS1 + w[j]) % MAX
        A[3] = A[2]
        A[2] = LoopLeftShift(A[1], 9)
        A[1] = A[0]
        A[0] = TT1
        A[7] = A[6]
        A[6] = LoopLeftShift(A[5], 19)
        A[5] = A[4]
        A[4] = P0(TT2)
    temp = Int2Bin(A[0], 32) + Int2Bin(A[1], 32) + Int2Bin(A[2], 32) + \
           Int2Bin(A[3], 32) + Int2Bin(A[4], 32) + Int2Bin(A[5], 32) + \
           Int2Bin(A[6], 32) + Int2Bin(A[7], 32)
    temp = int(temp, 2)
    return temp ^ int(vi, 2)

def SM3(mess,vi):
    msg_1=fillFunc(mess)
    hex(int(msg_1,2))
    res=IterFunc(msg_1,vi)
    result=int(res,2)
    return result

#长度扩展攻击函数
def LenExtAtt(mess):
    print("攻击信息为%s"%mess)
    msg_1=fillFunc(mess)
    m1=int(msg_1,2)
    print("填充后的信息为\n%x"%m1)
    res=IterFunc(msg_1,v1)
    result=int(res,2)
    print("杂凑值SM3=%x"%result)
    #随机附带信息M2
    ran=random.randint(0,2**12)
    print("\n附带消息为%x"%ran)
    #初始常量IV改变
    v2=result
    msg_2='%x'%ran
    lens=int(len(mess))
    for i in range(lens):
        msg_2='0'+msg_2
    res2=SM3(msg_2,v2)
    print("msg_2=",msg_2)
    print("杂凑值SM3=%x"%res2)
    #msg=int(fillFunc(ran2),2)
    msg_3=m1*16**(len(hex(ran))-2)+ran
    print("\n伪造信息为\n%x"%msg_3)
    result3=SM3(hex(msg_3)[2:],v1)
    print("级联后杂凑值SM3=%x\n"%result3)
    #print("杂凑值SM3=%x\n"%int(IterFunc(hex(msg),v2),2))
    if result3==res2:
        print("攻击成功！")
        return
    print("攻击失败")
    return

if __name__ == '__main__':
    mess='a1a1a1a1a1a1a1'
    start = time.time()
    LenExtAtt(mess)
    end = time.time()
    times = end - start
    print('攻击耗时t=', times, 's',sep='')
