"""Independent integer/byte models; inputs are capped at the runtime's 16 bytes."""
import random
import zlib

MASK=(1<<32)-1
MASK64=(1<<64)-1
def i32(v):return (v&MASK).to_bytes(4,'little')
def i64(v):return (v&MASK64).to_bytes(8,'little')
def signed(v):return v if v<1<<31 else v-(1<<32)
def fold(v):return ((v&MASK)^(v>>32))&MASK
PROBES=(
    ('shl64_fold',(i64(0x0102030405060708)+b'\x00',i64(0x0102030405060708)+b'\x24')),
    ('sar64_fold',(i64(0xf102030405060708)+b'\x00',i64(0xf102030405060708)+b'\x24')),
    ('umul_hi32',(i32(MASK)+i32(MASK),i32(1)+i32(17))),
    ('smul_hi32',(i32(-0x80000000)+i32(2),i32(-0x80000000)+i32(-2))),
    ('popcount32_swar',(i32(0),i32(MASK))),
    ('parity16',(b'\x00\x00',b'\x01\x00')),
    ('adler16',(b'abc',b'abcdefghijklmno')),
    ('fletcher16',(b'abc',b'\xff\x00\xfe')),
    ('crc32_8',(b'abcdefgh',b'ABCDEFGH')),
    ('base64_4',(b'TWFu',b'TWE/')),
    ('utf8_prefix4',(bytes.fromhex('e282ac'),bytes.fromhex('f09f9982'))),
    ('zigzag32',(i32(-1),i32(0x7fffffff))),
    ('saturating_add32',(i32(0x7fffffff)+i32(9),i32(-0x80000000)+i32(-9))),
    ('bitpack_5',(bytes([1,2,3,4,5]),bytes([31,0,31,0,31]))),
    ('lz_copy8',(b'abcdefgh'+bytes([0,7]),b'abcdefgh'+bytes([7,7]))),
    ('tlv_walk16',(b'\x01\x02ab\x02\x01Z',b'\x03\x03xyz\x04\x02pq')),
)
MINIMUM=(9,9,8,8,4,2,1,1,8,4,1,4,8,5,10,2)

def model(kind,data):
    data=data[:16]
    if not 0<=kind<len(PROBES):raise ValueError('Unknown extended kernel')
    if len(data)<MINIMUM[kind]:return MASK
    a=int.from_bytes(data[:4],'little')
    if kind in (0,1):
        value=int.from_bytes(data[:8],'little');k=data[8]%64
        if kind==0:value=(value*(1<<k))&MASK64
        else:
            if value>=1<<63:value-=1<<64
            value=(value//(1<<k))&MASK64
        return fold(value)
    if kind in (2,3):
        b=int.from_bytes(data[4:8],'little')
        return (((a*b) if kind==2 else signed(a)*signed(b))//(1<<32))&MASK
    if kind==4:return a.bit_count()
    if kind==5:return int.from_bytes(data[:2],'little').bit_count()%2
    if kind in (6,7):
        modulus=65521 if kind==6 else 255;initial=1 if kind==6 else 0
        one=(initial+sum(data))%modulus
        two=(initial*len(data)+sum((len(data)-i)*v for i,v in enumerate(data)))%modulus
        return (two<<(16 if kind==6 else 8))|one
    if kind==8:return zlib.crc32(data[:8])&MASK
    if kind==9:
        alphabet=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        out=0
        for i,v in enumerate(data[:4]):
            if v not in alphabet:return 0xffff0000|i
            out=out*64+alphabet.index(v)
        return out
    if kind==10:
        first=data[0]
        if first<128:return 0x01000000|first
        if 0xc2<=first<=0xdf:used=2;prefix=first-0xc0;minimum=0x80
        elif 0xe0<=first<=0xef:used=3;prefix=first-0xe0;minimum=0x800
        elif 0xf0<=first<=0xf4:used=4;prefix=first-0xf0;minimum=0x10000
        else:return 0xffff0000
        if len(data)<used:return 0xffff0100|len(data)
        digits=[prefix]
        for i,v in enumerate(data[1:used],1):
            if not 128<=v<=191:return 0xffff0200|i
            digits.append(v-128)
        value=sum(v*64**(used-1-i) for i,v in enumerate(digits))
        if value<minimum or value>0x10ffff or 0xd800<=value<=0xdfff:return 0xffff0300
        return (used<<24)|value
    if kind==11:
        value=signed(a);return value*2 if value>=0 else -value*2-1
    if kind==12:
        value=signed(a)+signed(int.from_bytes(data[4:8],'little'))
        return max(-(1<<31),min((1<<31)-1,value))&MASK
    if kind==13:return sum((v%32)*32**i for i,v in enumerate(data[:5]))
    if kind==14:
        distance=data[8]%8+1;length=data[9]%8+1;window=list(data[:8]);h=2166136261
        for _ in range(length):
            byte=window[-distance];window.append(byte);h=((h^byte)*16777619)&MASK
        return h
    if kind==15:
        pos=records=h=0
        while pos+2<=len(data) and records<3:
            tag,length=data[pos:pos+2];pos+=2
            if pos+length>len(data):return 0xfffe0000|pos
            payload=data[pos:pos+length]
            for byte in payload:h=((h*33)^byte)&MASK
            h^=tag*(1<<24)+length;pos+=length;records+=1
        return h^(records<<16)^pos
    raise AssertionError(kind)

def vectors(seeds):
    values=list(seeds)+[bytes(n) for n in range(17)]+[bytes([255])*16]
    edges=(0,1,2,7,15,16,31,32,63,64,127,128,129,254,255)
    for seed in seeds:
        for pos in range(len(seed)):
            values.extend(seed[:pos]+bytes([v])+seed[pos+1:] for v in edges)
        for v in range(256):values.extend((bytes([v])+seed[1:],seed[:-1]+bytes([v])))
    rng=random.Random(0x1a7c02)
    values.extend(bytes(rng.randrange(256) for _ in range(n)) for n in range(17) for _ in range(4))
    return list(dict.fromkeys(values))
