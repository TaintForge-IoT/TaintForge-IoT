"""Behavioral specifications and deterministic inputs, independent of C execution."""
import base64
import binascii
import re

NAMES = ('hexcodec', 'uintcalc', 'config', 'csvstats', 'packet', 'rle',
         'sort', 'dictionary', 'filetransform', 'automaton')
MASK = 2**32 - 1
WS = b' \t\r\n'


def fnv(data, seed=2166136261):
    for value in data:
        seed = ((seed ^ value) * 16777619) & MASK
    return seed


def uint(text):
    if isinstance(text, str):
        text = text.encode('ascii')
    text = text.strip(WS)
    if not re.fullmatch(rb'[0-9]+', text) or int(text) > MASK:
        raise ValueError('Invalid unsigned integer')
    return int(text)


def lines(data):
    if not data:
        return []
    parts = data.split(b'\n')
    return parts[:-1] if parts[-1] == b'' else parts


def oracle(name, raw, argv, files):
    result_files = {}
    try:
        data = files.get('input.bin') if name in ('config', 'filetransform') else raw
        if name != 'uintcalc' and (data is None or len(data) > 4096):
            raise ValueError('Input limit or missing file')
        if name == 'hexcodec':
            text = bytes(value for value in data if value not in WS)
            if len(text) % 2 or (text and not re.fullmatch(rb'[0-9a-fA-F]+', text)):
                raise ValueError('Hex syntax')
            stdout = binascii.unhexlify(text)
        elif name == 'uintcalc':
            if len(argv) != 3:
                raise ValueError('Argument count')
            op, a, b = argv[0], uint(argv[1]), uint(argv[2])
            if op == 'sum': value = a + b
            elif op == 'xor': value = a ^ b
            elif op == 'mul': value = a * b
            elif op == 'rot' and b < 32: value = a if b == 0 else (a << b) | (a >> (32-b))
            else: raise ValueError('Operation')
            stdout = f'{value & MASK}\n'.encode()
        elif name == 'config':
            config = {b'port': 80, b'mode': 0}
            seen = set()
            for line in lines(data):
                match = re.fullmatch(rb'[ \t\r]*(port|mode)[ \t\r]*=[ \t\r]*([0-9]+)[ \t\r]*', line)
                if not match or match[1] in seen:
                    raise ValueError('Config syntax or duplicate')
                key, value = match[1], uint(match[2])
                if not (1 <= value <= 65535 if key == b'port' else value <= 3):
                    raise ValueError('Config range')
                seen.add(key); config[key] = value
            stdout = f'port={config[b"port"]} mode={config[b"mode"]}\n'.encode()
        elif name == 'csvstats':
            rows = []
            for line in lines(data):
                match = re.fullmatch(rb'[ \t\r]*([0-9]+)[ \t\r]*,[ \t\r]*([0-9]+)[ \t\r]*', line)
                if not match:
                    raise ValueError('CSV syntax')
                rows.append((uint(match[1]), uint(match[2])))
            stdout = f'rows={len(rows)} sum={sum(sum(row) for row in rows) & MASK}\n'.encode()
        elif name == 'packet':
            if len(data) < 4 or data[:3] != b'TF\x01':
                raise ValueError('Packet header')
            at, count, total, x, size = 4, data[3], 0, 0, 0
            for _ in range(count):
                if at + 2 > len(data): raise ValueError('Truncated TLV')
                kind, length = data[at:at+2]; at += 2
                payload = data[at:at+length]
                if len(payload) != length or kind not in (1, 2): raise ValueError('Invalid TLV')
                if kind == 1: total += sum(payload)
                else:
                    for value in payload: x ^= value
                size += length; at += length
            if at != len(data): raise ValueError('Trailing bytes')
            stdout = f'bytes={size} sum={total & MASK} xor={x}\n'.encode()
        elif name == 'rle':
            if len(data) % 2 or any(value == 0 for value in data[::2]): raise ValueError('RLE syntax')
            stdout = b''.join(bytes([value]) * count for count, value in zip(data[::2], data[1::2]))
            if len(stdout) > 4096: raise ValueError('RLE output limit')
        elif name == 'sort':
            text = data.strip(WS)
            tokens = re.split(rb'[ \t\r\n]+', text) if text else []
            if len(tokens) > 32 or any(not re.fullmatch(rb'-?[0-9]+', token) for token in tokens):
                raise ValueError('Integer list syntax')
            values = [int(token) for token in tokens]
            if any(not -(2**31) <= value < 2**31 for value in values): raise ValueError('Signed range')
            stdout = (','.join(map(str, sorted(values))) + '\n').encode()
        elif name == 'dictionary':
            text = data.strip(WS); store, answers = {}, []
            parts = text.split(b';') if text else []
            if parts and not parts[-1].strip(WS): parts.pop()
            for part in parts:
                command = part.strip(WS)
                match = re.fullmatch(rb'([+?\-])[ \t\r\n]*([0-9]+)(?:[ \t\r\n]+([0-9]+))?', command)
                if not match: raise ValueError('Dictionary syntax')
                op, key = match[1], uint(match[2])
                if op == b'+':
                    if match[3] is None: raise ValueError('Missing value')
                    value = uint(match[3])
                    if key not in store and len(store) == 32: raise ValueError('Dictionary capacity')
                    store[key] = value
                elif match[3] is not None: raise ValueError('Unexpected value')
                elif op == b'-': store.pop(key, None)
                else: answers.append(f'{store[key]}\n'.encode() if key in store else b'MISSING\n')
            stdout = b''.join(answers)
        elif name == 'filetransform':
            if argv == ['copy']: transformed = data
            elif argv == ['reverse']: transformed = data[::-1]
            elif len(argv) == 2 and argv[0] == 'xor' and uint(argv[1]) <= 255:
                transformed = bytes(value ^ uint(argv[1]) for value in data)
            else: raise ValueError('Transform arguments')
            result_files['output.bin'] = transformed
            stdout = f'n={len(transformed)} hash={fnv(transformed)}\n'.encode()
        elif name == 'automaton':
            stack, quoted, escaped, pairs, strings = [], False, False, 0, 0
            closing = {ord(')'): ord('('), ord(']'): ord('['), ord('}'): ord('{')}
            for value in data:
                if quoted:
                    if escaped: escaped = False
                    elif value == 92: escaped = True
                    elif value == 34: quoted = False; strings += 1
                elif value == 34: quoted = True
                elif value in b'([{':
                    if len(stack) == 16: raise ValueError('Nesting limit')
                    stack.append(value)
                elif value in closing:
                    if not stack or stack.pop() != closing[value]: raise ValueError('Mismatched bracket')
                    pairs += 1
            if stack or quoted: raise ValueError('Incomplete state')
            stdout = f'pairs={pairs} strings={strings} hash={fnv(data)}\n'.encode()
        else:
            raise KeyError(name)
        return 0, stdout, result_files
    except (ValueError, OverflowError, binascii.Error):
        return 2, b'ERR\n', {}


def case(name, index, raw=b'', argv=(), files=None):
    files = files or {}
    status, stdout, generated = oracle(name, raw, list(argv), files)
    encode = lambda value: base64.b64encode(value).decode()
    return dict(id=f'input-{index:02d}', stdin_base64=encode(raw), argv=list(argv),
                files={key: encode(value) for key, value in files.items()},
                expected=dict(returncode=status, stdout_base64=encode(stdout), stderr_base64='',
                              files={key: encode(value) for key, value in generated.items()},
                              absent_files=['output.bin'] if name == 'filetransform' and not generated else []))


def cases(name):
    if name == 'hexcodec':
        inputs = [b'', b'00', b'ff', b'0F', b'0123456789abcdef', b'00 ff\n10', b'  \t', b'f', b'000', b'gg',
                  b'0x00', b'00\0', b'00\v', b'FEED', b'aaBBccDD', b'10\r\n20', b'012345'*20,
                  b'aa'*2048, b'aa'*2049, b' 0a 0B ']
    elif name == 'uintcalc':
        values = [('sum','0','0'),('sum','1','2'),('sum','4294967295','1'),('sum','2147483648','2147483648'),
                  ('xor','255','170'),('xor','4294967295','0'),('mul','0','999'),('mul','65536','65536'),
                  ('mul','4294967295','2'),('rot','2147483649','1'),('rot','1','31'),('rot','123','0'),
                  ('rot','1','32'),('sum','4294967296','1'),('sum','-1','2'),('sum','1x','2'),
                  ('sum',' 12 ','3'),('bad','1','2'),('sum','1'),('mul','12345','6789')]
        return [case(name, i, argv=value) for i, value in enumerate(values)]
    elif name == 'config':
        inputs = [b'', b'port=1', b'port=65535\nmode=3\n', b'mode=2\nport=8080', b' port = 443\r\n',
                  b'mode=0', b'port=0', b'port=65536', b'mode=4', b'port=2\nport=3', b'host=1',
                  b'port=', b'port=-1', b'port=3x', b'\n', b'port=4294967296', b'mode=1\nmode=1',
                  b'port=80\nmode=1', b'port=00022\n', None]
        return [case(name, i, files={} if value is None else {'input.bin': value}) for i, value in enumerate(inputs)]
    elif name == 'csvstats':
        inputs = [b'', b'1,2', b'1,2\n3,4\n', b'0,0', b'4294967295,1', b' 12 , 34 \r\n',
                  b'1', b'1,', b',2', b'1,2,3', b'-1,2', b'4294967296,0', b'\n', b'1,2\n\n', b'a,b',
                  b'01,002', b'65535,65535\n'*10, b'9,8\n7,6', b'1,2\0', b'0,0\n'*1025]
    elif name == 'packet':
        packet = lambda chunks: b'TF\x01' + bytes([len(chunks)]) + b''.join(bytes([kind,len(data)])+data for kind,data in chunks)
        inputs = [packet([]), packet([(1,b'abc')]), packet([(2,b'\xff\x0f')]), packet([(1,b'\0'),(2,b'abc')]),
                  packet([(1,bytes(range(255)))]), b'', b'T', b'TF\x01', b'XX\x01\0', b'TF\x02\0',
                  b'TF\x01\x01', b'TF\x01\x01\x01', b'TF\x01\x01\x01\x02a', packet([(3,b'a')]),
                  packet([])+b'x', packet([(1,b'')]), packet([(2,b'aaa')]), packet([(1,b'\xff'*32)]),
                  packet([(2,b'\0'*64)]), packet([(1,b'one'),(1,b'two'),(2,b'three')])]
    elif name == 'rle':
        inputs = [b'', b'\x01a', b'\x03a\x02b', b'\x01\0', b'\xffz', b'\0a', b'\x01', b'\x02a\xff',
                  b'\x10a'*16, b'\xffa'*16, b'\xffa'*17, b'\x01\xff', b'\x02\n', b'\x01a\x01a',
                  b'\x80b\x80c', b'\x04A\x03B\x02C', b'\x7f\0', b'\x05\xff\x02\0', b'\x01x'*100, b'\x01x'*2049]
    elif name == 'sort':
        inputs = [b'', b'1', b'3 1 2', b'-1 0 1', b'2147483647 -2147483648', b'2 2 1 1', b' 3\t-2\n0 ',
                  b'2147483648', b'-2147483649', b'+1', b'1,2', b'a', b'--1', b'- 1', b'-0 0',
                  b' '.join(str(i).encode() for i in range(31,-1,-1)), b' '.join(b'1' for _ in range(33)),
                  b'001 -002', b'1\0', b'9 7 5 3 1 -1 -3']
    elif name == 'dictionary':
        inputs = [b'', b'? 0', b'+ 1 10;? 1', b'+ 1 10;+ 1 20;? 1', b'+ 1 10;- 1;? 1',
                  b'- 999;? 999', b'+ 0 4294967295;? 0', b'+ 4294967295 0;? 4294967295', b'?1;',
                  b'+ 1', b'! 1', b'? 1 2', b'+ 4294967296 1', b'+ 1 -1', b'? 1;;', b';',
                  b';'.join(f'+ {i} {i*i}'.encode() for i in range(32))+b';? 31',
                  b';'.join(f'+ {i} 1'.encode() for i in range(33)),
                  b'+ 1 1;+ 2 2;- 1;+ 3 3;? 2;? 3', b'+12 34;?12']
    elif name == 'filetransform':
        values = [(b'',('copy',)),(b'abc',('copy',)),(b'abc',('reverse',)),(bytes(range(256)),('xor','255')),
                  (b'\0\xff\x80',('xor','128')),(b'a\nb\n',('reverse',)),(b'x'*4096,('copy',)),
                  (b'x'*4097,('copy',)),(b'abc',('xor','0')),(b'abc',('xor','256')),(b'abc',('xor','-1')),
                  (b'abc',('xor',)),(b'abc',('bad',)),(None,('copy',)),(b'1',('reverse',)),
                  (bytes(range(64)),('xor','1')),(b'abc',('copy','extra')),(b'abc',()),
                  (b'\0'*100,('xor','7')),(b'IoT firmware',('copy',))]
        return [case(name, i, argv=args, files={} if value is None else {'input.bin': value}) for i,(value,args) in enumerate(values)]
    elif name == 'automaton':
        inputs = [b'', b'()', b'([]{})', b'"text"', b'("[]")', b'"a\\"b"', b'(', b')', b'([)]', b'"',
                  b'"x\\', b'('*16+b')'*16, b'('*17+b')'*17, b'abc', b'\0\xff', b'{}[]()',
                  b'""""', b'["\\\\"]', b'{[()]} trailing', b'()'*2049]
    else:
        raise KeyError(name)
    return [case(name, i, raw=value) for i, value in enumerate(inputs)]


def scale_blob(length):
    return bytes((i * 17 + 3) & 255 for i in range(256)) * (length // 256)


def scale_case(length, iterations, seed, index):
    value = fnv(scale_blob(length), seed)
    mul, add, n, factor, increment = 1, 0, iterations, 1664525, 1013904223
    while n:
        if n & 1:
            mul, add = (mul * factor) & MASK, (add * factor + increment) & MASK
        factor, increment = (factor * factor) & MASK, (increment * (factor + 1)) & MASK
        n >>= 1
    value = (value * mul + add) & MASK
    stdout = f'img={length} iters={iterations} value={value}\n'.encode()
    return dict(id=f'scale-{index}', stdin_base64='', argv=[str(iterations),str(seed)], files={},
                expected=dict(returncode=0,stdout_base64=base64.b64encode(stdout).decode(),stderr_base64='',files={},absent_files=[]))
