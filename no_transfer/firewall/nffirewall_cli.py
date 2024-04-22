import socket

from base64 import b64encode, b64decode
from sys import argv
from random import randbytes, seed as random_seed

if len(argv) != 2:
    print('Usage: python nffirewall_cli.py <ip>:<port>')
    exit(1)

toks = argv[1].split(':')
if len(toks) != 2:
    print('Usage: python nffirewall_cli.py <ip>:<port>')
    exit(1)

if not toks[1].isdigit():
    print('Port must be a number')
    exit(1)

if int(toks[1]) < 0 or int(toks[1]) > 65535:
    print('Port must be between 0 and 65535')
    exit(1)

IP, PORT = toks[0], int(toks[1].strip())
BUFF_SIZE = 1024
SEP = b'\r\n\r\n'
END = b'\r\n\r\n\r\n\r\n'

class Arcfour:
    def __init__(self) -> None:
        pass

    def ksg(self, key: bytes):
        s = list(range(256))

        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) % 256
            s[i], s[j] = s[j], s[i]

        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) % 256]
            yield k

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        ks = self.ksg(key)
        return b''.join(bytes([next(ks) ^ byte]) for byte in data)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        ks = self.ksg(key)
        return b''.join(bytes([next(ks) ^ byte]) for byte in data)


ARC4 = Arcfour()

BIT_LIMIT = 64
ANDY = 2 ** BIT_LIMIT - 1  # used to correct for how python handles integers.

def rotl(num: int, bits: int, zfill_len: int):
    bits %= zfill_len
    if bits == 0:
        return num

    andy = 2 ** (zfill_len - bits) - 1
    return ((num & andy) << bits) | (num >> (zfill_len - bits))


def predictable_random_bytes(num_bytes: int, seed: bytes) -> bytes:
    random_seed(seed)
    result = randbytes(num_bytes)
    random_seed(None)  # Reset python's random seed
    return result


def chunk_data(data: bytes, chunk_size: int) -> list[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def bytes_to_int_sip(b: bytes) -> int:
    int_value = 0
    for i in range(len(b)):
        int_value |= b[i] << (i * 8)
    return int_value


def int_to_bytes_sip(number: int) -> bytes:
    num_bytes = (number.bit_length() + 7) // 8
    little_endian_bytes = bytearray(num_bytes)
    for i in range(num_bytes):
        little_endian_bytes[i] = (number >> (8 * i)) & 0xFF
    return bytes(little_endian_bytes)


def sip_round(v0, v1, v2, v3):
    v0 = (v0 + v1) & ANDY
    v2 = (v2 + v3) & ANDY
    v1 = rotl(v1, 13, BIT_LIMIT) ^ v0
    v3 = rotl(v3, 16, BIT_LIMIT) ^ v2
    v0 = rotl(v0, 32, BIT_LIMIT)

    v2 = (v2 + v1) & ANDY
    v0 = (v0 + v3) & ANDY
    v1 = rotl(v1, 17, BIT_LIMIT) ^ v2
    v3 = rotl(v3, 21, BIT_LIMIT) ^ v0
    v2 = rotl(v2, 32, BIT_LIMIT)
    return v0, v1, v2, v3


def pad_64_blocks(data: bytes) -> bytes:
    input_len = len(data)
    padding_len = 8 - 1 - (input_len % 8)
    if padding_len == 8:
        padding_len = 0
    padded_bytes = data + (
        b"\x00" * padding_len
    )
    final_byte = input_len & 0xFF
    padded_bytes += bytes([final_byte])
    return padded_bytes


def initialize_state(seed: bytes) -> tuple[int, int, int, int]:
    k0 = bytes_to_int_sip(seed[:8])
    k1 = bytes_to_int_sip(seed[8:])
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573
    return v0, v1, v2, v3


def siphashcdo(c: int, d: int, o: int, data: bytes, k: bytes) -> int:
    if o % 64 != 0:
        raise ValueError(
            f"Output length of `{o}` is not supported. It must be a multiple of 64 bits."
        )

    if len(k) != 16:
        raise ValueError(
            f"Key length of `{len(k)}` is not supported. It must be 128 bits/16 bytes long."
        )

    His = []
    hashes = o // 64
    for _ in range(hashes):
        v0, v1, v2, v3 = initialize_state(
            k
        )
        padded_message = pad_64_blocks(data)
        blocks = chunk_data(padded_message, 8)

        for block in blocks:
            m = bytes_to_int_sip(block)
            v3 ^= m
            for _ in range(c):
                v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)
            v0 ^= m

        v2 ^= 0xFF
        for _ in range(d):
            v0, v1, v2, v3 = sip_round(v0, v1, v2, v3)

        hi = v0 ^ v1 ^ v2 ^ v3
        His.append(hi)
        if len(His) < hashes:
            k = predictable_random_bytes(16, k + int_to_bytes_sip(hi))

    H = His[0]
    for hi in His[1:]:
        H = (H << 64) | hi

    return H


def sip24_64(data: bytes, seed: bytes) -> int:
    return siphashcdo(2, 4, 64, data, seed)


def int_to_bytes(number: int, size: int = None, endian: str = 'big', signed=False) -> bytes:
    if size is None:
        size = (number.bit_length() + 7) // 8
    return number.to_bytes(size, endian, signed=signed)


def bytes_to_int(b: bytes, endian: str = 'big', signed=False) -> int:
    return int.from_bytes(b, endian, signed=signed)


def square_exp_round_func(base: int, y: int, bit: int, mod: int) -> int:
    y = (y**2) % mod
    if bit == 1:
        y = (y * base) % mod
    return y


def square_exponentiation(base: int, exponent: int, mod: int = None) -> int:
    if mod is None:
        return pow(base, exponent)
    y = base
    exponent = [int(x) for x in bin(exponent)[3:]]
    for bit in exponent:
        y = square_exp_round_func(base, y, bit, mod)
    return y


def send(sock: socket.socket, data: bytes, d: bytes):
    if d is None:
        d = b'\x00' * 16
    sock.sendall(b64encode(data) + SEP + int_to_bytes(sip24_64(data, d)) + END)


def recv(sock: socket.socket, d: bytes):
    try:
        if d is None:
            d = b'\x00' * 16
        sock.settimeout(15)
        recv = sock.recv(BUFF_SIZE)
        sock.settimeout(None)
        while not recv.endswith(END):
            sock.settimeout(15)
            recv += sock.recv(BUFF_SIZE)
            sock.settimeout(None)
        recv_data = recv.split(SEP, 1)
        if len(recv_data) != 2:
            return b''
        recv, recv_hash = recv_data[0], recv_data[1].rstrip(END)
        data = b64decode(recv)
        if sip24_64(data, d) != bytes_to_int(recv_hash):
            return b''
        return b64decode(recv)
    except TimeoutError as e:
        sock.close()
        raise TimeoutError('Timeout while receiving data from server. An error likely occured. Closing') from e


def send_rcv(sock: socket.socket, data: bytes, d: bytes):
    send(sock, data, d)
    return recv(sock, d)


def auth(sock, s: bytes, d: bytes, args: list[str]):
    if not args:
        print('Usage: auth <username>:<password>')
        return
    if len(args) != 1:
        print('Usage: auth <username>:<password>')
        return
    args = args[0].split(':')
    if len(args) != 2:
        print('Usage: auth <username>:<password>')
        return
    
    prefix = 'AUTH'
    uname, passwd = args
    passwd = b64encode(int_to_bytes(sip24_64(passwd.encode(), d))).decode()
    msg = f'{prefix}\r\n\r\n{uname}:{passwd}'
    resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
    resp = ARC4.decrypt(resp_raw, s).decode()
    print(resp + '\n')
    pass


def run(sock, s: bytes, d: bytes, args: list[str]):
    if not args:
        print('Usage: run <shell command>')
        return
    prefix = 'RUN'
    msg = prefix + '\r\n\r\n' + '\r\n\r\n'.join(args)
    resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
    resp = ARC4.decrypt(resp_raw, s).decode()
    print(resp + '\n')


def show(sock, s: bytes, d: bytes, args: list[str]):
    if not args:
        print('Usage: show <info|rule <rule id>|rules|status>')
        return
    prefix = 'SHOW'
    if args[0] == 'info':
        msg = f'{prefix}\r\n\r\nINFO'
        resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
        resp = ARC4.decrypt(resp_raw, s).decode()
        print(resp + '\n')
    elif args[0] == 'rule':
        if len(args) != 2:
            print('Usage: show rule <rule id>')
            return
        rule_id = args[1]
        msg = f'{prefix}\r\n\r\nRULE\r\n\r\n{rule_id}'
        resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
        resp = ARC4.decrypt(resp_raw, s).decode()
        print(resp + '\n')
    elif args[0] == 'rules':
        msg = f'{prefix}\r\n\r\nRULES'
        resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
        resp = ARC4.decrypt(resp_raw, s).decode()
        print(resp + '\n')
    elif args[0] == 'status':
        msg = f'{prefix}\r\n\r\nSTATUS'
        resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
        resp = ARC4.decrypt(resp_raw, s).decode()
        print(resp + '\n')
    else:
        print('Usage: show <info|rule <rule id>|rules|status>')
        return


def chstat(sock, s: bytes, d: bytes, args: list[str]):
    if not args or len(args) != 1:
        print('Usage: chstat <log|filter|stop|start>')
        return
    prefix = 'CHSTAT'
    if args[0].lower() not in ['log', 'filter', 'stop', 'start']:
        print('Usage: chstat <log|filter|stop|start>')
        return
    msg = f'{prefix}\r\n\r\n{args[0].upper()}'
    resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
    resp = ARC4.decrypt(resp_raw, s).decode()
    print(resp + '\n')
    pass


def rules(sock, s: bytes, d: bytes, args: list[str]):
    if not args:
        print('Usage: rules <add <rule prio> <ip> <proto> <port> <action> <direction>|del <rule id>|toggle <rule id>>')
        return
    prefix = 'RULES'
    if args[0] == 'add':
        if len(args) != 7:
            print('Usage: rules add <rule prio> <ip> <proto> <port> <action> <direction>')
            return
        prio, ip, proto, port, action, direction = args[1:]
        msg = f'{prefix}\r\n\r\nADD\r\n\r\n{prio}\r\n\r\n{ip}\r\n\r\n{proto}\r\n\r\n{port}\r\n\r\n{action}\r\n\r\n{direction}'
        resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
        resp = ARC4.decrypt(resp_raw, s).decode()
        print(resp + '\n')
    elif args[0] == 'del':
        if len(args) != 2:
            print('Usage: rules del <rule id>')
            return
        rule_id = args[1]
        msg = f'{prefix}\r\n\r\nDEL\r\n\r\n{rule_id}'
        resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
        resp = ARC4.decrypt(resp_raw, s).decode()
        print(resp + '\n')
    elif args[0] == 'toggle':
        if len(args) != 2:
            print('Usage: rules toggle <rule id>')
            return
        rule_id = args[1]
        msg = f'{prefix}\r\n\r\nTOGGLE\r\n\r\n{rule_id}'
        resp_raw = send_rcv(sock, ARC4.encrypt(msg.encode(), s), d)
        resp = ARC4.decrypt(resp_raw, s).decode()
        print(resp + '\n')
    else:
        print('Usage: rules <add <rule prio> <ip> <proto> <port> <action> <direction>|del <rule id>|toggle <rule id>>')
        return


def cli_exit(sock, s: bytes, d: bytes, args: list[str]):
    prefix = 'EXIT'
    send(sock, ARC4.encrypt(prefix.encode(), s), d)
    return


def do_handshake(sock):
    try:
        d = None
        a = bytes_to_int(randbytes(8))
        nonce_bytes = randbytes(8)
        nonce = bytes_to_int(nonce_bytes)
        msg = send_rcv(sock, f'GETKEY{SEP.decode()}'.encode() + nonce_bytes, d)
        msg_toks = msg.split(SEP)
        # print(msg_toks) # comment out
        if len(msg_toks) != 4:
            print('Invalid response from server')
            return None, None
        if msg_toks[0] != b'VARS':
            print('Invalid response from server')
            return None, None
        p = bytes_to_int(msg_toks[1])
        g = bytes_to_int(msg_toks[2])
        B = bytes_to_int(msg_toks[3])
        A = square_exponentiation(g, a, p)
        # print(f'p: {p}, g: {g}, B: {B}, A: {A}') # comment out
        msg = f'A{SEP.decode()}'.encode() + int_to_bytes(A)
        send(sock, msg, d)
        s = int_to_bytes(square_exponentiation(B, a, p) ^ nonce)
        ok_raw = recv(sock, d)
        ok = ARC4.decrypt(ok_raw, s)
        if ok != nonce_bytes:
            print('Failed to establish session key')
            return None, None
        send(sock, ARC4.encrypt(b'ACK', s), d)
        d = (s + nonce_bytes)[:16]
        d = (d + b'\x00' * (16 - len(d)))[:16]
        return s, d
    except Exception as e:
        print(f'Error: {e}')
        # raise e # comment out
        return None, None
    

def print_help():
    print('Commands:')
    print('run <shell command> - Run a shell command on the server')
    print('show <info|rule <rule id>|rules|status> - Show information about the server')
    print('chstat <log|filter|stop|start> - Change the status of the server')
    print('rules <add <rule prio> <ip> <proto> <port> <action> <direction>|del <rule id>|toggle <rule id>> - Add, delete or toggle a rule')
    print('auth <username>:<password> - Authenticate with the server')
    print('exit - Exit the CLI')


def main():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((IP, int(PORT)))
        s, d = do_handshake(sock)
        if s is None or d is None:
            print('Failed to establish session key. Trying again...')
            continue
        break

    # print(f's: {s}, d: {d}') # comment out

    while True:
        try:
            cmd = input('nffirewall> ')
            cmd_toks = cmd.split(' ')
            if cmd_toks[0] == 'run':
                run(sock, s, d, cmd_toks[1:])
            elif cmd_toks[0] == 'show':
                show(sock, s, d, cmd_toks[1:])
            elif cmd_toks[0] == 'chstat':
                chstat(sock, s, d, cmd_toks[1:])
            elif cmd_toks[0] == 'rules':
                rules(sock, s, d, cmd_toks[1:])
            elif cmd_toks[0] == 'auth':
                auth(sock, s, d, cmd_toks[1:])
            elif cmd_toks[0] == 'exit':
                cli_exit(sock, s, d, cmd_toks[1:])
                break
            elif cmd_toks[0] == 'help':
                print_help()
            else:
                print('Invalid command')
                print_help()
        except Exception as e:
            print(f'Error: {e}')
            # raise e


if __name__ == '__main__':
    main()
