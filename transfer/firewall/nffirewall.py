import logging
import signal
import socket
import subprocess
import os
import warnings

from base64 import b64encode, b64decode
from concurrent.futures import ProcessPoolExecutor, as_completed, process
from copy import deepcopy
from enum import Enum
from multiprocessing import Manager, cpu_count
from netfilterqueuelinux import NetfilterQueue, Packet as nf_Packet
from pathlib import Path
from scapy.all import IP, Raw, Packet as sc_Packet, TCP, UDP
from random import randbytes, randint, randrange, choice, seed as random_seed, shuffle
from sys import argv
from threading import Thread
from datetime import datetime


# nf_Packet, NetfilterQueue = None, None # comment out
# IP, Raw, sc_Packet, TCP, UDP = None, None, None, None, None # comment out

class OperatingSystem(Enum):
    LINUX = 1
    WINDOWS = 2


ROOT_DIR = Path(__file__).parent
LOG_FILE = ROOT_DIR / 'nffirewall.log'
RULES_FILE = ROOT_DIR / 'nffirewall.rules'
LOCK_FILE = ROOT_DIR / 'nffirewall.lock'
BUFF_SIZE = 1024
SEP = b'\r\n\r\n'
END = b'\r\n\r\n\r\n\r\n'
BIND_ADDR = '0.0.0.0'
BASE_BIND_PORT = 1337

warnings.simplefilter('ignore', Warning)
if len(argv) > 1 and argv[1] == '-v':
    logging.basicConfig(filename=LOG_FILE, filemode='a', level=logging.DEBUG)
else:
    logging.basicConfig(filename=LOG_FILE, filemode='a', level=logging.INFO)

INTERFACES: dict[str, set] = {'rustdesk': {'129.168.33.138'}, 'sshjump': {'100.65.1.1'}, 'other': set(), 'control': set()}
OS_TYPE = OperatingSystem.LINUX if os.name == 'posix' else OperatingSystem.WINDOWS


def get_pid_and_run(queue, func, *args, **kwargs):
    pid = os.getpid()
    queue.put(pid)
    result = func(*args, **kwargs)
    return pid, result


def kill_all_pid_in_queue(pid_queue):
    while not pid_queue.empty():
        pid = pid_queue.get()
        try:
            os.kill(pid, 9)
        except (ProcessLookupError, process.BrokenProcessPool):
            pass


def get_first_result(func, *args, timeout=None, tries=None, **kwargs):
    """
    Runs multiple instances of a function in parallel.
    The first process to complete will return its result.
    All other processes are killed.

    Wish this was a decorator.
    """
    pid_queue = Manager().Queue()
    runs = 0
    proc_timeout = timeout
    while True:
        kill_all_pid_in_queue(pid_queue)
        with ProcessPoolExecutor(max_workers=cpu_count()) as executor:
            futures = [executor.submit(get_pid_and_run, pid_queue, func, *args, **kwargs) for _ in range(cpu_count())]
            try:
                for future in as_completed(futures, timeout=proc_timeout):
                    _, result = future.result()
                    kill_all_pid_in_queue(pid_queue)
                    return result
            except TimeoutError:
                runs += 1
                if tries is not None and runs >= tries:
                    kill_all_pid_in_queue(pid_queue)
                    break
                kill_all_pid_in_queue(pid_queue)
                continue
    try:
        kill_all_pid_in_queue(pid_queue)
    except Exception:
        pass


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


def is_prime_miller(n: int, s: int = 10):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r = n - 1
    u = 0
    while r % 2 == 0:
        u += 1
        r //= 2

    for _ in range(s):
        a = randint(2, n - 2)
        z = square_exponentiation(a, r, n)
        if z == 1 or z == n - 1:
            continue
        for _ in range(u - 1):
            z = square_exponentiation(z, 2, n)
            if z == n - 1:
                break
        else:
            return False
    return True


def generate_prime_miller(min_bits: int, prime_list: tuple[int] = None) -> int:
    start = 2 ** (min_bits - 1)
    stop = 2**min_bits
    if prime_list is None:
        prime_list = []
    while True:
        prime = randrange(start, stop)
        if is_prime_miller(prime):
            return prime


def euclidean_alg_gcd(a, b):
    if b == 0:
        return a
    if a == 0:
        return b

    if b > a:
        a, b = b, a

    while True:
        r = a % b
        if r <= 0:
            return b
        a = b
        b = r


def brents_pollards_rho(n):
    if n % 2 == 0:
        return 2

    c = randint(1, n - 1)
    hare = tortoise = randint(1, n - 1)
    m = randint(1, n - 1)
    d, lam, z = 1, 1, 1
    while d == 1:
        tortoise = hare
        for _ in range(lam):
            hare = (square_exponentiation(hare, 2, n) + c) % n

        k = 0
        while k < lam and d == 1:
            ys = hare
            for _ in range(min(m, lam - k)):
                hare = (square_exponentiation(hare, 2, n) + c) % n
                z = z * abs(tortoise - hare) % n
            d = euclidean_alg_gcd(z, n)
            k += m
        lam *= 2

    if d == n:
        while True:
            ys = (square_exponentiation(ys, 2, n) + c) % n
            d = euclidean_alg_gcd(abs(tortoise - ys), n)
            if d > 1:
                break
    if d == n and not is_prime_miller(n):
        return brents_pollards_rho(n)
    return d


def prime_factors_brents(n):
    if n <= 1:
        return []

    factor = brents_pollards_rho(n)
    if factor == n:
        return [n]

    factors = prime_factors_brents(factor)
    factors.extend(prime_factors_brents(n // factor))

    return factors


def get_primitive_roots(p: int) -> list:
    if p == 2:
        return 1

    prime_factors = set(prime_factors_brents(p - 1))
    powers = {(p - 1) // pf for pf in prime_factors}
    lowest_root = None
    for g in range(2, int(p**0.5) + 1):
        for prime in prime_factors:
            if g % prime == 0:
                break
        else:
            for power in powers:
                if square_exponentiation(g, power, p) == 1:
                    break
            else:
                lowest_root = g
                break
    
    if lowest_root is None:
        return []
    
    roots = {lowest_root}
    for m in range(int(p**0.5) + 1, p):
        if euclidean_alg_gcd(m, p - 1) == 1:
            roots.add(square_exponentiation(lowest_root, m, p))
    return list(roots)


def get_a_primitive_root(p: int) -> int:
    if p == 2:
        return 1

    prime_factors = set(prime_factors_brents(p - 1))
    powers = {(p - 1) // pf for pf in prime_factors}

    tried = set()
    while True:
        g = randint(2, int(p**0.5) + 1)
        if g in tried:
            continue
        tried.add(g)
        for prime in prime_factors:
            if g % prime == 0:
                break
        else:
            for power in powers:
                if square_exponentiation(g, power, p) == 1:
                    break
            else:
                return g


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


def run(cmd: str, cwd=None) -> tuple[str | None, str | None]:
    if cwd is None or not os.path.exists(cwd):
        cwd = os.getcwd()

    logging.info(f'Running command: {cmd}')
    proc = subprocess.Popen(cmd, cwd=cwd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ.copy(), shell=True)

    try:
        stdout, stderr = proc.communicate(timeout=30)
        logging.debug(f'Command: {cmd}\n\tstdout: {stdout}\n\tstderr: {stderr}')
    except subprocess.TimeoutExpired:
        stdout, stderr = '', 'Command timed out after 30 seconds.'
        logging.error(f'Command timed out: {cmd}')
    return stdout.decode().strip() if stdout else None, stderr.decode().strip() if stderr else None


class Direction(Enum):
    IN = 1
    OUT = 2
    ANY = 3

    def __str__(self) -> str:
        return '<-' if self == Direction.IN else '->' if self == Direction.OUT else '<->'

    def __repr__(self) -> str:
        return self.name


class Action(Enum):
    ACCEPT = 1
    DROP = 2


class Status(Enum):
    INIT = 0
    FILTER = 1
    LOG = 2
    STOPPED = 3


class TransportProcol(Enum):
    TCP = 1
    UDP = 2
    ANY = 3


class RuleStatus(Enum):
    ON = 1
    OFF = 2


WILDCARDS = {'any', '*', 'all'}


class Port:
    def __init__(self, port: int, protocol: TransportProcol) -> None:
        self.port = port
        self.protocol = protocol

    def __eq__(self, other) -> bool:
        if not isinstance(other, Port):
            return False
        return self.port == other.port and (self.protocol == other.protocol or self.protocol == TransportProcol.ANY or other.protocol == TransportProcol.ANY)

    def __hash__(self) -> int:
        return hash(f'{self.port}:{self.protocol.name}')

    def __str__(self) -> str:
        return f'{self.port}:{self.protocol.name}'


class Rule:
    def __init__(self, id: int, priority: int, ip: str, protocol: str, port: Port | str, action: Action, direction: Direction) -> None:
        self.id = id
        self.priority = priority
        self.ip = ip
        self.protocol = protocol
        self.port = port
        self.action = action
        self.direction = direction
        self.enabled = RuleStatus.ON

    def __eq__(self, other) -> bool:
        if not isinstance(other, Rule):
            return False
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)

    def __str__(self) -> str:
        return (
            f'[{repr(self.direction)}:{self.action.name}:{self.enabled.name}]'.ljust(15)
            + f'{self.id}:'.ljust(8)
            + f'ip={self.ip}'.ljust(16)
            + f'protocol={self.protocol}'.ljust(16)
            + f'port={self.port}'.ljust(17)
            + f'priority={self.priority}'
        )

    def __repr__(self) -> str:
        return f'{self.priority} {self.ip} {self.protocol} {self.port} {self.action.name} {self.direction.name}'.lower()

    def toggle_rule(self):
        self.enabled = RuleStatus.ON if self.enabled == RuleStatus.OFF else RuleStatus.OFF

    def match(self, layers: list, source_ip: str, destination_ip: str, source_port: Port, destination_port: Port, direction: Direction) -> bool:
        if self.enabled == RuleStatus.OFF:
            return False

        ip_match = (source_ip == self.ip or destination_ip == self.ip) or self.ip in WILDCARDS

        protocol_match = False
        for layer in layers:
            if str(layer.name).lower() == self.protocol.lower():
                protocol_match = True
        protocol_match = protocol_match or self.protocol in WILDCARDS

        port_match = (source_port == self.port or destination_port == self.port) or self.port in WILDCARDS
        direction_match = direction == self.direction or self.direction == Direction.ANY

        return ip_match and protocol_match and port_match and direction_match


class RulesTable:
    def __init__(self, rules_file_path: str) -> None:
        self.rules: dict[int, set[Rule]] = dict()
        self.ids = set()
        self.rules_file_path = rules_file_path
        self.load()

    def __iadd__(self, rule: Rule):
        if rule.priority not in self.rules:
            self.rules[rule.priority] = set()
        start_len = len(self.rules[rule.priority])
        self.rules[rule.priority].add(rule)
        end_len = len(self.rules[rule.priority])
        if start_len != end_len:
            self.ids.add(rule.id)

    def __isub__(self, rule: Rule):
        if rule.priority in self.rules:
            start_len = len(self.rules[rule.priority])
            self.rules[rule.priority] -= {rule}
            end_len = len(self.rules[rule.priority])
            if start_len != end_len:
                self.ids -= {rule.id}
    
    def __len__(self):
        return sum(len(rules) for rules in self.rules.values())

    def __iter__(self):
        for _, rules in sorted(self.rules.items(), key=lambda x: x[0]):
            for rule in sorted(rules, key=lambda x: x.id):
                yield rule

    def get_rule_by_id(self, id: int) -> Rule:
        for _, rules in self.rules.items():
            for rule in rules:
                if rule.id == id:
                    return rule
        return None

    def get_next_rule_id(self) -> int:
        if not self.ids:
            return 1
        rule_ids = set(range(min(self.ids), max(self.ids) + 1))
        available_ids = rule_ids - self.ids
        return min(available_ids) if available_ids else max(self.ids) + 1

    def load(self):
        if not os.path.exists(self.rules_file_path):
            run(f'touch {self.rules_file_path}')

        with open(self.rules_file_path, 'r') as rules_file:
            for line in rules_file:
                rule = create_rule_from_string(self.get_next_rule_id(), line)
                self += rule

    def save(self):
        with open(self.rules_file_path, 'w') as rules_file:
            for rule in self:
                rules_file.write(str(rule) + '\n')


def add_iptables(id):
    iptable_add_out = f'iptables -A OUTPUT -j NFQUEUE --queue-num={id}'
    iptable_add_in = f'iptables -A INPUT -j NFQUEUE --queue-num={id}'
    logging.info('Adding iptable rules...')
    _, iptables_stderr = run(f'{iptable_add_out} && {iptable_add_in}')
    if iptables_stderr is not None:
        logging.critical(f'Adding IP tables failed: {iptables_stderr}')
        raise ValueError(f'Adding IP tables failed: {iptables_stderr}')


def del_iptables(id, sig=None, frame=None):
    if sig is not None:
        logging.critical(f'Caught signal: {sig}')
    iptable_del_out = f'iptables -D OUTPUT -j NFQUEUE --queue-num={id}'
    iptable_del_in = f'iptables -D INPUT -j NFQUEUE --queue-num={id}'
    logging.info('Deleting iptable rules...')
    _, iptables_stderr = run(f'{iptable_del_out} && {iptable_del_in}')
    if iptables_stderr is not None:
        logging.critical(f'Deleting IP tables failed: {iptables_stderr}')
        raise ValueError(f'Deleting IP tables failed: {iptables_stderr}')


def create_rule_from_string(rule_id: int, rule_str: str, sep: str = ' ') -> Rule:
    try:
        rule_parts = rule_str.split(sep)
        if len(rule_parts) != 6:
            raise ValueError(f'Invalid rule string: {rule_str}\n\tParsed To: {rule_parts}')
        rule_parts = [part.strip().lower() for part in rule_parts]
        rule_priority = int(rule_parts[0])
        rule_ip = rule_parts[1]
        rule_protocol = rule_parts[2]
        rule_port_raw = rule_parts[3]
        port_tok = rule_port_raw.split(':')
        if len(port_tok) > 1:
            port_num = int(port_tok[0]) if port_tok[0] not in WILDCARDS else port_tok[0]
            rule_port = Port(port_num, TransportProcol[port_tok[1].upper()])
        else:
            rule_port = Port(int(rule_port_raw), TransportProcol.ANY) if rule_port_raw not in WILDCARDS else rule_port_raw
        rule_action = Action.ACCEPT if rule_parts[4] == 'accept' else Action.DROP
        rule_direction = Direction.IN if rule_parts[5] == 'in' else Direction.OUT if rule_parts[5] == 'out' else Direction.ANY if rule_parts[5] in WILDCARDS else None
        return Rule(rule_id, rule_priority, rule_ip, rule_protocol, rule_port, rule_action, rule_direction)
    except Exception as e:
        raise ValueError(f'Unable to parse rule string: {rule_str}\n\tError: {e}') from e


class Firewall:
    def __init__(self, id: int, rules_file: str) -> None:
        logging.log(logging.INFO, f'Firewall {id} created with Firewall({id}, {rules_file})')

        self.id = id
        self.starttime = datetime.now()
        self.prev_status = Status.INIT
        self.status = Status.INIT

        logging.info(f'Loading rules from {rules_file}')
        self.rules = RulesTable(rules_file)
        logging.info(f'Rules loaded from {rules_file}')

        self.__interfaces = deepcopy(INTERFACES)

        logging.info('Getting interfaces from ifconfig')
        ifconfig_stdout, ifconfig_stderr = run("ifconfig | awk '/inet / {print $2}'")
        if ifconfig_stderr is not None:
            logging.critical(f'Unable to get interfaces using ifconfig and awk: {ifconfig_stderr}')
            raise ValueError(f'Unable to get interfaces using ifconfig and awk: {ifconfig_stderr}')

        interfaces_from_ifconfig = [line.strip() for line in ifconfig_stdout.split('\n')]
        logging.info(f'Interfaces from ifconfig: {interfaces_from_ifconfig}')
        for interface in interfaces_from_ifconfig:
            self.__interfaces['other'].add(interface)

        # logging.info(f'Creating Packet Caputure file...')
        # self.__pktdump = PcapWriter(f'./firewall-{self.id}_{self.starttime.strftime("%Y%m%d-%H%M%S")}.pcap', append=True, sync=True)
        # logging.info(f'Packet Capture file created: ./firewall-{self.id}_{self.starttime.strftime("%Y%m%d-%H%M%S")}.pcap')

    def chstat(self, status: Status):
        self.prev_status = self.status
        self.status = status
        logging.info(f'Firewall status changed from {self.prev_status} to {self.status}.')
        if self.status == Status.STOPPED and self.prev_status != Status.STOPPED:
            del_iptables(self.id)
        elif (self.status == Status.FILTER or self.status == Status.LOG) and (self.prev_status == Status.INIT or self.prev_status == Status.STOPPED):
            add_iptables(self.id)

    def _handle_packet(self, payload: nf_Packet):
        data = payload.get_payload()
        pkt: sc_Packet = IP(data)
        log_packet = self.status == Status.LOG
        accept_packet = True
        try:
            layers = pkt.layers()
            layer = layers[-2] if isinstance(pkt.lastlayer(), Raw) else pkt.lastlayer()
            src_ip, dst_ip = str(pkt[IP].src), str(pkt[IP].dst)
            transport_protocol = TCP if pkt.haslayer(TCP) else UDP if pkt.haslayer(UDP) else 'any'
            transport_proto_enum_type = TransportProcol.TCP if pkt.haslayer(TCP) else TransportProcol.UDP if pkt.haslayer(UDP) else 'any'
            src_port = Port(pkt[transport_protocol].sport, transport_proto_enum_type) if transport_protocol != 'any' else 'any'
            dst_port = Port(pkt[transport_protocol].dport, transport_proto_enum_type) if transport_protocol != 'any' else 'any'

            # allow all rustdesk connections
            if src_ip in self.__interfaces['rustdesk'] or dst_ip in self.__interfaces['rustdesk']:
                logging.debug(f'Allowing RustDesk packet: {pkt}')
                payload.accept()
                return

            # allow all sshjump connections
            if src_ip in self.__interfaces['sshjump'] or dst_ip in self.__interfaces['sshjump']:
                logging.debug(f'Allowing SSHJump packet: {pkt}')
                payload.accept()
                return

            # allow localhost connections
            if src_ip in self.__interfaces['other'] and dst_ip in self.__interfaces['other']:
                logging.debug(f'Allowing Localhost packet: {pkt}')
                payload.accept()
                return

            # allow control connections
            # anti-lockout rule
            if src_ip in self.__interfaces['control'] and dst_ip in self.__interfaces['other'] and transport_protocol is TCP:
                logging.debug(f'Allowing Control packet: {pkt}')
                payload.accept()
                return

            if self.status != Status.FILTER:
                logging.debug(f'Firewall is not in filter mode. Accepting packet: [{src_ip} -> {dst_ip}] {pkt}')
                payload.accept()
                if log_packet:
                    logging.info(f'Packet: {pkt}')
                return

            for _, rule in self.rules:
                rule: Rule
                if rule.match(layers, src_ip, dst_ip, src_port, dst_port, Direction.IN):
                    if rule.action == Action.ACCEPT:
                        logging.debug(f'Accepting packet: {pkt}\n\tReason: {rule}')
                        accept_packet = True
                    elif rule.action == Action.DROP:
                        logging.info(f'Dropping packet: {pkt}\n\tReason: {rule}')
                        accept_packet = False
                    break

            if log_packet:
                logging.info(f'Packet: {pkt}')

            if not accept_packet:
                payload.drop()
            else:
                payload.accept()
            print(f'Packet: {pkt[layer]}')
            return
        except Exception as e:
            logging.error(f'Unable to handle packet {pkt}: {e}')
            try:
                payload.accept()
            except Exception as e:
                logging.error(f'Unable to accept packet: {e}')
                pass
            return

    def start(self):
        # Setup
        is_root = run("id | awk '/uid=0/ {print $1}' ")[0] is not None
        if not is_root:
            logging.critical('Must be run as root.')
            raise ValueError('Must be run as root.')

        logging.info('Ensuring system firewall is disabled...')
        run('ufw disable')

        q = NetfilterQueue()
        q.bind(self.id, self._handle_packet)
        try:
            self.chstat(Status.LOG)
            q.run()
        except (Exception, KeyboardInterrupt) as e:
            if not isinstance(e, KeyboardInterrupt):
                logging.critical(f'Unhandled Error Raised: {e}')
            self.stop()
            raise e

    def stop(self):
        self.chstat(Status.STOPPED)
        # logging.info("Closing Packet Capture file...")
        # self.__pktdump.close()
        # logging.info("Packet Capture file closed.")
        logging.info('Saving rules...')
        self.rules.save()
        logging.info('Rules saved.')


def send(sock: socket.socket, data: bytes, d: bytes):
    if d is None:
        d = b'\x00' * 16
    sock.sendall(b64encode(data) + SEP + int_to_bytes(sip24_64(data, d)) + END)


def recv(sock: socket.socket, d: bytes):
    if d is None:
        d = b'\x00' * 16
    recv = sock.recv(BUFF_SIZE)
    while not recv.endswith(END):
        recv += sock.recv(BUFF_SIZE)
    recv_data = recv.split(SEP, 1)
    if len(recv_data) != 2:
        return b''
    recv, recv_hash = recv_data[0], recv_data[1].rstrip(END)
    data = b64decode(recv)
    if sip24_64(data, d) != bytes_to_int(recv_hash):
        return b''
    return b64decode(recv)


def send_rcv(sock: socket.socket, data: bytes, d: bytes):
    send(sock, data, d)
    return recv(sock, d)


class FirewallCTL:
    def __init__(self, id: int, rules_file: str, ctl_port_num: int) -> None:
        self.firewall = Firewall(id, rules_file)
        self.port_num = ctl_port_num

    def run(self, fw: Firewall, args: list[str]) -> bytes:
        # Run shell command
        if not args:
            return b''
        cmd = ' '.join(args)
        stdout, stderr = run(cmd)
        if stderr is not None:
            return f'{stdout}\nError: {stderr}'.encode()
        return f'{stdout}'.encode()

    def show(self, fw: Firewall, args: list[str]) -> bytes:
        # Show firewall attributes
        if not args:
            return  # f'Options: info, rule, rules, status\n'
        if args[0] == 'INFO':
            return f'Firewall ID: {fw.id}\nStatus: {fw.status}\nRules: {len(fw.rules)}\nStart Time: {fw.starttime}\n'.encode()
        elif args[0] == 'RULE':
            if len(args) < 2:
                return b'ERR'
            rule_id = int(args[1])
            rule = fw.rules.get_rule_by_id(rule_id)
            if rule is None:
                return b'ERR'
            return f'{rule}'.encode()
        elif args[0] == 'RULES':
            return '\n'.join([str(rule) for rule in fw.rules]).encode()
        elif args[0] == 'STATUS':
            return f'{fw.status}'.encode()
        else:
            return b'ERR'

    def chstat(self, fw: Firewall, args: list[str]) -> bytes:
        # Change firewall status
        if not args:
            return b''  # f'Options: log, filter, stop, start\n'
        if args[0] == 'LOG':
            fw.chstat(Status.LOG)
            return b'OK'
        elif args[0] == 'FILTER':
            fw.chstat(Status.FILTER)
            return b'OK'
        elif args[0] == 'STOP':
            fw.chstat(Status.STOPPED)
            return b'OK'
        elif args[0] == 'RESTART':
            if fw.status == Status.STOPPED:
                return b'Firewall not started.'
            fw.chstat(Status.STOPPED)
            fw.chstat(fw.prev_status)
            return b'OK'
        else:
            return b'ERR'

    def rules(self, fw: Firewall, args: list[str]) -> bytes:
        # manage filter rules
        if not args:
            return b''  # f'Options: add, del, toggle\n'
        if args[0] == 'ADD':
            if len(args) < 7:
                return b'ERR'
            rule_id = fw.rules.get_next_rule_id()
            rule = create_rule_from_string(rule_id, ' '.join(args[1:]))
            fw.rules += rule
            return b'OK'
        elif args[0] == 'DEL':
            if len(args) < 2:
                return b'ERR'
            rule_id = int(args[1])
            rule = fw.rules.get_rule_by_id(rule_id)
            if rule is None:
                return b'ERR'
            fw.rules -= rule
            return b'OK'
        elif args[0] == 'TOGGLE':
            if len(args) < 2:
                return b'ERR'
            rule_id = int(args[1])
            rule = fw.rules.get_rule_by_id(rule_id)
            if rule is None:
                return b'ERR'
            rule.toggle_rule()
            return b'OK'
        else:
            return b'ERR'

    def authenticate(self, fw: Firewall, args: list[str], c: bytes) -> bytes:
        if not args:
            return b''
        msg_toks = args[0].split(':')
        if len(msg_toks) != 2:
            return b'ERR'
        user, passwd = msg_toks
        passwd = bytes_to_int(b64decode(passwd))
        # print(f'User: {user}, Passwd: {passwd}, C: {c}') # comment out
        if user == 'admin' and passwd == c:
            return b'OK'
        
    def do_handshake(self, sock: socket.socket) -> tuple:
        d = None
        p = get_first_result(generate_prime_miller, 64)
        g = get_first_result(get_a_primitive_root, p, timeout=1, tries=2)
        while g is None:
            p = get_first_result(generate_prime_miller, 64)
            g = get_first_result(get_a_primitive_root, p, timeout=1, tries=2)
        msg_raw = recv(sock, d)
        msg_tok = msg_raw.split(SEP)
        # print(f'msg_tok: {msg_tok}') # comment out
        if msg_tok[0] != b'GETKEY':
            send(sock, b'ERR', d)
            return None, None, None
        nonce_bytes = msg_tok[1]
        nonce = bytes_to_int(nonce_bytes)
        b = bytes_to_int(randbytes(8))
        B = square_exponentiation(g, b, p)

        msg = f'VARS{SEP.decode()}'.encode() + int_to_bytes(p) + SEP + int_to_bytes(g) + SEP + int_to_bytes(B)
        A_raw = send_rcv(sock, msg, d)
        msg_tok = A_raw.split(SEP)
        # print(f'msg_tok: {msg_tok}') # comment out
        if len(msg_tok) < 2:
            send(sock, b'ERR', d)
            return None, None, None
        if msg_tok[0] != b'A':
            send(sock, b'ERR', d)
            return None, None, None
        A = bytes_to_int(msg_tok[1])
        # print(f'p: {p}, g: {g}, B: {b}, A: {B}') # comment out
        s = int_to_bytes(square_exponentiation(A, b, p) ^ nonce)
        ack_raw = send_rcv(sock, ARC4.encrypt(nonce_bytes, s), d)
        ack = ARC4.decrypt(ack_raw, s)
        if ack != b'ACK':
            send(sock, b'ERR', d)
            return None, None, None
        d = (s + nonce_bytes)[:16]
        d = (d + b'\x00' * (16 - len(d)))[:16]
        c = sip24_64(int_to_bytes(int(b64decode(b'N2M3YzdjN2M=').decode(), 16)), d)
        return s, c, d

    def __handle_ctl(self, sock: socket.socket, fw: Firewall):
        try:
            s, c, d = self.do_handshake(sock)
            if s is None or c is None or d is None:
                host, port = sock.getpeername()
                logging.error(f'[{host}@{port}]: Handshake failed.')
                # print(f'[{host}@{port}]: Handshake failed.') # comment out
                return

            # print(f's: {s}, c: {c}, d: {d}') # comment out

            authorized = False
            while True:
                data = ARC4.decrypt(recv(sock, d), s)
                toks = data.split(SEP)
                cmd = toks[0].decode()
                if cmd == 'EXIT':
                    send(sock, b'ACK', d)
                    sock.close()
                    break
                args = []
                if len(toks) > 1:
                    args = toks[1:]
                args = [arg.decode() for arg in args]
                # logging.info(f'[FirewallCTL] {cmd} {args}') # comment out
                resp = b''
                if cmd == 'RUN' and authorized:
                    resp = self.run(fw, args)
                elif cmd == 'SHOW' and authorized:
                    resp = self.show(fw, args)
                elif cmd == 'CHSTAT' and authorized:
                    resp = self.chstat(fw, args)
                elif cmd == 'RULES' and authorized:
                    resp = self.rules(fw, args)
                elif cmd == 'AUTH':
                    resp = self.authenticate(fw, args, c)
                    if resp == b'OK':
                        authorized = True
                        self.firewall._Firewall__interfaces['control'].add(str(sock.getpeername()[0]))
                        # print(f'Authorized: {sock.getpeername()[0]}') # comment out
                    else:
                        resp = b'ERR'
                elif authorized:
                    resp = b'Invalid Command'
                else:
                    resp = b'Unauthorized'
                send(sock, ARC4.encrypt(resp, s), d)
        except Exception as e:
            try:
                host, port = sock.getpeername()
            except Exception:
                host, port = 'unknown', 'unknown'
            logging.error(f'[{host}@{port}] Uncaught Exception: {e}')
            raise e

    def start(self):
        if os.path.exists(LOCK_FILE):
            with open(LOCK_FILE, 'r') as lock_file:
                pid = lock_file.read().strip()
            logging.critical(f'[Firewall] already running with PID: {pid}')
            print(f'[Firewall] already running with PID: {pid}')
            exit(1)

        with open(LOCK_FILE, 'w') as lock_file:
            lock_file.write(str(os.getpid()))
            lock_file.flush()

        def sig_handler(sig, frame):
            del_iptables(self.port_num, sig, frame)

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        signal.signal(signal.SIGQUIT, sig_handler)
        signal.signal(signal.SIGABRT, sig_handler)
        signal.signal(signal.SIGTSTP, sig_handler)
        signal.signal(signal.SIGSEGV, sig_handler)
        signal.signal(signal.SIGILL, sig_handler)

        try:
            logging.info(f'[FirewallCTL] Starting {self.firewall.id}...')
            fw_thread = Thread(target=self.firewall.start, daemon=True)
            fw_thread.start()
            logging.info(f'[Firewall] {self.firewall.id} started.')
            ctl_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ctl_listener.bind((BIND_ADDR, self.port_num))
            logging.info(f'[FirewallCTL] Bound to {BIND_ADDR}@{self.port_num}.')
            print(f'[FirewallCTL] Bound to {BIND_ADDR}@{self.port_num}.')
            ctl_listener.listen()
            while True:
                sock, addr = ctl_listener.accept()
                logging.info(f'[FirewallCTL] Connection from {addr}')
                Thread(target=self.__handle_ctl, args=(sock, self.firewall)).start()
        except (Exception, KeyboardInterrupt) as e:
            logging.critical(f'[FirewallCTL] Uncaught Exception: {e}')
            self.stop()
            print()
            # raise e # comment out
            exit()

    def stop(self):
        if os.path.exists(LOCK_FILE):
            os.remove(LOCK_FILE)
        logging.info(f'[Firewall] Stopping {self.firewall.id}...')
        self.firewall.stop()
        logging.info(f'[Firewall] {self.firewall.id} stopped.')


def main():
    port = BASE_BIND_PORT
    while True:
        try:
            fw_ctl = FirewallCTL(randint(1, 100), RULES_FILE, port)
            fw_ctl.start()
            break
        except OSError:
            try:
                fw_ctl.stop()
            except Exception:
                pass
            port += 1


if __name__ == '__main__':
    main()
