import socket
from Crypto.Cipher import DES

class RFBProtocol:
    def __init__(self, host, password, port=5900, timeout=3):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.sock = None
        self.connected = False
        self.server_name = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        banner = self.sock.recv(12)
        if not banner.startswith(b"RFB"):
            raise Exception("Not a VNC server")
        self.sock.sendall(b"RFB 003.003\n")
        method = int.from_bytes(self.sock.recv(4), "big")
        if method == 2:
            challenge = self.sock.recv(16)
            self.sock.sendall(self._vnc_response(challenge))
            result = int.from_bytes(self.sock.recv(4), "big")
            if result != 0:
                raise Exception("Auth failed")
            self.connected = True
        else:
            raise Exception("Unsupported auth method")

    def _vnc_response(self, challenge):
        key = (self.password + '\0' * 8)[:8]
        key = bytes([int('{:08b}'.format(b)[::-1], 2) for b in key.encode("latin-1")])
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(challenge)

    def close(self):
        if self.sock:
            self.sock.close() 