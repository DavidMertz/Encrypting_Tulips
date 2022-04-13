import base64
from hashlib import md5

words = open('/usr/local/share/scrabble').read().split()
bob_privkey = b'robert_16_chars_'
clara_privkey = b'clara_password77'
david_privkey = b'david_password00'


def sign(last_block: str,
         timestamp: str,
         payload: str,
         password: bytes) -> str:
    s = "\n".join([last_block, timestamp, payload])
    digest = md5(s.encode()).digest()
    sig = bytes(a ^ b for a, b in zip(digest, password))
    return base64.b64encode(sig).decode()


def verify_block(last_block: str,
                 timestamp: str,
                 payload: str,
                 signature: str,
                 nonce: str) -> bool:
    s = "\n".join([last_block, timestamp, payload, signature, nonce])
    return md5(s.encode()).hexdigest().startswith('fffffff')


def find_nonce(last_block: str,
               timestamp: str,
               payload: str,
               signature: str):
    s = "\n".join([last_block, timestamp, payload, signature])
    for w1 in words:
        for w2 in words:
            hash = md5(f"{s}\n{w2}_{w1}".encode()).hexdigest()
            if hash.startswith('fffffff'):
                return (hash, f"{w2}_{w1}")
