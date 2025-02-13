# BITSCTF 2025

1. By `jibe__`
- Praise our RNG Gods
```py
import random
import re

from pwnlib.tubes.remote import remote
from randcrack import RandCrack
from tqdm import tqdm


def generate_password(i):
    return random.getrandbits(32) * ((i ^ 0xBAD1DEA) ^ 0x1337C0DE) * 0xB1007411


def reverse_output(p: int, i):
    assert p % 0xB1007411 == 0
    p //= 0xB1007411
    k = (i ^ 0xBAD1DEA) ^ 0x1337C0DE
    assert p % k == 0
    return p // k


def main():
    r = remote("chals.bitskrieg.in", 7007)
    print(r.recvuntil(b"> ").decode())

    # Gather PRNG outputs
    rc = RandCrack()
    for i in tqdm(range(1, 624 + 1)):
        r.sendline(b"0")
        answer = r.recvuntil(b"> ").decode()

        m = re.findall("You are (\d+) away", answer)
        value = int(m[0])
        rc.submit(reverse_output(value, i))

    # RNG state has been recovered. Subsequent outputs can be predicted
    i = 624 + 1
    password = rc.predict_getrandbits(32) * ((i ^ 0xBAD1DEA) ^ 0x1337C0DE) * 0xB1007411
    r.sendline(str(password).encode())
    print(r.recvline().decode())
    r.close()


if __name__ == "__main__":
    main()

# Access Granted! Here is your flag: BITSCTF{V4u1t_cr4ck1ng_w45_345y_0384934}
```
- Baby Rev
```py
import base64
import zlib
import re

def decode_and_decompress(s: str) -> str:
    s = base64.b64decode(s[::-1])
    return zlib.decompress(s).decode()


def main():
    with open("chall.py", encoding="utf8") as f:
        s = re.findall(f"b'(\S+)'", f.read())[0]

    while True:
        s = decode_and_decompress(s)
        m = re.findall(r"b'(\S+)'", s)
        if not m:
            break
        s = m[0]
    print(s)


if __name__ == "__main__":
    main()
```
- Loginator
```py
import subprocess
import string

wanted = bytes.fromhex(
    "02 92 a8 06 77 a8 32 3f 15 68 c9 77 de 86 99 7d 08 60 8e 64 77 be ba 74 26 96 e7 4e"
)


def guess_next_char(password: str) -> str:
    current_len = len(password)
    for c in string.printable:
        with subprocess.Popen(
            ["/tmp/loginator.out", f"{password + c}"], stdout=subprocess.PIPE
        ) as proc:
            flag = bytes.fromhex(proc.stdout.read().decode())
        if flag == wanted[: current_len + 1]:
            return password + c
    raise ValueError("Next char not found")


def main():
    password = ""
    for _ in range(len(wanted)):
        password = guess_next_char(password)
        print(password)


if __name__ == "__main__":
    main()
```
- Symphonies
```py
import io

import mido

# Fix corrupted MIDI header
with open("Demo1", "rb") as f:
    data = f.read()
    midi_file = io.BytesIO(b"MThd" + data[4:])

# Extract encoded message.
# Data is encoded into "velocity" and "note" field of "note_on" messages
mid = mido.MidiFile(file=midi_file)
track = mid.tracks[0]

velocities = []
notes = []
for msg in track:
    if msg.type == "note_on":
        velocities.append(msg.velocity)
        notes.append(msg.note)

ascii_numbers = bytes(notes).decode()
notes = [int(c) for c in ascii_numbers.split()]
print(bytes([a ^ b for a, b in zip(notes, velocities)]).decode())
```