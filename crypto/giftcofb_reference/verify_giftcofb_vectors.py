
import ctypes
import re
from pathlib import Path

U8 = ctypes.c_ubyte
PTR = ctypes.POINTER(U8)
ULL = ctypes.c_ulonglong

dll = ctypes.CDLL(str(Path(__file__).with_name("giftcofb.dll")))

encrypt = dll.crypto_aead_encrypt
encrypt.argtypes = [
    PTR, ctypes.POINTER(ULL), PTR, ULL, PTR, ULL, PTR, PTR, PTR
]
encrypt.restype = ctypes.c_int


def buffer(data):
    return (U8 * max(1, len(data)))(*data) if data else (U8 * 1)()


text = Path(__file__).with_name("LWC_AEAD_KAT_128_128.txt").read_text()
cases = re.split(r"(?m)^Count = ", text.strip())[1:]

passed = 0
errors = []

for case in cases:
    fields = dict(
        line.split(" = ", 1)
        for line in case.splitlines()
        if " = " in line
    )

    count = fields.get("Count", "?")
    key = bytes.fromhex(fields["Key"])
    nonce = bytes.fromhex(fields["Nonce"])
    plaintext = bytes.fromhex(fields["PT"])
    aad = bytes.fromhex(fields["AD"])
    expected = bytes.fromhex(fields["CT"])

    out = (U8 * (len(plaintext) + 16))()
    out_len = ULL(0)

    rc = encrypt(
        out, ctypes.byref(out_len),
        buffer(plaintext), ULL(len(plaintext)),
        buffer(aad), ULL(len(aad)),
        None, buffer(nonce), buffer(key)
    )

    actual = bytes(out[:out_len.value])

    if rc != 0 or actual != expected:
        errors.append(count)
    else:
        passed += 1

print("Total vectors:", len(cases))
print("Passed:", passed)
print("Failed:", len(errors))
if errors:
    print("First failing cases:", errors[:10])

