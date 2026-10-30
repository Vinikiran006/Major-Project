
import socket
import json
import ctypes
import os
import sys
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ascon

LOG_FILE = open(
    f"receiver_{datetime.now():%Y%m%d_%H%M%S}.log",
    "a",
    buffering=1,
    encoding="utf-8"
)

sys.stdout = type(sys.stdout)(
    sys.stdout.fileno(),
    encoding="utf-8",
    errors="replace",
    line_buffering=True
) if False else sys.stdout

class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()

    def flush(self):
        for stream in self.streams:
            stream.flush()

sys.stdout = Tee(sys.stdout, LOG_FILE)
sys.stderr = Tee(sys.stderr, LOG_FILE)
# --------------------------------------------------
# TCP SERVER CONFIGURATION
# --------------------------------------------------

HOST = "0.0.0.0"
PORT = 5000


# --------------------------------------------------
# DEMONSTRATION CRYPTOGRAPHIC CONFIGURATION
# Must match the ESP32 sketch.
# Do not use this hardcoded key in production.
# --------------------------------------------------

AES_KEY = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
ASCON_KEY = AES_KEY
GIFT_KEY = AES_KEY

AAD = b"ESP32-DHT22-v1"


# --------------------------------------------------
# LOAD GIFT-COFB DLL
# Keep giftcofb.dll beside this Python file.
# --------------------------------------------------

GIFT_DLL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "giftcofb.dll",
)

if not os.path.isfile(GIFT_DLL_PATH):
    raise FileNotFoundError(
        f"GIFT DLL not found: {GIFT_DLL_PATH}"
    )

gift = ctypes.CDLL(GIFT_DLL_PATH)

U8P = ctypes.POINTER(ctypes.c_ubyte)
ULLP = ctypes.POINTER(ctypes.c_ulonglong)

gift.giftcofb_crypto_aead_decrypt.argtypes = [
    U8P,                         # m: output plaintext
    ULLP,                        # mlen: output plaintext length
    U8P,                         # nsec: unused
    U8P,                         # c: ciphertext + tag
    ctypes.c_ulonglong,          # clen
    U8P,                         # ad
    ctypes.c_ulonglong,          # adlen
    U8P,                         # npub: nonce
    U8P,                         # k: key
]

gift.giftcofb_crypto_aead_decrypt.restype = ctypes.c_int


def as_c_buffer(data):
    """Convert bytes to a ctypes byte buffer."""
    if not data:
        return None
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


# --------------------------------------------------
# GIFT-COFB-128 DECRYPTION
# Ciphertext field contains ciphertext followed by
# the 16-byte authentication tag.
# --------------------------------------------------

def decrypt_gift(ciphertext, nonce, aad, key):
    if len(nonce) != 16:
        raise ValueError("Invalid GIFT nonce length")

    if len(key) != 16:
        raise ValueError("Invalid GIFT key length")

    if len(ciphertext) < 16:
        raise ValueError("GIFT ciphertext is missing its tag")

    # Allocate output space. Plaintext cannot be longer
    # than the ciphertext including its tag.
    output = (ctypes.c_ubyte * len(ciphertext))()
    output_len = ctypes.c_ulonglong(0)

    ciphertext_buf = as_c_buffer(ciphertext)
    nonce_buf = as_c_buffer(nonce)
    aad_buf = as_c_buffer(aad)
    key_buf = as_c_buffer(key)

    result = gift.giftcofb_crypto_aead_decrypt(
        output,
        ctypes.byref(output_len),
        None,
        ciphertext_buf,
        len(ciphertext),
        aad_buf,
        len(aad),
        nonce_buf,
        key_buf,
    )

    if result != 0:
        raise ValueError("GIFT authentication failed")

    if output_len.value > len(output):
        raise ValueError("Invalid GIFT plaintext length")

    return bytes(output[:output_len.value])


# --------------------------------------------------
# DECRYPT AND AUTHENTICATE INCOMING MESSAGE
# --------------------------------------------------

def decrypt_message(message):
    algorithm = message.get("algorithm")

    if algorithm == "AES-128-GCM":
        nonce = bytes.fromhex(message["nonce"])
        ciphertext = bytes.fromhex(message["ciphertext"])
        tag = bytes.fromhex(message["tag"])
        aad = message.get("aad", AAD.decode()).encode()

        if len(nonce) != 12:
            raise ValueError("Invalid AES nonce length")

        if len(tag) != 16:
            raise ValueError("Invalid AES authentication tag length")

        plaintext = AESGCM(AES_KEY).decrypt(
            nonce,
            ciphertext + tag,
            aad,
        )

    elif algorithm == "ASCON-AEAD128":
        nonce = bytes.fromhex(message["nonce"])
        ciphertext = bytes.fromhex(message["ciphertext"])
        aad = message.get("aad", AAD.decode()).encode()

        if len(nonce) != 16:
            raise ValueError("Invalid ASCON nonce length")

        if len(ciphertext) < 16:
            raise ValueError("ASCON ciphertext is missing its tag")

        plaintext = ascon.ascon_decrypt(
            ASCON_KEY,
            nonce,
            aad,
            ciphertext,
            variant="Ascon-AEAD128",
        )

        if plaintext is None:
            raise ValueError("ASCON authentication failed")

    elif algorithm == "GIFT-COFB-128":
        nonce = bytes.fromhex(message["nonce"])
        ciphertext = bytes.fromhex(message["ciphertext"])
        aad = message.get("aad", AAD.decode()).encode()

        plaintext = decrypt_gift(
            ciphertext,
            nonce,
            aad,
            GIFT_KEY,
        )

    else:
        raise ValueError(
            f"Unsupported encryption algorithm: {algorithm}"
        )

    # Parse JSON only after successful authentication/decryption.
    return json.loads(plaintext.decode("utf-8"))


# --------------------------------------------------
# TCP RECEIVER
# Messages are newline-delimited JSON.
# --------------------------------------------------

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(5)

        print(f"Secure IoT receiver listening on port {PORT}")
        print(
            "Supported algorithms: "
            "AES-128-GCM, ASCON-AEAD128, GIFT-COFB-128"
        )
        print("Waiting for ESP32 messages...")

        while True:
            conn, addr = server.accept()
            print(f"\nConnection from {addr}")

            with conn:
                buffer = b""

                while True:
                    data = conn.recv(4096)

                    if not data:
                        break

                    buffer += data

                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)

                        if not line.strip():
                            continue

                        try:
                            message = json.loads(line.decode("utf-8"))

                            print("\nEncrypted message received.")
                            print("Device:", message.get("device_id", "Unknown"))
                            print("Algorithm:", message.get("algorithm"))

                            sensor_data = decrypt_message(message)

                            print("Authentication: PASS")
                            print("Decryption: PASS")
                            print("Recovered sensor data:")
                            print(json.dumps(sensor_data, indent=2))

                        except Exception as error:
                            print("Authentication/decryption: REJECTED")
                            print("Reason:", str(error))

                # Handle a final message if the connection closes
                # without a trailing newline.
                if buffer.strip():
                    try:
                        message = json.loads(buffer.decode("utf-8"))
                        sensor_data = decrypt_message(message)

                        print("\nAuthentication: PASS")
                        print("Decryption: PASS")
                        print("Recovered sensor data:")
                        print(json.dumps(sensor_data, indent=2))

                    except Exception as error:
                        print("Authentication/decryption: REJECTED")
                        print("Reason:", str(error))

            print("Connection closed.")

    except KeyboardInterrupt:
        print("\nReceiver stopped.")

    finally:
        server.close()


if __name__ == "__main__":
    main()
