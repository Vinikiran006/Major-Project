
import ctypes
import secrets
from pathlib import Path


KEY_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16


class GiftCofbError(Exception):
    """Base exception for GIFT-COFB operations."""


class GiftCofbAuthenticationError(GiftCofbError):
    """Raised when ciphertext authentication fails."""


class GiftCofb128:
    """Python wrapper around the reference GIFT-COFB-128 C implementation."""

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != KEY_SIZE:
            raise ValueError("GIFT-COFB requires a 16-byte key.")

        dll_path = Path(__file__).with_name("giftcofb.dll")
        if not dll_path.is_file():
            raise FileNotFoundError(f"GIFT-COFB DLL not found: {dll_path}")

        self._key = bytes(key)
        self._dll = ctypes.CDLL(str(dll_path))

        self._u8 = ctypes.c_ubyte
        self._ptr = ctypes.POINTER(self._u8)
        self._ull = ctypes.c_ulonglong

        self._encrypt = self._dll.crypto_aead_encrypt
        self._encrypt.argtypes = [
            self._ptr, ctypes.POINTER(self._ull),
            self._ptr, self._ull, self._ptr, self._ull,
            self._ptr, self._ptr, self._ptr,
        ]
        self._encrypt.restype = ctypes.c_int

        self._decrypt = self._dll.crypto_aead_decrypt
        self._decrypt.argtypes = [
            self._ptr, ctypes.POINTER(self._ull),
            self._ptr, self._ptr, self._ull,
            self._ptr, self._ull, self._ptr, self._ptr,
        ]
        self._decrypt.restype = ctypes.c_int

    def _buffer(self, data: bytes):
        # Allocate at least one byte for empty inputs.
        return (
            (self._u8 * len(data))(*data)
            if data else (self._u8 * 1)()
        )

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
        nonce: bytes | None = None,
    ) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes.")
        if not isinstance(associated_data, bytes):
            raise TypeError("Associated data must be bytes.")

        if nonce is None:
            nonce = secrets.token_bytes(NONCE_SIZE)
        if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
            raise ValueError("Nonce must be exactly 16 bytes.")

        # The caller must ensure this nonce has never been used with this key.
        output = (self._u8 * (len(plaintext) + TAG_SIZE))()
        output_len = self._ull(0)

        result = self._encrypt(
            output, ctypes.byref(output_len),
            self._buffer(plaintext), self._ull(len(plaintext)),
            self._buffer(associated_data), self._ull(len(associated_data)),
            None, self._buffer(nonce), self._buffer(self._key),
        )

        if result != 0:
            raise GiftCofbError(
                f"GIFT-COFB encryption failed with code {result}."
            )

        expected_len = len(plaintext) + TAG_SIZE
        if output_len.value != expected_len:
            raise GiftCofbError("Unexpected ciphertext length.")

        # Format: nonce || ciphertext || authentication tag.
        return nonce + bytes(output[:output_len.value])

    def decrypt(
        self,
        sealed: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        if not isinstance(sealed, bytes):
            raise TypeError("Sealed message must be bytes.")
        if not isinstance(associated_data, bytes):
            raise TypeError("Associated data must be bytes.")

        # 16-byte nonce plus 16-byte minimum authentication tag.
        if len(sealed) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Sealed message is too short.")

        nonce = sealed[:NONCE_SIZE]
        ciphertext_and_tag = sealed[NONCE_SIZE:]

        # Never expose the output buffer unless authentication succeeds.
        output = (self._u8 * max(
            1, len(ciphertext_and_tag) - TAG_SIZE
        ))()
        output_len = self._ull(0)

        result = self._decrypt(
            output, ctypes.byref(output_len),
            None, self._buffer(ciphertext_and_tag),
            self._ull(len(ciphertext_and_tag)),
            self._buffer(associated_data),
            self._ull(len(associated_data)),
            self._buffer(nonce), self._buffer(self._key),
        )

        if result != 0:
            raise GiftCofbAuthenticationError(
                "GIFT-COFB authentication failed."
            )

        expected_len = len(ciphertext_and_tag) - TAG_SIZE
        if output_len.value != expected_len:
            raise GiftCofbError("Unexpected plaintext length.")

        return bytes(output[:output_len.value])
