import os
from dotenv import load_dotenv

load_dotenv()

def load_optional_key(env_name):
    """Load a 16-byte key from a 32-character hex environment variable."""
    value = os.environ.get(env_name)

    if value is None or value.strip() == "":
        return None

    value = value.strip()

    if len(value) != 32:
        raise ValueError(
            f"{env_name} must contain exactly 32 hexadecimal characters."
        )

    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            f"{env_name} must contain valid hexadecimal characters."
        ) from exc

    if len(key) != 16:
        raise ValueError(f"{env_name} must decode to exactly 16 bytes.")

    return key


def load_optional_hmac_key():
    """Load a 32-byte HMAC key from a 64-character hex environment variable."""
    value = os.environ.get("IOT_HMAC_KEY")

    if value is None or not value.strip():
        raise ValueError(
            "IOT_HMAC_KEY is missing. Configure it before starting sender or gateway."
        )

    value = value.strip()

    if len(value) != 64:
        raise ValueError(
            "IOT_HMAC_KEY must contain exactly 64 hexadecimal characters."
        )

    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("IOT_HMAC_KEY must be valid hexadecimal.") from exc

    if len(key) != 32:
        raise ValueError("HMAC key must be exactly 32 bytes.")

    return key
