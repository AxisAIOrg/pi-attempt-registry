"""Build / sign AttemptRegistry submit messages (matches the Soroban contract).

Message (183 bytes), ed25519-signed raw (no EIP-191 prefix):
  b"AXIS_STELLAR_ATTEMPT_V1"   # 23
  + network_id                # 32  sha256(network passphrase)
  + contract_id               # 32  raw payload of the C... address
  + data_id                   # 16  uint128 BE
  + task_id                   # 16  uint128 BE
  + user_id                   # 32  raw payload of the G... or C... address
  + score                     # 16  uint128 BE
  + simulation_time           # 16  uint128 BE (ms)
"""

from __future__ import annotations

import hashlib
from typing import Final

DOMAIN: Final[bytes] = b"AXIS_STELLAR_ATTEMPT_V1"

MAINNET_PASSPHRASE = "Public Global Stellar Network ; September 2015"
TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"


def network_id(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def _u128_be(value: int) -> bytes:
    if value < 0 or value >= 1 << 128:
        raise ValueError("value must fit in uint128")
    return value.to_bytes(16, "big")


def _strkey_payload(address: str) -> bytes:
    try:
        from stellar_sdk import strkey
    except ImportError as exc:
        raise ImportError("pip install stellar-sdk") from exc

    if address.startswith("G"):
        return strkey.decode_ed25519_public_key(address)
    if address.startswith("C"):
        return strkey.decode_contract(address)
    raise ValueError(f"unsupported strkey: {address}")


def build_submit_message(
    *,
    network_passphrase: str,
    contract_id: str,
    user: str,
    data_id: int,
    task_id: int,
    score: int,
    simulation_time: int,
) -> bytes:
    msg = (
        DOMAIN
        + network_id(network_passphrase)
        + _strkey_payload(contract_id)
        + _u128_be(data_id)
        + _u128_be(task_id)
        + _strkey_payload(user)
        + _u128_be(score)
        + _u128_be(simulation_time)
    )
    if len(msg) != 183:
        raise RuntimeError(f"unexpected message length {len(msg)}")
    return msg


def sign_submit_message(secret_key: str, message: bytes) -> bytes:
    """Return 64-byte ed25519 signature. `secret_key` is an S... stellar secret."""
    try:
        from stellar_sdk import Keypair
    except ImportError as exc:
        raise ImportError("pip install stellar-sdk") from exc

    return Keypair.from_secret(secret_key).sign(message)
