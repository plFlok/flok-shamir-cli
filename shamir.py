#!/usr/bin/env python3
"""Offline encoder and decoder for the flok.codes FSS share format."""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sys

POWERED_BY = "https://flok.codes"
MAX_SECRET_BYTES = 4096
MAX_LEGACY_SECRET_BYTES = 1024
MAX_SHARES = 20
MAX_BASE64_LENGTH = 4 * ((MAX_SECRET_BYTES + 43 + 2) // 3)
MAX_DECODE_INPUT = MAX_SHARES * (MAX_BASE64_LENGTH + 64) + 1024
METADATA_SIZE = 6
TAG_SIZE = 16
KEY_SIZE = 16
CHECKSUM_SIZE = 4
SHARE_OFFSET = METADATA_SIZE + TAG_SIZE
LEGACY_HEADER_SIZE = 36
LEGACY_SHARE_END = LEGACY_HEADER_SIZE + 33
LEGACY_CHECKSUM_SIZE = 32


@dataclass(frozen=True)
class Share:
    header: bytes
    payload: bytes
    ciphertext: bytes | None = None


def check_counts(total: int, threshold: int) -> None:
    if not 2 <= threshold <= total <= MAX_SHARES:
        raise ValueError("Choose 2–20 shares and a threshold between 2 and the number of shares.")


def multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(256), with the AES polynomial 0x11b."""
    result = 0
    for _ in range(8):
        result ^= a & -(b & 1)
        a = ((a << 1) & 0xFF) ^ (0x1B & -(a >> 7))
        b >>= 1
    return result


def inverse(value: int) -> int:
    # The multiplicative group has order 255, so a nonzero byte's inverse is a^254.
    result = 1
    exponent = 254
    while exponent:
        if exponent & 1:
            result = multiply(result, value)
        value = multiply(value, value)
        exponent >>= 1
    return result


def split_payload(payload: bytes, total: int, threshold: int) -> list[bytearray]:
    coordinates = secrets.SystemRandom().sample(range(1, 256), total)
    shares = [bytearray(len(payload)) + bytes([x]) for x in coordinates]
    degree = threshold - 1
    random_bytes = secrets.token_bytes(len(payload) * degree)

    for index, intercept in enumerate(payload):
        start = index * degree
        coefficients = random_bytes[start:start + degree]
        for share, x in zip(shares, coordinates):
            value = coefficients[-1]
            for coefficient in reversed(coefficients[:-1]):
                value = multiply(value, x) ^ coefficient
            share[index] = multiply(value, x) ^ intercept
    return shares


def combine_payloads(payloads: list[bytes]) -> bytes:
    coordinates = [payload[-1] for payload in payloads]
    weights = []
    for x in coordinates:
        # Lagrange basis at x = 0. Subtraction and addition both use XOR in GF(256).
        weight = 1
        for other in coordinates:
            if other != x:
                weight = multiply(weight, multiply(other, inverse(x ^ other)))
        weights.append(weight)

    result = bytearray(len(payloads[0]) - 1)
    for payload, weight in zip(payloads, weights):
        for index, value in enumerate(payload[:-1]):
            result[index] ^= multiply(value, weight)
    return bytes(result)


def recovery_tag(key: bytes, metadata: bytes, plaintext: bytes) -> bytes:
    return hmac.digest(key, metadata + plaintext, "sha256")[:TAG_SIZE]


def encode(plaintext: bytes, total: int, threshold: int) -> list[str]:
    check_counts(total, threshold)
    if not 1 <= len(plaintext) <= MAX_SECRET_BYTES:
        raise ValueError(f"Enter a secret between 1 and {MAX_SECRET_BYTES} UTF-8 bytes.")
    check_utf8(plaintext)

    metadata = b"FSS\x02" + bytes([threshold, total])
    key = secrets.token_bytes(KEY_SIZE)
    header = metadata + recovery_tag(key, metadata, plaintext)
    result = []
    for share in split_payload(plaintext + key, total, threshold):
        packet = header + share
        checksum = hashlib.sha256(packet).digest()[:CHECKSUM_SIZE]
        result.append(base64.b64encode(packet + checksum).decode("ascii"))
    return result


def parse_share(value: str) -> Share:
    value = value.strip()
    if not value or len(value) > MAX_BASE64_LENGTH or len(value) % 4:
        raise ValueError("Invalid Base64 share.")
    try:
        packet = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Invalid Base64 share.") from None

    if base64.b64encode(packet).decode("ascii") != value:
        raise ValueError("Invalid Base64 share.")
    if len(packet) < METADATA_SIZE or packet[:4] not in (b"FSS\x01", b"FSS\x02"):
        raise ValueError("Unsupported share format. Use FSS1 or FSS2 shares.")
    check_counts(total=packet[5], threshold=packet[4])

    if packet[3] == 1:
        header = packet[:LEGACY_HEADER_SIZE]
        payload = packet[LEGACY_HEADER_SIZE:LEGACY_SHARE_END]
        ciphertext = packet[LEGACY_SHARE_END:-LEGACY_CHECKSUM_SIZE]
        cipher_length = int.from_bytes(header[34:36], "big")
        if not 17 <= cipher_length <= MAX_LEGACY_SECRET_BYTES + 16 or len(ciphertext) != cipher_length:
            raise ValueError("Invalid or truncated FSS1 share.")
        checksum_size = LEGACY_CHECKSUM_SIZE
    else:
        header = packet[:SHARE_OFFSET]
        payload = packet[SHARE_OFFSET:-CHECKSUM_SIZE]
        ciphertext = None
        if not KEY_SIZE + 2 <= len(payload) <= MAX_SECRET_BYTES + KEY_SIZE + 1:
            raise ValueError("Invalid or truncated FSS2 share.")
        checksum_size = CHECKSUM_SIZE

    if payload[-1] == 0:
        raise ValueError("Invalid share coordinate.")
    expected = hashlib.sha256(packet[:-checksum_size]).digest()[:checksum_size]
    if not hmac.compare_digest(expected, packet[-checksum_size:]):
        raise ValueError("Share checksum failed. Check for copying errors.")
    return Share(header, payload, ciphertext)


def decrypt_legacy(header: bytes, ciphertext: bytes, key: bytes) -> bytes:
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ValueError("FSS1 recovery requires cryptography. Install requirements.txt.") from None

    try:
        return AESGCM(key).decrypt(header[22:34], ciphertext, header)
    except InvalidTag:
        raise ValueError("Recovery authentication failed. Check the shares.") from None


def decode(values: list[str]) -> bytes:
    if not 1 <= len(values) <= MAX_SHARES:
        raise ValueError("Provide between 1 and 20 shares.")
    shares = [parse_share(value) for value in values]
    first = shares[0]
    coordinates = set()
    for share in shares:
        if (
            share.header != first.header
            or len(share.payload) != len(first.payload)
            or share.ciphertext != first.ciphertext
        ):
            raise ValueError("Shares belong to different sets. Use one generation only.")
        coordinate = share.payload[-1]
        if coordinate in coordinates:
            raise ValueError("Duplicate share. Provide a different share from each holder.")
        coordinates.add(coordinate)

    threshold, total = first.header[4:6]
    if len(shares) > total:
        raise ValueError("Too many shares for this set.")
    if len(shares) < threshold:
        raise ValueError(f"Need {threshold} different shares; received {len(shares)}.")

    payload = combine_payloads([share.payload for share in shares])
    if first.ciphertext is not None:
        plaintext = decrypt_legacy(first.header, first.ciphertext, payload)
    else:
        plaintext, key = payload[:-KEY_SIZE], payload[-KEY_SIZE:]
        metadata, tag = first.header[:METADATA_SIZE], first.header[METADATA_SIZE:]
        if not hmac.compare_digest(recovery_tag(key, metadata, plaintext), tag):
            raise ValueError("Recovery authentication failed. Check the shares.")
    check_utf8(plaintext)
    return plaintext


def check_utf8(data: bytes) -> None:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Secret must be valid UTF-8.") from None


def unique_json_fields(pairs: list[tuple]) -> dict:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("Duplicate field in share JSON.")
    return fields


def read_shares(data: bytes) -> list[str]:
    if len(data) > MAX_DECODE_INPUT:
        raise ValueError("Share input is too large.")
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        raise ValueError("Share input must be UTF-8 text.") from None

    if not text.startswith("{"):
        return [line.strip() for line in text.splitlines() if line.strip()]

    try:
        fields = json.loads(text, object_pairs_hook=unique_json_fields)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("Invalid share JSON.") from None
    allowed = {f"key{index}" for index in range(1, MAX_SHARES + 1)}
    fields.pop("powered_by", None)
    if any(key not in allowed or not isinstance(value, str) for key, value in fields.items()):
        raise ValueError("Expected a JSON object with Base64 strings in key1, key2, …, key20.")
    return list(fields.values())


def read_input(path: Path | None, limit: int) -> bytes:
    if path is None:
        return sys.stdin.buffer.read(limit + 1)
    with path.open("rb") as stream:
        return stream.read(limit + 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    encoder = commands.add_parser("encode", help="split UTF-8 text into FSS2 shares and print JSON")
    encoder.add_argument("-n", "--shares", type=int, default=8, help="number of shares (default: 8)")
    encoder.add_argument("-t", "--threshold", type=int, default=5, help="shares needed to recover (default: 5)")
    encoder.add_argument("-i", "--input", type=Path, metavar="FILE", help="UTF-8 secret file (default: stdin)")
    decoder = commands.add_parser("decode", help="recover UTF-8 text from FSS1 or FSS2 shares")
    decoder.add_argument("-i", "--input", type=Path, metavar="FILE", help="share JSON or newline-separated Base64 (default: stdin)")
    args = parser.parse_args()
    try:
        if args.command == "encode":
            shares = encode(read_input(args.input, MAX_SECRET_BYTES), args.shares, args.threshold)
            output = {f"key{index}": share for index, share in enumerate(shares, start=1)}
            output["powered_by"] = POWERED_BY
            print(json.dumps(output, indent=2))
        else:
            sys.stdout.buffer.write(decode(read_shares(read_input(args.input, MAX_DECODE_INPUT))))
    except (OSError, ValueError) as error:
        print(f"shamir.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
