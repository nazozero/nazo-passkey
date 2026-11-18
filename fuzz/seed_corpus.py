#!/usr/bin/env python3
"""Regenerate public W3C seeds and explicit boundary mutations.

The small reader below extracts existing CBOR bytes, not production inputs.
It does not generate new cryptographic keys, certificates, or signatures.
"""
from pathlib import Path
import base64
import json

ROOT = Path(__file__).resolve().parent
NAMES = ["none-es256", "packed-self-es256", "packed-es256", "packed-eddsa", "fido-u2f-es256"]
MODES = 8


def decode(data, pos=0):
    first = data[pos]
    pos += 1
    major, argument = first >> 5, first & 31
    if argument >= 24:
        if argument > 27:
            raise ValueError("unexpected indefinite/reserved encoding in W3C fixture")
        width = 1 << (argument - 24)
        argument = int.from_bytes(data[pos:pos + width], "big")
        pos += width
    if major in (0, 1):
        return (argument if major == 0 else -1 - argument), pos
    if major in (2, 3):
        value = data[pos:pos + argument]
        assert len(value) == argument
        return (value if major == 2 else value.decode("utf-8")), pos + argument
    if major == 4:
        values = []
        for _ in range(argument):
            value, pos = decode(data, pos)
            values.append(value)
        return values, pos
    if major == 5:
        values = {}
        for _ in range(argument):
            key, pos = decode(data, pos)
            value, pos = decode(data, pos)
            assert key not in values
            values[key] = value
        return values, pos
    raise ValueError("unexpected value in public W3C fixture")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main():
    fixture = json.loads((ROOT.parent / "tests/fixtures/w3c-level3.json").read_text())
    corpus = ROOT / "corpus/ceremonies"
    corpus.mkdir(parents=True, exist_ok=True)
    boundary_seeds = 0
    for fixture_index, name in enumerate(NAMES):
        vector = next(v for v in fixture["vectors"] if v["name"] == name)
        registration = {k: bytes.fromhex(v) for k, v in vector["registration"].items()}
        authentication = {k: bytes.fromhex(v) for k, v in vector["authentication"].items()}
        envelope, consumed = decode(registration["attestationObject"])
        assert consumed == len(registration["attestationObject"])
        auth_data = envelope["authData"]
        assert auth_data[32] & 0x40
        id_length = int.from_bytes(auth_data[53:55], "big")
        assert auth_data[55:55 + id_length] == registration["credential_id"]
        key_start = 55 + id_length
        key, key_end = decode(auth_data, key_start)
        assert key[3] in (-7, -8)
        credential_id = b64(registration["credential_id"])
        envelope = {
            "id": credential_id, "rawId": credential_id, "type": "public-key",
            "clientExtensionResults": {},
        }
        registration_json = {**envelope, "response": {
            "transports": [],
            "attestationObject": b64(registration["attestationObject"]),
            "clientDataJSON": b64(registration["clientDataJSON"]),
        }}
        authentication_json = {**envelope, "response": {
            "authenticatorData": b64(authentication["authenticatorData"]),
            "clientDataJSON": b64(authentication["clientDataJSON"]),
            "signature": b64(authentication["signature"]),
        }}
        seeds = [
            (0, "attestation", registration["attestationObject"]),
            (1, "registration-client-data", registration["clientDataJSON"]),
            (2, "authenticator-data", authentication["authenticatorData"]),
            (3, "stored-cose", auth_data[key_start:key_end]),
            (4, "signature", authentication["signature"]),
            (5, "registration-json", json.dumps(registration_json, separators=(",", ":")).encode()),
            (5, "authentication-json", json.dumps(authentication_json, separators=(",", ":")).encode()),
            (6, "authentication-client-data", authentication["clientDataJSON"]),
            (7, "discoverable-handle", b"fuzz-user"),
        ]
        # The existing credential point, authenticator data and real signature
        # remain unchanged. Stored keys accept non-canonical map ordering, but
        # a present key_ops must have the correct schema and permit verify(2).
        stored_key = auth_data[key_start:key_end]
        assert stored_key[0] >> 5 == 5 and stored_key[0] & 31 < 23
        with_operation = bytes([stored_key[0] + 1]) + stored_key[1:] + b"\x04"
        for description, operations in [
            ("verify", b"\x81\x02"),
            ("sign-only", b"\x81\x01"),
            ("empty", b"\x80"),
            ("invalid-after-verify", b"\x82\x02\xf5"),
        ]:
            seeds.append((3, f"stored-cose-key-ops-{description}", with_operation + operations))
            boundary_seeds += 1
        if key[3] == -8:
            signature = authentication["signature"]
            assert len(signature) == 64
            for description, point in [
                ("zero-r", bytes(32)),
                ("identity-r", b"\x01" + bytes(31)),
                ("negative-zero-r", b"\x01" + bytes(30) + b"\x80"),
                ("out-of-range-r", b"\xed" + b"\xff" * 30 + b"\x7f"),
            ]:
                seeds.append((4, f"signature-{description}", point + signature[32:]))
                boundary_seeds += 1
            seeds.append((4, "signature-out-of-range-s", signature[:32] + b"\xff" * 32))
            boundary_seeds += 1
        for mode, description, data in seeds:
            selector = fixture_index * MODES + mode
            (corpus / f"{name}-{description}").write_bytes(bytes([selector]) + data)
    print(f"Generated {len(NAMES) * 9} unchanged W3C seeds and {boundary_seeds} boundary mutations for {len(NAMES)} fixtures")


if __name__ == "__main__":
    main()
