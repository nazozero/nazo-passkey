#!/usr/bin/env python3
"""Regenerate public W3C seeds; reads only the checked-in trusted fixture file.

The small reader below extracts existing CBOR bytes, not production inputs.
It does not generate authenticator data, keys, certificates, or signatures.
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
        registration_json = {
            "id": credential_id, "transports": [],
            "attestationObject": b64(registration["attestationObject"]),
            "clientDataJSON": b64(registration["clientDataJSON"]),
        }
        authentication_json = {
            "id": credential_id,
            "authenticatorData": b64(authentication["authenticatorData"]),
            "clientDataJSON": b64(authentication["clientDataJSON"]),
            "signature": b64(authentication["signature"]),
            "userHandle": None,
        }
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
        for mode, description, data in seeds:
            selector = fixture_index * MODES + mode
            (corpus / f"{name}-{description}").write_bytes(bytes([selector]) + data)
    print(f"Generated {len(NAMES) * 9} W3C seeds for {len(NAMES)} fixtures")


if __name__ == "__main__":
    main()
