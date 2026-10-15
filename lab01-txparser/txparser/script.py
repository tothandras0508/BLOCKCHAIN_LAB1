"""Script disassembly, standard output templates and address encoding."""

from __future__ import annotations

from .parser import hash160, sha256d

# --------------------------------------------------------------------------- #
# Opcodes
# --------------------------------------------------------------------------- #

_NAMED_OPS = {
    0x00: "OP_0",
    0x4C: "OP_PUSHDATA1",
    0x4D: "OP_PUSHDATA2",
    0x4E: "OP_PUSHDATA4",
    0x4F: "OP_1NEGATE",
    0x50: "OP_RESERVED",
    0x61: "OP_NOP",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6A: "OP_RETURN",
    0x6B: "OP_TOALTSTACK",
    0x6C: "OP_FROMALTSTACK",
    0x6D: "OP_2DROP",
    0x6E: "OP_2DUP",
    0x73: "OP_IFDUP",
    0x74: "OP_DEPTH",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x77: "OP_NIP",
    0x78: "OP_OVER",
    0x7C: "OP_SWAP",
    0x82: "OP_SIZE",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0x8B: "OP_1ADD",
    0x8C: "OP_1SUB",
    0x93: "OP_ADD",
    0x94: "OP_SUB",
    0x9A: "OP_BOOLAND",
    0x9B: "OP_BOOLOR",
    0x9C: "OP_NUMEQUAL",
    0x9D: "OP_NUMEQUALVERIFY",
    0xA5: "OP_WITHIN",
    0xA6: "OP_RIPEMD160",
    0xA7: "OP_SHA1",
    0xA8: "OP_SHA256",
    0xA9: "OP_HASH160",
    0xAA: "OP_HASH256",
    0xAB: "OP_CODESEPARATOR",
    0xAC: "OP_CHECKSIG",
    0xAD: "OP_CHECKSIGVERIFY",
    0xAE: "OP_CHECKMULTISIG",
    0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY",
    0xBA: "OP_CHECKSIGADD",
}


def opcode_name(op: int) -> str:
    if op in _NAMED_OPS:
        return _NAMED_OPS[op]
    if 0x51 <= op <= 0x60:
        return f"OP_{op - 0x50}"  # OP_1 .. OP_16
    return f"OP_UNKNOWN_{op:02x}"


def disassemble(script: bytes) -> list[str]:
    """Split a script into opcode names and ``<hex>`` data pushes."""
    out: list[str] = []
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1

        if 0x01 <= op <= 0x4B:  # direct push: the opcode is the length
            size, prefix = op, ""
        elif op in (0x4C, 0x4D, 0x4E):  # OP_PUSHDATA1/2/4
            width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            if pos + width > len(script):
                out.append(f"{opcode_name(op)} <truncated length>")
                break
            size = int.from_bytes(script[pos : pos + width], "little")
            pos += width
            prefix = opcode_name(op) + " "
        else:
            out.append(opcode_name(op))
            continue

        data = script[pos : pos + size]
        pos += size
        token = f"{prefix}<{data.hex()}>"
        if len(data) < size:
            token += " (truncated)"
        out.append(token)
    return out


# --------------------------------------------------------------------------- #
# Output classification
# --------------------------------------------------------------------------- #


def classify(spk: bytes) -> tuple[str, bytes | None]:
    """Match a scriptPubKey against the standard templates.

    Returns (type, payload): payload is the key, key hash, script hash or
    witness program an address encodes, or None when there is no address.
    """
    n = len(spk)

    if n == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac":
        return "p2pkh", spk[3:23]  # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    if n == 23 and spk[:2] == b"\xa9\x14" and spk[22] == 0x87:
        return "p2sh", spk[2:22]  # OP_HASH160 <20> OP_EQUAL
    if n == 22 and spk[:2] == b"\x00\x14":
        return "p2wpkh", spk[2:]  # OP_0 <20>
    if n == 34 and spk[:2] == b"\x00\x20":
        return "p2wsh", spk[2:]  # OP_0 <32>
    if n == 34 and spk[:2] == b"\x51\x20":
        return "p2tr", spk[2:]  # OP_1 <32>
    if spk[-1:] == b"\xac" and n in (35, 67) and spk[0] == n - 2:
        return "p2pk", spk[1:-1]  # <33 or 65 byte pubkey> OP_CHECKSIG
    if n >= 1 and spk[0] == 0x6A:
        return "nulldata", None  # OP_RETURN ...
    if n >= 3 and spk[-1] == 0xAE and 0x51 <= spk[0] <= 0x60 and 0x51 <= spk[-2] <= 0x60:
        return "multisig", None  # OP_m <keys> OP_n OP_CHECKMULTISIG
    return "nonstandard", None


# --------------------------------------------------------------------------- #
# Base58Check
# --------------------------------------------------------------------------- #

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload: bytes) -> str:
    data = payload + sha256d(payload)[:4]
    n = int.from_bytes(data, "big")
    digits = []
    while n:
        n, r = divmod(n, 58)
        digits.append(_B58[r])
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + "".join(reversed(digits))


# --------------------------------------------------------------------------- #
# Bech32 / Bech32m (BIP-173, BIP-350)
# --------------------------------------------------------------------------- #

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i, g in enumerate(_GEN):
            if (top >> i) & 1:
                chk ^= g
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _to_5bit(data: bytes) -> list[int]:
    """Regroup 8-bit bytes into 5-bit groups, zero-padding the last one."""
    acc = bits = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a SegWit address: Bech32 for v0, Bech32m for v1 and above."""
    const = BECH32_CONST if witver == 0 else BECH32M_CONST
    data = [witver, *_to_5bit(witprog)]
    pm = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(pm >> (5 * (5 - i))) & 31 for i in range(6)]
    return f"{hrp}1" + "".join(_CHARSET[d] for d in data + checksum)


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #

NETWORKS = {
    "mainnet": {"pkh": 0x00, "sh": 0x05, "hrp": "bc"},
    "testnet": {"pkh": 0x6F, "sh": 0xC4, "hrp": "tb"},
    "regtest": {"pkh": 0x6F, "sh": 0xC4, "hrp": "bcrt"},
}


def address_for(script_type: str, payload: bytes | None, network: str = "regtest") -> str | None:
    """Address for a classified output, or None if the type has none.

    P2PK has no address format of its own; the P2PKH address of the same key
    is returned so the output can still be recognised (this is how explorers
    show the genesis output as 1A1zP1...).
    """
    if payload is None:
        return None
    net = NETWORKS[network]
    if script_type == "p2pkh":
        return base58check(bytes([net["pkh"]]) + payload)
    if script_type == "p2sh":
        return base58check(bytes([net["sh"]]) + payload)
    if script_type == "p2pk":
        return base58check(bytes([net["pkh"]]) + hash160(payload))
    if script_type in ("p2wpkh", "p2wsh"):
        return bech32_encode(net["hrp"], 0, payload)
    if script_type == "p2tr":
        return bech32_encode(net["hrp"], 1, payload)
    return None
