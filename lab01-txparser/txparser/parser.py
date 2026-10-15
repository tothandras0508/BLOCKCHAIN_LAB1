"""Raw Bitcoin transaction parser.

Reads a serialised transaction byte by byte using only the standard library.
Every field is recorded together with the offset where it starts, so the
report can point at the exact bytes.

Wire format (BIP-144 for the SegWit parts):

    nVersion        int32  LE
    marker, flag    0x00 0x01            (SegWit only)
    vin             CompactSize count, then inputs
    vout            CompactSize count, then outputs
    witness         one stack per input  (SegWit only)
    nLockTime       uint32 LE

    input   = prevout hash (32, LE) | prevout index (uint32 LE)
              | scriptSig (CompactSize + bytes) | nSequence (uint32 LE)
    output  = nValue (int64 LE, satoshi) | scriptPubKey (CompactSize + bytes)
    witness = CompactSize item count, then each item as CompactSize + bytes
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .ripemd160 import ripemd160

SATS_PER_BTC = 100_000_000
NULL_HASH = bytes(32)
NULL_INDEX = 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# Hashes
# --------------------------------------------------------------------------- #


def sha256d(data: bytes) -> bytes:
    """SHA-256 applied twice: Bitcoin's hash for txids and checksums."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD-160 of SHA-256; the hash behind P2PKH and P2WPKH addresses.

    hashlib's RIPEMD-160 is missing on OpenSSL 3 builds without the legacy
    provider, so a pure-Python version is used when it is not available.
    """
    inner = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", inner).digest()
    except (ValueError, TypeError):
        return ripemd160(inner)


# --------------------------------------------------------------------------- #
# CompactSize
# --------------------------------------------------------------------------- #

# prefix byte -> number of following little-endian bytes
_COMPACT_WIDTH = {0xFD: 2, 0xFE: 4, 0xFF: 8}


def read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a CompactSize at ``offset``. Returns (value, bytes consumed).

    0x00-0xfc : the byte is the value          (1 byte total)
    0xfd      : value in the next 2 bytes      (3 bytes total)
    0xfe      : value in the next 4 bytes      (5 bytes total)
    0xff      : value in the next 8 bytes      (9 bytes total)
    """
    if offset >= len(data):
        raise ValueError(f"truncated: CompactSize expected at offset {offset}")
    prefix = data[offset]
    width = _COMPACT_WIDTH.get(prefix)
    if width is None:
        return prefix, 1
    end = offset + 1 + width
    if end > len(data):
        raise ValueError(f"truncated: CompactSize at offset {offset} needs {width + 1} bytes")
    return int.from_bytes(data[offset + 1 : end], "little"), width + 1


def write_compact_size(value: int) -> bytes:
    """Encode ``value`` in the shortest CompactSize form."""
    if value < 0:
        raise ValueError("CompactSize cannot encode a negative number")
    if value <= 0xFC:
        return value.to_bytes(1, "little")
    for prefix, width in _COMPACT_WIDTH.items():
        if value < 1 << (8 * width):
            return bytes([prefix]) + value.to_bytes(width, "little")
    raise ValueError("CompactSize cannot encode values of 2**64 or more")


def _var_bytes(payload: bytes) -> bytes:
    return write_compact_size(len(payload)) + payload


# --------------------------------------------------------------------------- #
# Byte stream
# --------------------------------------------------------------------------- #


class ByteStream:
    """Sequential reader that refuses to run past the end of the buffer."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def left(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        if n > self.left:
            raise ValueError(f"truncated: needed {n} bytes at offset {self.pos}, {self.left} left")
        start = self.pos
        self.pos += n
        return self.data[start : self.pos]

    def uint(self, width: int) -> int:
        return int.from_bytes(self.read(width), "little")

    def compact(self) -> int:
        value, used = read_compact_size(self.data, self.pos)
        self.pos += used
        return value

    def blob(self) -> bytes:
        """A CompactSize length followed by that many bytes."""
        return self.read(self.compact())

    def hash_display(self) -> bytes:
        """Read a 32-byte hash and return it in display (big-endian) order.

        On the wire, hashes are little-endian; explorers and RPC print them
        reversed. Reversing here keeps every hash in the data model in the
        same order a human compares against.
        """
        return self.read(32)[::-1]


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class TxInput:
    offset: int
    prev_txid: bytes  # display order (big-endian)
    prev_vout: int
    script_sig: bytes
    sequence: int
    witness: list[bytes] = field(default_factory=list)
    field_offsets: dict[str, int] = field(default_factory=dict)

    @property
    def is_coinbase(self) -> bool:
        return self.prev_txid == NULL_HASH and self.prev_vout == NULL_INDEX

    def serialise(self) -> bytes:
        return b"".join(
            (
                self.prev_txid[::-1],
                self.prev_vout.to_bytes(4, "little"),
                _var_bytes(self.script_sig),
                self.sequence.to_bytes(4, "little"),
            )
        )

    def serialise_witness(self) -> bytes:
        return write_compact_size(len(self.witness)) + b"".join(
            _var_bytes(item) for item in self.witness
        )


@dataclass
class TxOutput:
    offset: int
    value_sat: int
    script_pubkey: bytes
    field_offsets: dict[str, int] = field(default_factory=dict)

    @property
    def value_btc(self) -> str:
        """Exact decimal string; floats cannot hold every satoshi amount."""
        btc, sats = divmod(self.value_sat, SATS_PER_BTC)
        return f"{btc}.{sats:08d}"

    def serialise(self) -> bytes:
        return self.value_sat.to_bytes(8, "little") + _var_bytes(self.script_pubkey)


@dataclass
class Transaction:
    version: int
    is_segwit: bool
    inputs: list[TxInput]
    outputs: list[TxOutput]
    locktime: int
    raw: bytes
    field_offsets: dict[str, int] = field(default_factory=dict)

    def serialise(self, include_witness: bool = True) -> bytes:
        """Rebuild the bytes from the parsed fields.

        With ``include_witness=False`` this is the legacy serialisation the
        txid is computed over: no marker, no flag, no witness section.
        """
        witness = include_witness and self.is_segwit
        parts = [self.version.to_bytes(4, "little")]
        if witness:
            parts.append(b"\x00\x01")
        parts.append(write_compact_size(len(self.inputs)))
        parts.extend(i.serialise() for i in self.inputs)
        parts.append(write_compact_size(len(self.outputs)))
        parts.extend(o.serialise() for o in self.outputs)
        if witness:
            parts.extend(i.serialise_witness() for i in self.inputs)
        parts.append(self.locktime.to_bytes(4, "little"))
        return b"".join(parts)

    @property
    def txid(self) -> str:
        """sha256d of the legacy serialisation, shown byte-reversed.

        Leaving the witness out is what makes the txid immune to signature
        malleability.
        """
        return sha256d(self.serialise(include_witness=False))[::-1].hex()

    @property
    def wtxid(self) -> str:
        """sha256d of the full serialisation; equals txid for legacy txs."""
        return sha256d(self.serialise(include_witness=True))[::-1].hex()

    @property
    def size(self) -> int:
        return len(self.raw)

    @property
    def stripped_size(self) -> int:
        return len(self.serialise(include_witness=False))

    @property
    def weight(self) -> int:
        """BIP-141: base bytes count 4 times, witness bytes once."""
        return 3 * self.stripped_size + self.size

    @property
    def vsize(self) -> int:
        return -(-self.weight // 4)  # ceiling division

    @property
    def total_output_sat(self) -> int:
        return sum(o.value_sat for o in self.outputs)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _parse_input(s: ByteStream) -> TxInput:
    offs = {"start": s.pos}
    offs["prev_txid"] = s.pos
    prev_txid = s.hash_display()
    offs["prev_vout"] = s.pos
    prev_vout = s.uint(4)
    offs["script_sig"] = s.pos
    script_sig = s.blob()
    offs["sequence"] = s.pos
    sequence = s.uint(4)
    return TxInput(
        offset=offs["start"],
        prev_txid=prev_txid,
        prev_vout=prev_vout,
        script_sig=script_sig,
        sequence=sequence,
        field_offsets=offs,
    )


def _parse_output(s: ByteStream) -> TxOutput:
    offs = {"start": s.pos, "value": s.pos}
    value = s.uint(8)
    offs["script_pubkey"] = s.pos
    script = s.blob()
    return TxOutput(offset=offs["start"], value_sat=value, script_pubkey=script, field_offsets=offs)


def parse_transaction(raw: bytes) -> Transaction:
    """Parse raw transaction bytes. Raises ValueError on malformed input."""
    s = ByteStream(raw)
    offs: dict[str, int] = {"version": 0}
    version = s.uint(4)

    # A legacy transaction cannot have zero inputs, so 0x00 right after the
    # version can only be the SegWit marker (BIP-144).
    is_segwit = s.data[s.pos : s.pos + 2] == b"\x00\x01"
    if is_segwit:
        offs["marker"] = s.pos
        offs["flag"] = s.pos + 1
        s.read(2)

    offs["input_count"] = s.pos
    inputs = [_parse_input(s) for _ in range(s.compact())]

    offs["output_count"] = s.pos
    outputs = [_parse_output(s) for _ in range(s.compact())]

    if is_segwit:
        offs["witness"] = s.pos
        for txin in inputs:
            txin.field_offsets["witness"] = s.pos
            txin.witness = [s.blob() for _ in range(s.compact())]

    offs["locktime"] = s.pos
    locktime = s.uint(4)

    if s.left:
        raise ValueError(f"{s.left} trailing bytes after locktime at offset {s.pos}")

    return Transaction(
        version=version,
        is_segwit=is_segwit,
        inputs=inputs,
        outputs=outputs,
        locktime=locktime,
        raw=raw,
        field_offsets=offs,
    )


def parse_hex(text: str) -> Transaction:
    """Parse a hex string; whitespace and a leading 0x are ignored."""
    cleaned = "".join(text.split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"input is not valid hexadecimal ({exc})") from None
    if not raw:
        raise ValueError("empty input")
    return parse_transaction(raw)
