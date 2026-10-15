"""Tests beyond the reference specification.

The Part B transaction below is the one I built, signed and broadcast on my
regtest node. The expected identifiers and sizes are copied from the node's
own `decoderawtransaction` output, so these tests show requirements 2 and 4
hold against Bitcoin Core, not just against hand-built fixtures.
"""

from __future__ import annotations

import pytest

from txparser import parse_hex, read_compact_size, write_compact_size
from txparser.cli import main
from txparser.ripemd160 import ripemd160
from txparser.script import address_for, classify, disassemble

# --------------------------------------------------------------------------- #
# My Part B transaction (1 P2WPKH input -> 10 BTC + 39.9999 BTC change)
# --------------------------------------------------------------------------- #

PART_B_HEX = (
    "02000000000101a30405b4c33f19ec5cb6e5a643c07430f5f3dbe598bdfa001edcdf5edd"
    "fd1f630000000000fdffffff0200ca9a3b00000000160014f1218f5ab4a36cd5a7bcbc67e1"
    "71226e9e87873ef0006bee000000001600142ed32412670f0958f2609b751c239be62e0e"
    "6b400247304402203f7f5e9f218e0a8547601549bf2edde33c62dc2616035b0606d0879"
    "972d6f0f602201555e7fa4b6b1d6bf574858d27913d99b8ebc495212a27662b42713c26"
    "0ec476012102487e35633283a3c7a8691f9adb34b375e1a2438021be4b3c7fab00af59d"
    "cb4bf00000000"
)

# Values reported by my node (decoderawtransaction / sendrawtransaction).
NODE_TXID = "371897969187b3a6bc537b818bf5a2e6a7e2bfac013867ea7e1c67009aab488d"
NODE_HASH = "e04ef7049d6845abf6ba1d3a069e59df1eda71117e3e20af0b92ddb623fef4ec"
SPENT_TXID = "631ffddd5edfdc1e00fabd98e5dbf3f53074c043a6e5b65cec193fc3b40504a3"
DEST_ADDR = "bcrt1q7ysc7k455dkdtfauh3n7zufzd60g0pe7qnmlcr"
CHANGE_ADDR = "bcrt1q9mfjgyn8puy43unqnd63cgumuchqu66qtc6g4k"


@pytest.fixture(scope="module")
def part_b():
    return parse_hex(PART_B_HEX)


def test_part_b_ids_match_node(part_b) -> None:
    assert part_b.txid == NODE_TXID
    assert part_b.wtxid == NODE_HASH
    assert part_b.txid != part_b.wtxid


def test_part_b_sizes_match_node(part_b) -> None:
    assert (part_b.size, part_b.stripped_size) == (222, 113)
    assert part_b.weight == 561 == 3 * part_b.stripped_size + part_b.size
    assert part_b.vsize == 141


def test_part_b_structure(part_b) -> None:
    assert part_b.version == 2 and part_b.locktime == 0 and part_b.is_segwit
    assert part_b.field_offsets["marker"] == 4 and part_b.field_offsets["flag"] == 5

    txin = part_b.inputs[0]
    assert txin.offset == 7
    assert txin.prev_txid.hex() == SPENT_TXID  # display order, as I passed it in
    assert txin.prev_vout == 0
    assert txin.script_sig == b""
    assert txin.sequence == 0xFFFFFFFD

    sig, pubkey = txin.witness
    assert len(sig) == 71 and sig[0] == 0x30 and sig[-1] == 0x01  # DER + SIGHASH_ALL
    assert len(pubkey) == 33 and pubkey[0] in (2, 3)


def test_part_b_outputs(part_b) -> None:
    dest, change = part_b.outputs
    assert (dest.offset, change.offset) == (49, 80)
    assert dest.value_btc == "10.00000000"
    assert change.value_btc == "39.99990000"
    # 50 BTC in, 49.9999 BTC out: the 0.0001 BTC fee is the remainder.
    assert 50 * 100_000_000 - part_b.total_output_sat == 10_000

    for out, addr in ((dest, DEST_ADDR), (change, CHANGE_ADDR)):
        stype, payload = classify(out.script_pubkey)
        assert stype == "p2wpkh"
        assert address_for(stype, payload, "regtest") == addr


def test_part_b_roundtrip(part_b) -> None:
    assert part_b.serialise(include_witness=True).hex() == PART_B_HEX


# --------------------------------------------------------------------------- #
# CompactSize edge cases
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (252, "fc"),
        (253, "fdfd00"),
        (65535, "fdffff"),
        (65536, "fe00000100"),
        (2**32 - 1, "feffffffff"),
        (2**32, "ff0000000001000000"),
    ],
)
def test_compact_size_exact_bytes(value: int, encoded: str) -> None:
    assert write_compact_size(value).hex() == encoded


@pytest.mark.parametrize("buf", ["fd01", "fe010203", "ff01020304050607", ""])
def test_compact_size_truncated(buf: str) -> None:
    with pytest.raises(ValueError, match="truncated"):
        read_compact_size(bytes.fromhex(buf), 0)


def test_truncated_witness_is_rejected() -> None:
    with pytest.raises(ValueError, match="truncated"):
        parse_hex(PART_B_HEX[:-60])


# --------------------------------------------------------------------------- #
# RIPEMD-160 fallback (forced, regardless of what hashlib supports)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("message", "digest"),
    [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        (b"a" * 1_000, "aa69deee9a8922e92f8105e007f76110f381e9cf"),
    ],
)
def test_ripemd160_vectors(message: bytes, digest: str) -> None:
    assert ripemd160(message).hex() == digest


# --------------------------------------------------------------------------- #
# Script
# --------------------------------------------------------------------------- #


def test_pushdata1_disassembly() -> None:
    script = bytes.fromhex("6a4c50" + "ab" * 80)
    assert disassemble(script) == ["OP_RETURN", "OP_PUSHDATA1 <" + "ab" * 80 + ">"]


def test_bare_multisig() -> None:
    key = "21" + "02" + "11" * 32
    spk = bytes.fromhex("51" + key + key + "52ae")
    assert classify(spk) == ("multisig", None)
    assert disassemble(spk)[0] == "OP_1" and disassemble(spk)[-1] == "OP_CHECKMULTISIG"


def test_mainnet_p2sh_starts_with_3() -> None:
    stype, payload = classify(bytes.fromhex("a914" + "22" * 20 + "87"))
    assert address_for(stype, payload, "mainnet").startswith("3")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_text(capsys) -> None:
    assert main([PART_B_HEX]) == 0
    out = capsys.readouterr().out
    assert NODE_TXID in out and NODE_HASH in out and DEST_ADDR in out


def test_cli_rejects_garbage(capsys) -> None:
    assert main(["zz"]) == 1
    assert "hexadecimal" in capsys.readouterr().err
