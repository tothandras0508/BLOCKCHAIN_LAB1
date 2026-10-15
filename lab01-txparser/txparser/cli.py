"""Command line: print a transaction field by field with byte offsets."""

from __future__ import annotations

import argparse
import json
import sys

from .parser import Transaction, parse_hex
from .script import address_for, classify, disassemble

LINE = "=" * 78


def _sequence_note(seq: int) -> str:
    if seq == 0xFFFFFFFF:
        return "final (no RBF, nLockTime ignored)"
    if seq == 0xFFFFFFFE:
        return "nLockTime enforced, no RBF"
    if seq < 0xFFFFFFFE:
        return "RBF signalled (BIP-125)"
    return ""


def _locktime_note(lt: int) -> str:
    if lt == 0:
        return "no lock"
    return "block height" if lt < 500_000_000 else "unix time"


def _at(offset: int) -> str:
    return f"@{offset:>4}"


def to_text(tx: Transaction, network: str) -> str:
    o = tx.field_offsets
    lines: list[str] = [LINE, "TRANSACTION", LINE]
    add = lines.append

    add(f"txid           {tx.txid}")
    add(f"wtxid          {tx.wtxid}")
    add(f"size           {tx.size} B")
    add(f"stripped size  {tx.stripped_size} B")
    add(f"weight         {tx.weight} WU  (= 3 x {tx.stripped_size} + {tx.size})")
    add(f"vsize          {tx.vsize} vB")
    add("")
    add(f"{_at(o['version'])}  version        {tx.version}")
    if tx.is_segwit:
        add(f"{_at(o['marker'])}  marker         0x00")
        add(f"{_at(o['flag'])}  flag           0x01   -> SegWit serialisation")
    else:
        add("       (no marker/flag -> legacy serialisation)")
    add(f"{_at(o['input_count'])}  input count    {len(tx.inputs)}")

    for n, i in enumerate(tx.inputs):
        f = i.field_offsets
        add("")
        add(f"INPUT {n}" + ("  [coinbase]" if i.is_coinbase else ""))
        add(f"{_at(f['prev_txid'])}  prev txid      {i.prev_txid.hex()}")
        add(f"{_at(f['prev_vout'])}  prev vout      {i.prev_vout}")
        add(f"{_at(f['script_sig'])}  scriptSig      {len(i.script_sig)} B")
        if i.script_sig:
            if i.is_coinbase:
                add(f"                 {i.script_sig.hex()}")
            else:
                for tok in disassemble(i.script_sig):
                    add(f"                 {tok}")
        note = _sequence_note(i.sequence)
        add(f"{_at(f['sequence'])}  sequence       0x{i.sequence:08x}  {note}")

    add("")
    add(f"{_at(o['output_count'])}  output count   {len(tx.outputs)}")
    for n, out in enumerate(tx.outputs):
        f = out.field_offsets
        stype, payload = classify(out.script_pubkey)
        addr = address_for(stype, payload, network)
        add("")
        add(f"OUTPUT {n}")
        add(f"{_at(f['value'])}  value          {out.value_btc} BTC ({out.value_sat} sat)")
        add(f"{_at(f['script_pubkey'])}  scriptPubKey   {len(out.script_pubkey)} B, type {stype}")
        for tok in disassemble(out.script_pubkey):
            add(f"                 {tok}")
        if addr:
            add(f"                 address {addr} [{network}]")

    if tx.is_segwit:
        add("")
        add(f"{_at(o['witness'])}  WITNESS")
        for n, i in enumerate(tx.inputs):
            add(f"{_at(i.field_offsets['witness'])}  input {n}: {len(i.witness)} item(s)")
            for k, item in enumerate(i.witness):
                add(f"                 [{k}] {len(item)} B  {item.hex()}")

    add("")
    add(f"{_at(o['locktime'])}  locktime       {tx.locktime}  ({_locktime_note(tx.locktime)})")
    add("")
    add(LINE)
    add(f"sum of outputs {tx.total_output_sat} sat")
    add("fee            not in the transaction: fee = sum(inputs) - sum(outputs),")
    add("               and input values live in the spent outputs (gettxout).")
    add(LINE)
    return "\n".join(lines)


def to_json(tx: Transaction, network: str) -> str:
    def output(out):
        stype, payload = classify(out.script_pubkey)
        return {
            "offset": out.offset,
            "value_sat": out.value_sat,
            "value_btc": out.value_btc,
            "type": stype,
            "address": address_for(stype, payload, network),
            "script_pubkey": out.script_pubkey.hex(),
            "asm": disassemble(out.script_pubkey),
        }

    return json.dumps(
        {
            "txid": tx.txid,
            "wtxid": tx.wtxid,
            "version": tx.version,
            "segwit": tx.is_segwit,
            "size": tx.size,
            "stripped_size": tx.stripped_size,
            "weight": tx.weight,
            "vsize": tx.vsize,
            "locktime": tx.locktime,
            "offsets": tx.field_offsets,
            "inputs": [
                {
                    "offset": i.offset,
                    "prev_txid": i.prev_txid.hex(),
                    "prev_vout": i.prev_vout,
                    "script_sig": i.script_sig.hex(),
                    "sequence": i.sequence,
                    "witness": [w.hex() for w in i.witness],
                    "coinbase": i.is_coinbase,
                }
                for i in tx.inputs
            ],
            "outputs": [output(o) for o in tx.outputs],
        },
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="txparser", description="Parse a raw Bitcoin transaction byte by byte."
    )
    ap.add_argument("hex", nargs="?", help="raw transaction hex (default: read stdin)")
    ap.add_argument(
        "-n",
        "--network",
        choices=["mainnet", "testnet", "regtest"],
        default="regtest",
        help="address encoding (default: regtest)",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    text = args.hex if args.hex is not None else sys.stdin.read()
    if not text.strip():
        ap.error("no input: pass the hex as an argument or pipe it on stdin")

    try:
        tx = parse_hex(text)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(to_json(tx, args.network) if args.json else to_text(tx, args.network))
    return 0
