# txparser — Lab 01 student implementation

A byte-level parser for raw Bitcoin transactions, written against the
serialisation format directly with nothing but the Python standard library.

## Usage

```bash
uv sync
uv run python -m txparser <RAW_TX_HEX>
uv run python -m txparser <RAW_TX_HEX> --json        # machine-readable
uv run python -m txparser <RAW_TX_HEX> -n mainnet    # mainnet addresses
```

Or pipe from the node:

```bash
docker compose exec -T bitcoind bitcoin-cli getrawtransaction <TXID> false <BLOCKHASH> \
  | uv run python -m txparser
```

Every field is printed with the byte offset where it starts (`@ 7  prev txid …`),
including marker, flag, the witness section and locktime.

## Tests

```bash
uv run pytest -v
```

61 tests in two files:

| File | What it covers |
|---|---|
| `tests/test_parser.py` | The course's reference specification, **unchanged** (36 tests). |
| `tests/test_lab_extra.py` | My Part B transaction checked against my node's values; exact CompactSize encodings and truncation; RIPEMD-160 test vectors on the pure-Python fallback; PUSHDATA, multisig and mainnet P2SH; the CLI. |

## Requirements → evidence

| # | Requirement | Where it is shown |
|---|---|---|
| 1 | Legacy parsing with byte offsets | `test_genesis_coinbase_fields`, `test_first_payment_fields`, `test_prev_txid_is_in_display_byte_order`, `test_legacy_field_offsets` (input @5, output @119), `test_reserialisation_is_byte_identical` |
| 2 | SegWit: marker, flag, witness stacks | `test_segwit_*`; on my real transaction `test_part_b_structure` (marker @4, flag @5, input @7, 2 witness items: 71-byte DER signature + 33-byte pubkey) and `test_part_b_sizes_match_node` (weight 561 = 3 × 113 + 222) |
| 3 | CompactSize, all four classes | `test_compact_size_roundtrip`, `test_compact_size_offset_is_respected`, `test_compact_size_exact_bytes`, `test_compact_size_truncated` |
| 4 | txid recomputed and verified against the node | `test_genesis_txid_is_recomputed_correctly`, `test_legacy_txid_equals_wtxid`; `test_part_b_ids_match_node` (txid `371897…488d` = `sendrawtransaction`, wtxid `e04ef7…f4ec` = `decoderawtransaction` `hash`) |
| 5 | Disassembly and classification | `test_disassembly_of_p2pkh`; p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr and nulldata tests; `test_part_b_outputs` (both outputs decode to my destination and change addresses) |
| — | Robustness | `test_truncated_input_is_rejected`, `test_trailing_bytes_are_rejected`, `test_non_hex_input_is_rejected`, `test_truncated_witness_is_rejected` |

## Layout

| File | Responsibility |
|---|---|
| `txparser/parser.py` | CompactSize, `ByteStream` cursor, data model, txid / wtxid / weight |
| `txparser/script.py` | opcode names, disassembly, output templates, Base58Check, Bech32/Bech32m |
| `txparser/ripemd160.py` | pure-Python RIPEMD-160, used when OpenSSL 3 has it disabled |
| `txparser/cli.py` | text and JSON reports |

Byte order: hashes are read little-endian off the wire and stored reversed
(display order) in `ByteStream.hash_display`; `TxInput.serialise` reverses them
back. The txid is `sha256d` of the serialisation **without** marker, flag and
witness, also shown reversed.
