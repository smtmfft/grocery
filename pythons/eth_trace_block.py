from web3 import Web3
from eth_utils import to_hex
from collections import defaultdict
import json
from hexbytes import HexBytes
from flask import current_app as app, jsonify
from itertools import islice
from blob_utils import get_tx_list_from_expected_blob


def chunk_list(lst, chunk_size):
    iterator = iter(lst)
    return iter(lambda: list(islice(iterator, chunk_size)), [])


class HexJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        return super().default(obj)


# preload some addresses, like coinbase, 0x00, etc
preload_addresses = set(
    [Web3.to_checksum_address("0x0000000000000000000000000000000000000000")]
)

block_blob_slot_hash_offset_dict = {
    800000: (
        10934114,
        "0x010b218ea00b124aca73e9b53cc81e8e56aa6e4a3415a50fc72e7f7f911f5b6d",
        (0, 79849),
    )
}


def init_preload_addresses(block_number: int):
    if block_number not in block_blob_slot_hash_offset_dict:
        raise ValueError(
            f"block_number {block_number} not in block_blob_slot_hash_offset_dict"
        )

    blob_info = block_blob_slot_hash_offset_dict[block_number]
    txs = get_tx_list_from_expected_blob(blob_info[0], blob_info[1])
    app.logger.info(f"Decoded {len(txs)} transactions")
    for tx in txs:

        preload_addresses.add(tx.data["from"])
        preload_addresses.add(tx.data["to"])


def get_block_data(w3: Web3, block_number: int):
    # init preload addresses
    init_preload_addresses(block_number)

    # block info
    block = w3.eth.get_block(block_number, full_transactions=True)

    # collect addresses & slots
    addresses = preload_addresses
    storage_slots = defaultdict(set)
    contracts = {}

    # trace block txs
    trace = w3.provider.make_request(
        "debug_traceBlockByNumber", [hex(block_number), {"tracer": "prestateTracer"}]
    )
    app.logger.debug(f"trace: {trace}")
    if "result" in trace:
        for tx_trace in trace["result"]:
            for addr, info in tx_trace["result"].items():
                checksum_addr = Web3.to_checksum_address(addr)
                app.logger.debug(f"add checksum_addr: {checksum_addr} of {addr}")
                addresses.add(checksum_addr)
                if "storage" in info:
                    storage_slots[checksum_addr].update(info["storage"].keys())
                # collect contracts
                if "code" in info and info["code"] != "0x":
                    code_hash = w3.keccak(hexstr=info["code"])
                    contracts["0x" + code_hash.hex()] = info["code"]

    app.logger.info(f"touched addresses: {addresses}")
    app.logger.info(f"storage slots: {storage_slots}")
    app.logger.info(f"contract keys: {contracts.keys()}")

    proof_requests = []
    for address in addresses:
        app.logger.debug(f"proof request for address: {address}")
        slots = list(storage_slots[address])
        # pre state proof
        proof_requests.append(("eth_getProof", [address, slots, hex(block_number - 1)]))
        # post state proof
        proof_requests.append(("eth_getProof", [address, slots, hex(block_number)]))

    app.logger.info(f"num of proof_requests: {len(proof_requests)}")
    # batch rpc all
    pre_proofs = []
    post_proofs = []
    batch_provider = w3.provider
    for chunk_proof_requests in chunk_list(proof_requests, 256):
        responses = batch_provider.make_batch_request(chunk_proof_requests)
        app.logger.debug(f"batch_provider eth_getProof responses: {responses}")
        # proofs
        for i, response in enumerate(responses):
            if i % 2 == 0:
                app.logger.debug(f"pre_proofs: {response}")
                pre_proofs.append(serialize_web3_data(response["result"]))
            else:
                app.logger.debug(f"post_proofs: {response}")
                post_proofs.append(serialize_web3_data(response["result"]))

    app.logger.info(f"num of pre_proofs: {len(pre_proofs)}")
    app.logger.info(f"num of post_proofs: {len(post_proofs)}")

    # ancestors
    ancestor_hashes = []
    current_number = block_number - 1
    proof_requests = []
    for _ in range(256):  # to support block.hash opcode
        if current_number < 0:
            break
        proof_requests.append(("eth_getBlockByNumber", [hex(current_number), False]))
        current_number -= 1

    responses = batch_provider.make_batch_request(proof_requests)
    app.logger.debug(f"batch_provider eth_getBlockByNumber responses: {responses}")
    for response in responses:
        ancestor_hashes.append(response["result"]["hash"])

    return {
        "block": block,
        "preAccountProofs": pre_proofs,
        "postAccountProofs": post_proofs,
        "contracts": contracts,
        "ancestorHashes": ancestor_hashes,
    }


class Web3Encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        # TODO: more types
        return json.JSONEncoder.default(self, obj)


def serialize_web3_data(obj):
    if isinstance(obj, dict):
        return {k: serialize_web3_data(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_web3_data(x) for x in obj]
    elif isinstance(obj, HexBytes):
        return "0x" + obj.hex()
    elif isinstance(obj, bytes):
        return to_hex(obj)
    elif hasattr(obj, "hex"):
        return "0x" + obj.hex()
    elif hasattr(obj, "__dict__"):
        return serialize_web3_data(obj.__dict__)
    return obj


# TODO: real lru
lru_cache = defaultdict(set)


def trace_block(block_number, rpc_url):
    app.json_encoder = Web3Encoder
    app.logger.info(f"Received request for block {block_number}")

    if block_number in lru_cache:
        return lru_cache[block_number]
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        result = get_block_data(w3, block_number)
        # app.logger.debug(f"----------------------------------------------------------")
        # app.logger.debug(f"result: {result}")
        # app.logger.debug(f"----------------------------------------------------------")
        # response = jsonify(result)
        serialized_data = serialize_web3_data(dict(result))
        # app.logger.debug(f"serialized_data: {serialized_data}")
        response = jsonify(serialized_data)
        # app.logger.debug(f"response: {response}")
        app.logger.info("Sending response")
        lru_cache[block_number] = response
        return response
    except Exception as e:
        app.logger.error(f"Error processing request: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        app.logger.info("Request completed")


if __name__ == "__main__":
    import os
    import sys

    rpc_url = os.getenv("TAIKO_DEBUG_RPC")
    block_number = sys.argv[1]
    trace_block(block_number, rpc_url)
