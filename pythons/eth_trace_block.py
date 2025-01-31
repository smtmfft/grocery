from flask import Flask, jsonify, request
from web3 import Web3
from eth_utils import to_hex
from collections import defaultdict
import json
from hexbytes import HexBytes
import logging
import os

app = Flask(__name__)

class HexJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        return super().default(obj)

def get_block_data(w3: Web3, block_number: int):
    # block info
    block = w3.eth.get_block(block_number, full_transactions=True)
    
    # collect addresses & slots
    addresses = set()
    storage_slots = defaultdict(set)
    contracts = {}

    # trace tx
    for tx in block.transactions:
        app.logger.debug(f"trace tx: {tx}")
        trace = w3.provider.make_request(
            "debug_traceTransaction",
            ["0x"+tx.hash.hex(), {"tracer": "prestateTracer"}]
        )

        app.logger.debug(f"trace: {trace}")
        
        if 'result' in trace:
            result = trace['result']
            addresses.update(result.keys())
            for addr, info in result.items():
                checksum_addr = Web3.to_checksum_address(addr)
                app.logger.debug(checksum_addr)
                if 'storage' in info:
                    storage_slots[checksum_addr].update(info['storage'].keys())
                if 'code' in info and info['code'] != '0x':
                    contracts['0x'+w3.keccak(hexstr=checksum_addr).hex()] = info['code']

    app.logger.debug(f"touched addresses: {addresses}")
    app.logger.debug(f"storage_slots: {storage_slots}")
    # proofs
    pre_proofs = []
    post_proofs = []
    for address in addresses:
        checksum_addr = Web3.to_checksum_address(address)        
        slots = list(storage_slots[checksum_addr])
        # get pre state (N-1 block) proofs
        pre_proof = w3.eth.get_proof(
            checksum_addr,
            slots,
            block_number - 1
        )
        pre_proofs.append(pre_proof)
        
        # post state (N block) proofs
        post_proof = w3.eth.get_proof(
            checksum_addr,
            slots,
            block_number
        )
        post_proofs.append(post_proof)

    # ancestors
    ancestor_hashes = []
    current_number = block_number - 1
    for _ in range(256):  # to support block.hash opcode
        if current_number < 0:
            break
        ancestor_block = w3.eth.get_block(current_number)
        ancestor_hashes.append(ancestor_block.hash)
        current_number -= 1

    app.logger.debug(f"list contracts keys: {contracts.keys()}")

    return {
        "block": block,
        "preAccountProofs": pre_proofs,
        "postAccountProofs": post_proofs,
        "contracts": contracts,
        "ancestorHashes": ancestor_hashes
    }

class Web3Encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        if isinstance(obj, bytes):
            return obj.hex()
        # TODO: more types
        return json.JSONEncoder.default(self, obj)

app.json_encoder = Web3Encoder

def serialize_web3_data(obj):
    if isinstance(obj, dict):
        return {k: serialize_web3_data(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_web3_data(x) for x in obj]
    elif isinstance(obj, HexBytes):
        return "0x"+obj.hex()
    elif isinstance(obj, bytes):
        return "0x"+eth_utils.to_hex(obj)
    elif hasattr(obj, 'hex'):
        return "0x"+obj.hex()
    elif hasattr(obj, '__dict__'):
        return serialize_web3_data(obj.__dict__)
    return obj


rpc_url = os.getenv("TAIKO_DEBUG_RPC")

#TODO: real lru
lru_cache = defaultdict(set)

@app.route('/trace/<int:block_number>')
def trace_block(block_number):
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

app.logger.setLevel(logging.DEBUG)
if __name__ == '__main__':
    app.logger.info("Starting server on port 8090")
    app.run(host='0.0.0.0', port=8090, debug=True)
