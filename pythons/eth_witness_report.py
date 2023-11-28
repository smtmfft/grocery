from web3 import Web3
from web3.middleware import geth_poa_middleware
from random import randint
from time import sleep, time
import json
l1_url = "https://your-l1-node-url"
node_url = "https://your-l2-node-url"

# Connect to an l1 Ethereum node
l1_w3 = Web3(Web3.HTTPProvider(l1_url, {'timeout':60}))
l1_w3.middleware_onion.inject(geth_poa_middleware, layer=0)

# Connect to an l2 Ethereum node
w3 = Web3(Web3.HTTPProvider(node_url, {'timeout':60}))  # Replace with your node's URL
# Check connection status
if l1_w3.isConnected():
    print(f"Connected to l1 node {l1_url}")
if w3.isConnected():
    print(f"Connected to l2 node {node_url}")

# Get the latest block number
# block_number = 12345  # Replace with the desired block number
block_height = int(w3.eth.blockNumber)
print("Latest block number:", block_height)
def dump_block_trace(block_num: int):
    method = "debug_traceBlockByNumber"
    params = [hex(block_num), {}]
    response = w3.provider.make_request(method, params)
    fp = open(f"block_trace_{block_num}.json", "w")
    for result_i in response['result']:
        fp.writelines(json.dumps(line)+"\n" for line in result_i['result']['structLogs'])
    fp.close()
    
#dump_block_trace(401506)
def dump_block_trace_no_stack(block_num: int):
    method = "debug_traceBlockByNumber"
    params = [hex(block_num), {"DisableStack": True}]
    response = w3.provider.make_request(method, params)
    fp = open(f"block_trace_{block_num}_no_stack.json", "w")
    for result_i in response['result']:
        fp.writelines(json.dumps(line)+"\n" for line in result_i['result']['structLogs'])
    fp.close()

def dump_block_trace_with_params(block_num: int, logger_conf: dict):
    method = "debug_traceBlockByNumber"
    params = [hex(block_num), logger_conf]
    response = w3.provider.make_request(method, params)
    fp = open(f"block_trace_{block_num}_no_conf.json", "w")
    for result_i in response['result']:
        fp.writelines(json.dumps(line)+"\n" for line in result_i['result']['structLogs'])
    fp.close()

def tx_gas_used(tx_trace: list):
    sum = 0
    for i, trace_i in enumerate(tx_trace):
        op_gas = tx_trace[i]['gasCost']
        if trace_i['op'].endswith('CALL'):
           op_gas = tx_trace[i-1]['gas'] - tx_trace[i+1]['gas']
        #    print(f"{i}-th {tx_trace[i]['op']} CALL gas: {op_gas}")
        if 'error' in trace_i.keys():
           op_gas = tx_trace[i-1]['gas'] - tx_trace[i+1]['gas']
        sum += op_gas
    return sum        

def parse_anchor(block_num):
    block = w3.eth.get_block(block_num)
    txs = block['transactions']
    tx = w3.eth.get_transaction(txs[0])
    call_data_str = tx['input']
    call_data_hex = bytes.fromhex(call_data_str.lstrip('0x'))
    call_sig = call_data_hex[:4]
    assert(call_sig.hex() == 'da69d3db')
    l1_hash = call_data_hex[4:4+32].hex()
    l1_sig_root = call_data_hex[36:36+32].hex()
    l1_height = int.from_bytes(call_data_hex[68:68+32], 'big')
    prtGasUsed = int.from_bytes(call_data_hex[100:100+32], 'big')
    print(f"l1_hash: {l1_hash}, l1_sig_root: {l1_sig_root}, l1_height: {l1_height}, prtGasUsed: {prtGasUsed}")


def filter_block_gt_gasUsed(cmp_fn, start, end):
    for i in range(start, end):
        block_i = w3.eth.get_block(i)
        if cmp_fn(block_i['gasUsed']):
            print(f"block {i}: gasUsed: {block_i['gasUsed']}")


#l1 parse
from eth_abi import decode_single, decode_abi

def parse_abi_function(abi, data):
    item = abi
    encoded_signature = item['name'] + '(' + ','.join(i['type'] for i in item['inputs']) + ')'
    # print(encoded_signature)
    selector = bytes.hex(w3.keccak(bytes(encoded_signature, 'utf')))[:8]
    # print(selector[:8], data)
    if selector in data[2:10]:
        decoded_data = decode_abi([i['type'] for i in item['inputs']], bytes.fromhex(data[10:]))
        txlist_bytes = decoded_data[1]
        txlist_hash = w3.keccak(txlist_bytes)
        return {
            'name': item['name'],
            'inputs': [(info, d.hex()) for (info, d) in list(zip(item['inputs'], decoded_data))],
            'txlist_hash': txlist_hash,
        }
    return {}

# proposeBlock ABI
proposeBlock_abi = {
    "constant": False,
    "inputs": [
        { "name": "input", "type": "bytes" },
        { "name": "txList", "type": "bytes" }
    ],
    "name": "proposeBlock",
    "outputs": [],
    "payable": False,
    "stateMutability": "nonpayable",
    "type": "function"
}


def init_w3(rpc):
    w3 = Web3(Web3.HTTPProvider(rpc, {'timeout':60}))  # Replace with your node's URL
    if w3.isConnected():
        print(f"Connected to node {node_url}")
        return w3
    raise Exception(f"Invalid rpc: {rpc}")

def parse_l1_propose_block(block_num):
    block = l1_w3.eth.getBlock(block_num)
    txs = block['transactions']
    results = []
    for tx_hash in txs:
        tx = l1_w3.eth.getTransaction(tx_hash)
        input = tx['input']
        propose_call = parse_abi_function(proposeBlock_abi, input)
        if propose_call:
            propose_call['l2_height'] = get_l2_height(block_num, tx_hash)
            results.append(propose_call)
    print(results)

def get_l2_height(block_number, tx_hash):
    receipt = l1_w3.eth.get_transaction_receipt(tx_hash)
    # TODO: parse index instead hardcode
    l2_height = int.from_bytes(receipt['logs'][1]['topics'][1], 'big')
    return l2_height
#    events = w3.eth.get_logs({
#        'address': receipt['contractAddress'],
#        'fromBlock': block_number,
#        'toBlock': block_number,
#        'topics': receipt['logs'][1]['topics']
#    })
#    print(events)
