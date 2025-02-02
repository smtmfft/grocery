import rlp
from eth_utils import to_hex
from typing import List, Dict, Any
from dataclasses import dataclass
from flask import current_app

@dataclass
class DecodedTx:
    tx_type: int
    data: Dict[str, Any]

def decode_legacy_tx(tx_data: List) -> Dict[str, Any]:
    """解码 Legacy 交易"""
    return {
        'nonce': to_hex(tx_data[0]),
        'gas_price': to_hex(tx_data[1]),
        'gas': to_hex(tx_data[2]),
        'to': to_hex(tx_data[3]) if tx_data[3] else None,
        'value': to_hex(tx_data[4]),
        'data': to_hex(tx_data[5]),
        'v': to_hex(tx_data[6]),
        'r': to_hex(tx_data[7]),
        's': to_hex(tx_data[8])
    }

def decode_access_list_tx(tx_data: List) -> Dict[str, Any]:
    """解码 EIP-2930 (Type 1) 交易"""
    return {
        'chain_id': to_hex(tx_data[0]),
        'nonce': to_hex(tx_data[1]),
        'gas_price': to_hex(tx_data[2]),
        'gas': to_hex(tx_data[3]),
        'to': to_hex(tx_data[4]) if tx_data[4] else None,
        'value': to_hex(tx_data[5]),
        'data': to_hex(tx_data[6]),
        'access_list': tx_data[7],
        'v': to_hex(tx_data[8]),
        'r': to_hex(tx_data[9]),
        's': to_hex(tx_data[10])
    }

def decode_eip1559_tx(tx_data: List) -> Dict[str, Any]:
    """解码 EIP-1559 (Type 2) 交易"""
    return {
        'chain_id': to_hex(tx_data[0]),
        'nonce': to_hex(tx_data[1]),
        'max_priority_fee_per_gas': to_hex(tx_data[2]),
        'max_fee_per_gas': to_hex(tx_data[3]),
        'gas': to_hex(tx_data[4]),
        'to': to_hex(tx_data[5]) if tx_data[5] else None,
        'value': to_hex(tx_data[6]),
        'data': to_hex(tx_data[7]),
        'access_list': tx_data[8],
        'v': to_hex(tx_data[9]),
        'r': to_hex(tx_data[10]),
        's': to_hex(tx_data[11])
    }

def decode_blob_tx(tx_data: List) -> Dict[str, Any]:
    """解码 EIP-4844 (Type 3) blob 交易"""
    return {
        'chain_id': to_hex(tx_data[0]),
        'nonce': to_hex(tx_data[1]),
        'max_priority_fee_per_gas': to_hex(tx_data[2]),
        'max_fee_per_gas': to_hex(tx_data[3]),
        'gas': to_hex(tx_data[4]),
        'to': to_hex(tx_data[5]) if tx_data[5] else None,
        'value': to_hex(tx_data[6]),
        'data': to_hex(tx_data[7]),
        'access_list': tx_data[8],
        'max_fee_per_blob_gas': to_hex(tx_data[9]),
        'blob_versioned_hashes': [to_hex(h) for h in tx_data[10]],
        'v': to_hex(tx_data[11]),
        'r': to_hex(tx_data[12]),
        's': to_hex(tx_data[13])
    }

def decode_tx_list(rlp_bytes: bytes) -> List[DecodedTx]:
    """
    解码 RLP 编码的交易列表
    """
    try:
        # 先解码整个列表
        tx_list = rlp.decode(rlp_bytes)
        decoded_txs = []

        for tx_data in tx_list:
            # 检查是否是列表（普通RLP）还是字节（带类型前缀）
            if isinstance(tx_data, bytes) and tx_data:
                # 获取交易类型
                tx_type = tx_data[0]
                # 解码实际交易数据
                tx_payload = rlp.decode(tx_data[1:])
                
                if tx_type == 0x01:  # EIP-2930
                    decoded_tx = decode_access_list_tx(tx_payload)
                    decoded_txs.append(DecodedTx(1, decoded_tx))
                elif tx_type == 0x02:  # EIP-1559
                    decoded_tx = decode_eip1559_tx(tx_payload)
                    decoded_txs.append(DecodedTx(2, decoded_tx))
                elif tx_type == 0x03:  # EIP-4844
                    decoded_tx = decode_blob_tx(tx_payload)
                    decoded_txs.append(DecodedTx(3, decoded_tx))
                else:
                    current_app.logger.warning(f"Unknown transaction type: {tx_type}")
            else:
                # Legacy 交易
                decoded_tx = decode_legacy_tx(tx_data)
                decoded_txs.append(DecodedTx(0, decoded_tx))

        return decoded_txs

    except Exception as e:
        current_app.logger.error(f"Error decoding transaction list: {str(e)}")
        raise

