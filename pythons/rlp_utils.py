from eth_account import Account
import rlp
from eth_utils import to_hex
from typing import List, Dict, Any
from dataclasses import dataclass
from flask import current_app
from web3 import Web3


@dataclass
class DecodedTx:
    tx_type: int
    data: Dict[str, Any]


def decode_legacy_tx(tx_data: List) -> Dict[str, Any]:
    """解码 Legacy 交易"""
    return {
        "nonce": to_hex(tx_data[0]),
        "gas_price": to_hex(tx_data[1]),
        "gas": to_hex(tx_data[2]),
        "to": to_hex(tx_data[3]) if tx_data[3] else None,
        "value": "0x00" if not tx_data[4] else to_hex(tx_data[4]),
        "data": to_hex(tx_data[5]),
        "v": to_hex(tx_data[6]),
        "r": to_hex(tx_data[7]),
        "s": to_hex(tx_data[8]),
    }


def decode_access_list_tx(tx_data: List) -> Dict[str, Any]:
    """解码 EIP-2930 (Type 1) 交易"""
    return {
        "chain_id": to_hex(tx_data[0]),
        "nonce": to_hex(tx_data[1]),
        "gas_price": to_hex(tx_data[2]),
        "gas": to_hex(tx_data[3]),
        "to": to_hex(tx_data[4]) if tx_data[4] else None,
        "value": "0x00" if not tx_data[5] else to_hex(tx_data[5]),
        "data": to_hex(tx_data[6]),
        "access_list": tx_data[7],
        "v": to_hex(tx_data[8]),
        "r": to_hex(tx_data[9]),
        "s": to_hex(tx_data[10]),
    }


def decode_eip1559_tx(tx_data: List) -> Dict[str, Any]:
    """解码 EIP-1559 (Type 2) 交易"""
    current_app.logger.debug(f"decode_eip1559_tx tx_data: {tx_data}")
    return {
        "chain_id": to_hex(tx_data[0]),
        "nonce": to_hex(tx_data[1]),
        "max_priority_fee_per_gas": to_hex(tx_data[2]),
        "max_fee_per_gas": to_hex(tx_data[3]),
        "gas": to_hex(tx_data[4]),
        "to": to_hex(tx_data[5]) if tx_data[5] else None,
        "value": "0x00" if not tx_data[6] else to_hex(tx_data[6]),
        "data": to_hex(tx_data[7]),
        "access_list": tx_data[8],
        "v": to_hex(tx_data[9]),
        "r": to_hex(tx_data[10]),
        "s": to_hex(tx_data[11]),
    }


def decode_blob_tx(tx_data: List) -> Dict[str, Any]:
    """解码 EIP-4844 (Type 3) blob 交易"""
    return {
        "chain_id": to_hex(tx_data[0]),
        "nonce": to_hex(tx_data[1]),
        "max_priority_fee_per_gas": to_hex(tx_data[2]),
        "max_fee_per_gas": to_hex(tx_data[3]),
        "gas": to_hex(tx_data[4]),
        "to": to_hex(tx_data[5]) if tx_data[5] else None,
        "value": "0x00" if not tx_data[6] else to_hex(tx_data[6]),
        "data": to_hex(tx_data[7]),
        "access_list": tx_data[8],
        "max_fee_per_blob_gas": to_hex(tx_data[9]),
        "blob_versioned_hashes": [to_hex(h) for h in tx_data[10]],
        "v": to_hex(tx_data[11]),
        "r": to_hex(tx_data[12]),
        "s": to_hex(tx_data[13]),
    }


from eth_account._utils.signing import extract_chain_id, to_standard_v
from eth_keys import KeyAPI
from eth_utils import keccak, to_hex


def recover_sender(tx_type: int, tx_data: Dict[str, Any]) -> str:
    """
    从交易签名中恢复发送者地址
    """
    # 准备需要签名的数据
    current_app.logger.debug(f"recover_sender tx_data: {tx_data}")
    if tx_type == 0:  # Legacy
        # 构造用于签名的数据
        tx_hash = keccak(
            rlp.encode(
                [
                    int(tx_data["nonce"], 16),
                    int(tx_data["gas_price"], 16),
                    int(tx_data["gas"], 16),
                    bytes.fromhex(tx_data["to"][2:]) if tx_data["to"] else b"",
                    int(tx_data["value"], 16),
                    bytes.fromhex(tx_data["data"][2:]),
                ]
            )
        )
    elif tx_type == 1:  # Access List
        tx_hash = keccak(
            bytes([1])
            + rlp.encode(
                [
                    int(tx_data["chain_id"], 16),
                    int(tx_data["nonce"], 16),
                    int(tx_data["gas_price"], 16),
                    int(tx_data["gas"], 16),
                    bytes.fromhex(tx_data["to"][2:]) if tx_data["to"] else b"",
                    int(tx_data["value"], 16),
                    bytes.fromhex(tx_data["data"][2:]),
                    tx_data["access_list"],
                ]
            )
        )
    elif tx_type == 2:  # EIP-1559
        tx_hash = keccak(
            bytes([2])
            + rlp.encode(
                [
                    int(tx_data["chain_id"], 16),
                    int(tx_data["nonce"], 16),
                    int(tx_data["max_priority_fee_per_gas"], 16),
                    int(tx_data["max_fee_per_gas"], 16),
                    int(tx_data["gas"], 16),
                    bytes.fromhex(tx_data["to"][2:]) if tx_data["to"] else b"",
                    int(tx_data["value"], 16),
                    bytes.fromhex(tx_data["data"][2:]),
                    tx_data["access_list"],
                ]
            )
        )
    elif tx_type == 3:  # Blob
        tx_hash = keccak(
            bytes([3])
            + rlp.encode(
                [
                    int(tx_data["chain_id"], 16),
                    int(tx_data["nonce"], 16),
                    int(tx_data["max_priority_fee_per_gas"], 16),
                    int(tx_data["max_fee_per_gas"], 16),
                    int(tx_data["gas"], 16),
                    bytes.fromhex(tx_data["to"][2:]) if tx_data["to"] else b"",
                    int(tx_data["value"], 16),
                    bytes.fromhex(tx_data["data"][2:]),
                    tx_data["access_list"],
                    int(tx_data["max_fee_per_blob_gas"], 16),
                    [bytes.fromhex(h[2:]) for h in tx_data["blob_versioned_hashes"]],
                ]
            )
        )

    # 从签名中恢复公钥
    v = int(tx_data["v"], 16)
    r = int(tx_data["r"], 16)
    s = int(tx_data["s"], 16)

    # 对于 EIP-155 的向后兼容
    if tx_type == 0:  # 只有 Legacy 交易需要处理 EIP-155
        chain_id = extract_chain_id(v)
        if chain_id is not None:
            v = to_standard_v(v)

    keys = KeyAPI()
    public_key = keys.ecdsa_recover(tx_hash, keys.Signature(vrs=(v, r, s)))

    # 从公钥计算地址
    address = keys.PublicKey(public_key).to_address()
    return to_hex(address)


def recover_sender_from_tx(tx_data: bytes) -> str:
    """
    从交易数据中恢复发送者地址
    Args:
        tx_data: 原始交易数据（RLP 编码之前的）
    Returns:
        发送者地址（格式：0x...）
    """
    try:
        # 使用 eth_account 直接从交易恢复地址
        address = Account.recover_transaction(tx_data)
        return Web3.to_checksum_address(address)
    except Exception as e:
        current_app.logger.error(f"Failed to recover sender from tx: {e}")
        return None


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
                    from_address = recover_sender_from_tx(tx_data)
                    decoded_tx["from"] = from_address
                    decoded_txs.append(DecodedTx(1, decoded_tx))
                elif tx_type == 0x02:  # EIP-1559
                    decoded_tx = decode_eip1559_tx(tx_payload)
                    from_address = recover_sender_from_tx(tx_data)
                    decoded_tx["from"] = from_address
                    decoded_txs.append(DecodedTx(2, decoded_tx))
                elif tx_type == 0x03:  # EIP-4844
                    decoded_tx = decode_blob_tx(tx_payload)
                    from_address = recover_sender_from_tx(tx_data)
                    decoded_tx["from"] = from_address
                    decoded_txs.append(DecodedTx(3, decoded_tx))
                else:
                    current_app.logger.warning(f"Unknown transaction type: {tx_type}")
            else:
                # Legacy 交易
                decoded_tx = decode_legacy_tx(tx_data)
                from_address = recover_sender_from_tx(rlp.encode(tx_data))
                decoded_tx["from"] = from_address
                decoded_txs.append(DecodedTx(0, decoded_tx))

        return decoded_txs

    except Exception as e:
        current_app.logger.error(f"Error decoding transaction list: {str(e)}")
        raise
