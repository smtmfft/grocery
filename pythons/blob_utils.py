from ckzg import load_trusted_setup, blob_to_kzg_commitment
from flask import current_app, Flask
import hashlib
from io import BytesIO
import os
import requests
from rlp_utils import decode_tx_list
from typing import Optional
import zlib

blob_url = "https://ethereum-beacon-api.publicnode.com/eth/v1/beacon/blob_sidecars/"


def get_expected_blob_from_slot(slot_id, expected_versioned_hash):
    """
    从 URL 获取 eth blob 数据并验证 hash

    Args:
        url: blob 数据的 URL
        expected_versioned_hash: 期望的 versioned hash
    Returns:
        验证成功返回 blob 数据，失败返回 None
    """
    try:
        # 初始化 trusted setup
        setup_path = "/Users/wangyue/works/ethereum/c-kzg-4844/src/trusted_setup.txt"
        trust_setup = load_trusted_setup(setup_path, 0)
        # load_trusted_setup("/Users/wangyue/works/ethereum/c-kzg-4844/src/trusted_setup.txt")

        # 获取 blob 数据
        blob_query_url = f"{blob_url}{slot_id}"
        current_app.logger.debug(f"Fetching eth blob from URL: {blob_query_url}")
        response = requests.get(blob_query_url)
        response.raise_for_status()
        blob_data_array = response.json()["data"]
        current_app.logger.debug(f"Received blob data: {blob_data_array[0].keys()}")

        # 计算 commitment
        for blob_data in blob_data_array:
            blob_bytes = bytes.fromhex(blob_data["blob"].removeprefix("0x"))
            blob_commitment = blob_data["kzg_commitment"]
            commitment = blob_to_kzg_commitment(blob_bytes, trust_setup)
            assert commitment == bytes.fromhex(
                blob_commitment.removeprefix("0x")
            ), f"commitment mismatch: {commitment.hex()} != {blob_commitment}"

            versioned_hash = commitment_to_versioned_hash(commitment)
            current_app.logger.debug(f"Calculated versioned hash: {versioned_hash}")
            if versioned_hash == expected_versioned_hash:
                current_app.logger.info(
                    f"Found matching blob for hash: {expected_versioned_hash}"
                )
                return blob_bytes

        current_app.logger.warning(
            f"Blob hash mismatch. Expected: {expected_versioned_hash}, "
            f"Got: {versioned_hash}"
        )
        return None

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Failed to fetch blob from URL: {str(e)}")
        raise
    except Exception as e:
        current_app.logger.error(f"Error processing eth blob: {str(e)}")
        raise


def commitment_to_versioned_hash(commitment):
    """
    将 commitment 转换为 versioned hash
    1. 对 commitment 做 SHA256
    2. 设置第一个字节为 VERSIONED_HASH_VERSION_KZG (0x01)
    """
    # 确保 commitment 是 bytes 类型
    if isinstance(commitment, str):
        commitment = bytes.fromhex(commitment.removeprefix("0x"))

    # 计算 SHA256
    hash_bytes = hashlib.sha256(commitment).digest()

    # 修改第一个字节为 0x01
    versioned_hash = bytearray(hash_bytes)
    versioned_hash[0] = 0x01

    return "0x" + bytes(versioned_hash).hex()


# Constants
BLOB_FIELD_ELEMENT_NUM = 4096
BLOB_FIELD_ELEMENT_BYTES = 32
BLOB_DATA_CAPACITY = BLOB_FIELD_ELEMENT_NUM * BLOB_FIELD_ELEMENT_BYTES
# max call data bytes
CALL_DATA_CAPACITY = BLOB_FIELD_ELEMENT_NUM * (BLOB_FIELD_ELEMENT_BYTES - 1)
BLOB_VERSION_OFFSET = 1
BLOB_ENCODING_VERSION = 0
MAX_BLOB_DATA_SIZE = (4 * 31 + 3) * 1024 - 4


def decode_field_element(
    b: bytes, opos: int, ipos: int, output: bytearray
) -> tuple[int, int, int]:
    """
    解码单个 field element
    """
    # 检查最高两位是否为0
    if b[ipos] & 0b11000000 != 0:
        raise ValueError(f"ErrBlobInvalidFieldElement: field element: {ipos}")

    # 复制数据
    output[opos : opos + 31] = b[ipos + 1 : ipos + 32]
    return b[ipos], opos + 32, ipos + 32


def reassemble_bytes(opos: int, encoded_byte: list[int], output: bytearray) -> int:
    """
    重组字节
    """
    # 调整位置（不输出第128个字节）
    opos = opos - 1

    # 重组字节
    x = (encoded_byte[0] & 0b00111111) | ((encoded_byte[1] & 0b00110000) << 2)
    y = (encoded_byte[1] & 0b00001111) | ((encoded_byte[3] & 0b00001111) << 4)
    z = (encoded_byte[2] & 0b00111111) | ((encoded_byte[3] & 0b00110000) << 2)

    # 将重组的字节放到正确的输出位置
    output[opos - 32] = z
    output[opos - (32 * 2)] = y
    output[opos - (32 * 3)] = x

    return opos


def decode_blob_data(blob_buf: bytes) -> bytes:
    """
    解码 blob 数据
    """
    # 检查版本
    if blob_buf[BLOB_VERSION_OFFSET] != BLOB_ENCODING_VERSION:
        return bytes()

    # 解码3字节大端序长度值为4字节整数
    output_len = blob_buf[2] << 16 | blob_buf[3] << 8 | blob_buf[4]

    if output_len > MAX_BLOB_DATA_SIZE:
        return bytes()

    # 创建输出缓冲区
    output = bytearray(MAX_BLOB_DATA_SIZE)

    # 复制第一个 field element 的剩余27字节
    output[0:27] = blob_buf[5:32]

    # 处理第0轮剩余的3个 field elements
    opos = 28  # 输出缓冲区当前位置
    ipos = 32  # 输入blob当前位置
    encoded_byte = [0] * 4  # 4个6位块的缓冲区
    encoded_byte[0] = blob_buf[0]

    try:
        for i in range(1, 4):
            encoded_byte[i], opos, ipos = decode_field_element(
                blob_buf, opos, ipos, output
            )
        opos = reassemble_bytes(opos, encoded_byte, output)

        # 处理剩余轮次，每轮解码4个 field elements
        for _ in range(1, 1024):
            if opos < output_len:
                for j in range(4):
                    encoded_byte[j], opos, ipos = decode_field_element(
                        blob_buf, opos, ipos, output
                    )
                opos = reassemble_bytes(opos, encoded_byte, output)
    except ValueError:
        return bytes()

    # 验证剩余字节是否为0
    if any(b != 0 for b in output[output_len:]):
        return bytes()

    if any(b != 0 for b in blob_buf[ipos:BLOB_DATA_CAPACITY]):
        return bytes()

    return bytes(output[:output_len])


def zlib_decompress_data(data: bytes) -> bytes:
    """
    使用 zlib 解压数据
    """
    return zlib.decompress(data)


def zlib_compress_data(data: bytes) -> bytes:
    """
    使用 zlib 压缩数据
    """
    return zlib.compress(data)


def get_tx_list_from_expected_blob(slot_id: int, expected_versioned_hash: str) -> list:
    """
    从 eth blob 获取交易列表
    """
    blob_bytes = get_expected_blob_from_slot(slot_id, expected_versioned_hash)
    zip_tx_list = decode_blob_data(blob_bytes)
    raw_txlist_bytes = zlib_decompress_data(zip_tx_list[0:79849])
    txs = decode_tx_list(raw_txlist_bytes)
    return txs


if __name__ == "__main__":
    app = Flask(__name__)
    app.logger.setLevel("DEBUG")
    with app.app_context():
        slot_id = 10934114
        expected_versioned_hash = (
            "0x010b218ea00b124aca73e9b53cc81e8e56aa6e4a3415a50fc72e7f7f911f5b6d"
        )
        blob_bytes = get_expected_blob_from_slot(slot_id, expected_versioned_hash)
        zip_tx_list = decode_blob_data(blob_bytes)
        raw_txlist_bytes = zlib_decompress_data(zip_tx_list[0:79849])
        txs = decode_tx_list(raw_txlist_bytes)
        app.logger.info(f"Decoded {len(txs)} transactions")
        for tx in txs[:10]:
            app.logger.info(f"tx: {tx.data}")
            sender = tx.data["from"]
            to = tx.data["to"]
            app.logger.info(f"tx from: {sender}, to: {to}")
