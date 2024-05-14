from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from enum import Enum
import hashlib
import json
import re

sender_valid = re.compile('^[a-fA-F0-9]{64}$')
signature_valid = re.compile('^[a-fA-F0-9]{128}$')

TransactionValidationError = Enum('TransactionValidationError',
                                  ['INVALID_JSON', 'INVALID_SENDER', 'INVALID_MESSAGE', 'INVALID_SIGNATURE'])


def make_transaction(sender, message, signature) -> str:
    return json.dumps({'sender': sender, 'message': message, 'signature': signature})


def make_transaction_request(sender, message, nonce, signature) -> str:
    transaction = {"type": "transaction",
                   "payload": {
                       'sender': sender,
                       'message': message,
                       'nonce': nonce,
                       'signature': signature}}
    return json.dumps(transaction)


def make_block_request(index) -> str:
    block_index = {"type": "value",
                   "payload": index}
    return json.dumps(block_index)


def transaction_bytes(transaction: dict) -> bytes:
    # access the payload
    payload = transaction.get('payload', {})
    # get from payload
    data_to_sign = {k: payload.get(k) for k in ['sender', 'message', 'nonce']}
    return json.dumps(data_to_sign, sort_keys=True).encode()


def make_signature(private_key: ed25519.Ed25519PrivateKey, message: str) -> str:
    transaction = {'sender': private_key.public_key().public_bytes_raw().hex(), 'message': message}  # nonce？
    return private_key.sign(transaction_bytes(transaction)).hex()


def validate_transaction(transaction: str) -> dict | TransactionValidationError:
    try:
        tx = json.loads(transaction)
    except json.JSONDecodeError:
        return TransactionValidationError.INVALID_JSON

    # 访问 payload 数据
    payload = tx.get('payload', {})

    if not (payload.get('sender') and isinstance(payload['sender'], str) and sender_valid.search(payload['sender'])):
        return TransactionValidationError.INVALID_SENDER

    if not (payload.get('message') and isinstance(payload['message'], str) and len(payload['message']) <= 70 and
            payload['message'].isalnum()):
        return TransactionValidationError.INVALID_MESSAGE

    # 将 sender 用于创建公钥对象
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload['sender']))
    except ValueError:
        return TransactionValidationError.INVALID_SENDER

    if not (payload.get('signature') and isinstance(payload['signature'], str) and signature_valid.search(
            payload['signature'])):
        return TransactionValidationError.INVALID_SIGNATURE

    try:
        # 确保传递正确的数据给验证函数
        public_key.verify(bytes.fromhex(payload['signature']), transaction_bytes(payload))
    except InvalidSignature:
        return TransactionValidationError.INVALID_SIGNATURE

    return tx  # 返回验证通过的交易

def block_validate_transaction(transaction: dict) -> dict | TransactionValidationError:
    tx = transaction

    # 访问 payload 数据
    payload = tx.get('payload', {})

    if not (payload.get('sender') and isinstance(payload['sender'], str) and sender_valid.search(payload['sender'])):
        return TransactionValidationError.INVALID_SENDER

    if not (payload.get('message') and isinstance(payload['message'], str) and len(payload['message']) <= 70 and
            payload['message'].isalnum()):
        return TransactionValidationError.INVALID_MESSAGE

    # 将 sender 用于创建公钥对象
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(payload['sender']))
    except ValueError:
        return TransactionValidationError.INVALID_SENDER

    if not (payload.get('signature') and isinstance(payload['signature'], str) and signature_valid.search(
            payload['signature'])):
        return TransactionValidationError.INVALID_SIGNATURE

    try:
        # 确保传递正确的数据给验证函数
        public_key.verify(bytes.fromhex(payload['signature']), transaction_bytes(payload))
    except InvalidSignature:
        return TransactionValidationError.INVALID_SIGNATURE

    return tx  # 返回验证通过的交易

class Blockchain():
    def __init__(self):
        self.blockchain = []
        self.pool = []
        self.new_block('0' * 64)  # gen block
        self.confirmed_transactions = []
        self.nonce_map = {}

    def new_block(self, previous_hash):
        block = {
            'index': len(self.blockchain) + 1,
            'transactions': self.pool.copy(),
            'previous_hash': previous_hash or self.blockchain[-1]['current_hash'],
        }
        block['current_hash'] = self.calculate_hash(block)
        self.pool = []
        self.blockchain.append(block)
        print(self.blockchain)
        return True

    def last_block(self):
        return self.blockchain[-1]

    def calculate_hash(self, block: dict) -> str:
        block_object: str = json.dumps({k: block.get(k) for k in ['index', 'transactions', 'previous_hash']},
                                       sort_keys=True)
        block_string = block_object.encode()
        raw_hash = hashlib.sha256(block_string)
        hex_hash = raw_hash.hexdigest()
        return hex_hash

    def add_transaction(self, transaction: str) -> bool:
        if isinstance((tx := validate_transaction(transaction)), dict) and self.validate_nonce(transaction):
            self.pool.append(tx)
            self.confirm_transaction(tx)
            return True
        else:
            print(validate_transaction(transaction))
        return False

    def update_nonce(self, sender):
        """Increment the nonce for a sender after their transaction is confirmed."""
        current_nonce = self.get_current_nonce(sender)
        self.nonce_map[sender] = current_nonce + 1
        print(f"Nonce updated for {sender}: {current_nonce + 1}")

    def get_current_nonce(self, sender):
        """Retrieve the current nonce for a given sender."""
        return self.nonce_map.get(sender, 0)

    def validate_nonce(self, transaction_str):
        """Validate the transaction, especially the nonce."""
        transaction = json.loads(transaction_str)
        sender = transaction['payload']['sender']
        if transaction['payload']['nonce'] != self.get_current_nonce(sender):
            print(f"Invalid nonce for transaction: {transaction}")
            return False
        # Additional validation checks
        return True

    def confirm_transaction(self, transaction):
        """Confirm a transaction and update the sender's nonce."""
        self.confirmed_transactions.append(transaction)
        self.update_nonce(transaction['payload']['sender'])
