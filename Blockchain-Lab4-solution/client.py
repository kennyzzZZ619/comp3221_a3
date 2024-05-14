import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import socket

from blockchain import make_signature, make_transaction_request, make_block_request
from network import recv_prefixed, send_prefixed


private_key = ed25519.Ed25519PrivateKey.generate()
sender = private_key.public_key().public_bytes_raw().hex()
message = 'hello'
nonce = 0
signature = make_signature(private_key, message)
index = 2
# transaction = make_transaction(sender, message, signature)
transaction = make_transaction_request(sender, message, nonce, signature)
# transaction = make_block_request(index)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 8888))

send_prefixed(s, transaction.encode())
try:
	data = recv_prefixed(s).decode()
	print(data)
except Exception as e:
	print(e)
