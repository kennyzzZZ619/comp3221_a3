import hashlib
import threading
import time
from argparse import ArgumentParser
import json
from socket import socket
from threading import Lock
import socketserver
import socket

import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519

from blockchain import Blockchain, make_signature, make_transaction_request, make_block_request, \
    block_validate_transaction
from network import recv_prefixed, send_prefixed


class MyTCPServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, nodes=None):
        self.blockchain = Blockchain()
        self.blockchain_lock = Lock()
        self.nodes = nodes
        self.view_leader = 0
        self.prepares = {}
        self.commits = {}
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def create_and_broadcast_block(self):
        new_block = self.blockchain.last_block()
        block_data = json.dumps({'type': 'pre-prepare', 'block': new_block, 'sender': f"{self.server_address[0]}:{self.server_address[1]}"}).encode('utf-8')
        self.broadcast(block_data)

    def broadcast(self, message):
        print("try to broadcasting.....")
        for node in self.nodes:
            t = threading.Thread(target=self.send_message, args=(message, node))
            t.start()

    def send_message(self, message, node, retry_attempts=3, retry_delay=5):
        host, port = node
        for attempt in range(retry_attempts):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(5)
                    sock.connect((host, port))
                    send_prefixed(sock, message)
                    print(f"Message sent to {host}:{port}")
                    return
            except socket.timeout:
                print(f"Connection to {host}:{port} timed out on attempt {attempt + 1}/{retry_attempts}. Retrying...")
            except Exception as e:
                print(f"Failed to send message to {host}:{port} on attempt {attempt + 1}/{retry_attempts}: {e}")

            time.sleep(retry_delay)

        print(f"Failed to send message to {host}:{port} after {retry_attempts} attempts. Giving up.")


class MyTCPHandler(socketserver.BaseRequestHandler):
    server: MyTCPServer

    def handle(self):
        while True:
            try:
                data = recv_prefixed(self.request).decode('utf-8')
            except Exception as e:
                # print(f"Error handling message: {e}")
                break
            data_load = json.loads(data)
            request_type = data_load['type']
            with self.server.blockchain_lock:
                if request_type == "transaction":
                    print("**************************")
                    print("Transaction Request.")
                    print(f"Received a transaction from node: {format(self.client_address[0])}:\n{data}")
                    payload = data_load['payload']
                    added = self.server.blockchain.add_transaction(data)
                    # before added,validate nonce, validate other things.
                    if added:
                        print(f"[MEM] Stored transaction in the transaction pool: {payload['signature']}")
                        if len(self.server.blockchain.pool) >= 3:
                            new_block_created = self.server.blockchain.new_block(
                                self.server.blockchain.last_block()['current_hash'])
                            if new_block_created:
                                self.server.create_and_broadcast_block()
                                print("[PROPOSAL] Created a block proposal:", new_block_created)
                                print("**************************")
                    print("**************************")
                    send_prefixed(self.request, json.dumps({'response': added}).encode())
                elif request_type == "value":
                    print("**************************")
                    print("Block Request.")
                    index = data_load['payload']
                    print(f"{index}")
                    response = self.handle_block_request(index)
                    send_prefixed(self.request, json.dumps({'response': response}).encode())
                    print("**************************")
                elif request_type == 'pre-prepare':
                    self.handle_pre_prepare(data_load)
                    print(
                        f"[BLOCK] Received a block request pre-prepare from node {data_load['sender']}: {data_load}")
                elif request_type == 'prepare':
                    self.handle_prepare(data_load)
                    print(
                        f"[BLOCK] Received a block prepare request from node {data_load['sender']}: {data_load}")
                elif request_type == 'commit':
                    self.handle_commit(data_load)
                    print(
                        f"[BLOCK] Received a block commit request from node {data_load['sender']}: {data_load}")
                else:
                    print("error: invalid request type.")


    def handle_block_request(self, payload):
        block_index = int(payload)  # Payload is the index of the block requested

        # Ensure the index is within the valid range of your blockchain
        if block_index < 0 or block_index >= len(self.server.blockchain.blockchain):
            return {'error': 'Block index out of range'}

        # Fetch the block
        block = self.server.blockchain.blockchain[block_index]
        print(f"The block {block_index} is : {block}")
        return block

    def calculate_block_hash(self, block):
        # Assuming block is a dictionary that includes all necessary fields
        block_string = json.dumps({
            'index': block['index'],
            'transactions': block['transactions'],
            'previous_hash': block['previous_hash']
        }, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_string).hexdigest()

    def handle_pre_prepare(self, message):
        block = message['block']
        sender = message['sender']
        if self.validate_block(block):
            block_hash = self.calculate_block_hash(block)
            self.server.prepares[block_hash] = set()
            self.broadcast_prepare(block)
            print("Prepare message broadcast to all nodes")
        else:
            print("Block validation failed......")

    def broadcast_prepare(self, block):
        prepare_msg = json.dumps({'type': 'prepare',
                                  'block': block,
                                  'sender': f"{self.server.server_address[0]}:{self.server.server_address[1]}"}).encode(
            'utf-8')
        print("preparing message......")
        self.server.broadcast(prepare_msg)


    def handle_prepare(self, message):
        block_hash = self.calculate_block_hash(message['block'])
        sender = message['sender']
        sender = str(sender)
        if not isinstance(sender, str):
            print(f"Invalid sender type: {type(sender)}")
            return
        if block_hash not in self.server.prepares:
            self.server.prepares[block_hash] = set()
        self.server.prepares[block_hash].add(sender)
        print(f"Length is : {len(self.server.prepares[block_hash])} and {len(self.server.nodes) * 2 / 3}")
        # Check if the prepares reach 2/3 of the nodes
        if len(self.server.prepares[block_hash]) >= len(self.server.nodes) * 2 / 3:
            print("broadcast commit")
            self.broadcast_commit(message['block'])
            del self.server.prepares[block_hash]
        # else:
        #     print("Not validate")

    def broadcast_commit(self, block):
        commit_msg = json.dumps({'type': 'commit',
                                 'block': block,
                                 'sender': f"{self.server.server_address[0]}:{self.server.server_address[1]}"}).encode(
            'utf-8')
        self.server.broadcast(commit_msg)


    def handle_commit(self, message):
        block_hash = self.calculate_block_hash(message['block'])
        sender = message['sender']
        sender = str(sender)
        if block_hash not in self.server.commits:
            self.server.commits[block_hash] = set()
        self.server.commits[block_hash].add(sender)
        if len(self.server.commits[block_hash]) >= len(self.server.nodes) * 2 / 3:
            if self.add_block_to_chain(message['block']):
                del self.server.commits[block_hash]


    def add_block_to_chain(self, block):
        # 检查是否有相同索引的区块
        for existing_block in self.server.blockchain.blockchain:
            if existing_block['index'] == block['index']:
                print(f"Block with index {block['index']} already exists. Not adding to blockchain.")
                return False

        # 添加区块到区块链
        self.server.blockchain.blockchain.append(block)
        print("Block added to the blockchain.")
        print(f"[CONSENSUS] Appended to the blockchain: {block['current_hash']}")
        return True

    def validate_block(self, block: dict):
        for tx in block['transactions']:
            if not block_validate_transaction(tx):
                print("transaction validation fail")
                return False
        if block['index'] != self.server.blockchain.last_block()['index'] + 1:
            print("block index fail")
            return False
        if self.server.blockchain.last_block()['current_hash'] != block['previous_hash']:
            print("hash validation fail")
            return False
        return True


def server_threading(HOST, port, nodes):
    server = MyTCPServer((HOST, port), MyTCPHandler, True, nodes)
    server.serve_forever()


def client_threading(host_other, port_other):
    try:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.connect((host_other, port_other))
                except socket.error as e:
                    print(f"Failed to connect to {host_other}:{port_other}, error: {e}")
                    time.sleep(10)  # Wait before retrying to connect
                    continue

                while True:
                    classifier = input("Enter '0' for transaction request, '1' for block request: ")
                    if classifier in ['0', '1']:
                        break
                    print("Invalid input, please enter '0' or '1'.")

                sender, message, nonce, signature, index = generate_message()

                transaction = None  # Initialize to None
                if classifier == '0':
                    transaction = make_transaction_request(sender, message, nonce, signature)
                elif classifier == '1':
                    transaction = make_block_request(index)

                if transaction:
                    send_prefixed(sock, transaction.encode())
                    try:
                        response = recv_prefixed(sock).decode()
                        print("Received from other node:", response)
                    except Exception as e:
                        print(f"Error receiving data: {e}")
                else:
                    print("No valid transaction was generated.")

            time.sleep(10)  # Wait for 10 seconds before sending the next request

    except Exception as e:
        print(f"Error in client operations: {e}")

def generate_message():
    private_key = ed25519.Ed25519PrivateKey.generate()
    sender = private_key.public_key().public_bytes_raw().hex()
    message = 'hello'  # or other message
    nonce = 0
    signature = make_signature(private_key, message)
    index = 1
    return sender, message, nonce, signature, index


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('port', type=int)
    parser.add_argument('node_list', type=str)
    args = parser.parse_args()
    port: int = args.port
    node_list: str = args.node_list
    HOST = '192.168.1.106'  # localhost
    host_other = '192.168.1.105'  # change----->'local host'
    port_other = 8001  # change--------->8000
    nodes = []
    try:
        with open(node_list, 'r') as file:
            for line in file:
                ip_port = line.strip()
                if ip_port:
                    host, port_str = ip_port.split(':')
                    node_port = int(port_str)
                    if node_port != port:
                        nodes.append((host, node_port))
    except FileNotFoundError:
        print(f"Error: The file {node_list} does not exist.")
        exit(1)
    except ValueError:
        print("Error: File format is incorrect. Each line should be in 'host:port' format.")
        exit(1)

    print(f"Loaded nodes: {nodes}")
    try:
        server_thread = threading.Thread(target=server_threading, args=(HOST, port, nodes))
        server_thread.start()
        client_thread = threading.Thread(target=client_threading, args=(host_other, port_other))  # nodes,
        client_thread.start()
        print(f"Server started on {HOST}:{port}. Press Ctrl+C to stop.")
        server_thread.join()
        client_thread.join()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    except Exception as e:
        print(f"Error starting the server: {e}")
