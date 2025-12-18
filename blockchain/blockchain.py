from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
import time
from urllib.parse import urlparse
from uuid import uuid4

import sqlite3
import os
import json
from collections import OrderedDict

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS


MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self, port=None):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')

        # Формируем уникальное имя БД для каждой ноды
        if port:
            self.db_path = f'blockchain_node_{port}.db'
        else:
            self.db_path = 'blockchain.db'

        self.init_db(self.db_path)
        loaded_chain = self.load_chain_from_db()
        if loaded_chain:
            self.chain = loaded_chain
            print(
                f"✅ Нода на порту {port or 'default'}: загружено {len(self.chain)} блоков из {self.db_path}")
        else:
            self.create_block(0, '00')
            print(
                f"🆕 Нода на порту {port or 'default'}: создан генезис-блок в {self.db_path}")

    def init_db(self, db_path='blockchain.db'):
        self.db_path = db_path
        # Создаём таблицу, если не существует
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS blocks (
                        block_number INTEGER PRIMARY KEY,
                        timestamp REAL,
                        transactions TEXT,
                        nonce INTEGER,
                        previous_hash TEXT,
                        hash TEXT
                    )''')
        conn.commit()
        conn.close()

    def save_block_to_db(self, block):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO blocks
                    (block_number, timestamp, transactions,
                     nonce, previous_hash, hash)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                  (block['block_number'],
                   block['timestamp'],
                   # сериализуем список транзакций
                   json.dumps(block['transactions']),
                   block['nonce'],
                   block['previous_hash'],
                   block['hash']))
        conn.commit()
        conn.close()

    def load_chain_from_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # позволяет обращаться по ключам
        c = conn.cursor()
        c.execute('SELECT * FROM blocks ORDER BY block_number ASC')
        rows = c.fetchall()
        chain = []
        for row in rows:
            block = {
                'block_number': row['block_number'],
                'timestamp': row['timestamp'],
                'transactions': json.loads(row['transactions']),
                'nonce': row['nonce'],
                'previous_hash': row['previous_hash'],
                'hash': row['hash']  # Сохраняем оригинальный хеш из БД
            }
            chain.append(block)
        return chain

    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def verify_transaction_signature(self, sender_address, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))

    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = OrderedDict({'sender_address': sender_address,
                                   'recipient_address': recipient_address,
                                   'value': value})

        # Reward for mining a block
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        # Manages transactions from wallet to another wallet
        else:
            transaction_verification = self.verify_transaction_signature(
                sender_address, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False

    def create_block(self, nonce, previous_hash):
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.transactions.copy(),  # Важно: копируем список
            'nonce': nonce,
            'previous_hash': previous_hash,
            'hash': None  # Временно None для корректного расчёта
        }
        # Сначала вычисляем хеш без поля 'hash'
        calculated_hash = self.hash(block)

        # Теперь устанавливаем хеш и сохраняем
        block['hash'] = calculated_hash
        self.transactions = []  # очищаем пул
        self.chain.append(block)
        self.save_block_to_db(block)
        return block

    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # Создаём копию без поля 'hash' чтобы избежать циклической зависимости
        block_copy = block.copy()
        block_copy.pop('hash', None)  # Удаляем поле хеша перед расчётом

        # Гарантируем одинаковый порядок ключей
        block_string = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def valid_proof(self, transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0'*difficulty

    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            # Проверяем хеш предыдущего блока
            if block['previous_hash'] != self.hash(last_block):
                print(
                    f"❌ Хеш не совпадает! Ожидаемый: {self.hash(last_block)}, Фактический: {block['previous_hash']}")
                return False

            # Check that the Proof of Work is correct
            # Delete the reward transaction
            transactions = block['transactions'][:-1]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = [
                'sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict(
                (k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Улучшенный метод разрешения конфликтов, который учитывает невалидность локальной цепочки
        """
        neighbours = self.nodes
        new_chain = None

        # Проверяем валидность нашей собственной цепочки
        our_chain_valid = self.valid_chain(self.chain)
        print(f"Наша цепочка валидна: {our_chain_valid}")

        # Если наша цепочка невалидна, мы готовы принять ЛЮБУЮ валидную цепочку,
        # даже если она короче нашей
        if not our_chain_valid:
            print("⚠️ Наша цепочка невалидна! Ищем ЛЮБУЮ валидную цепочку")

        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain', timeout=1)

                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    # Две стратегии выбора:
                    # 1. Если наша цепочка невалидна - принимаем ЛЮБУЮ валидную цепочку
                    # 2. Если наша цепочка валидна - принимаем только более длинные валидные цепочки
                    chain_valid = self.valid_chain(chain)
                    should_replace = (
                        (not our_chain_valid and chain_valid) or
                        (our_chain_valid and length > len(
                            self.chain) and chain_valid)
                    )

                    if should_replace:
                        print(
                            f"✅ Выбрана цепочка от узла {node} (длина: {length}, валидна: {chain_valid})")
                        new_chain = chain
                        break  # Находим первую подходящую цепочку и выходим

            except Exception as e:
                print(f" Ошибка при запросе к узлу {node}: {str(e)}")
                continue

        # Заменяем цепочку, если нашли подходящую
        if new_chain:
            self.chain = new_chain
            print(
                f" Цепочка успешно заменена. Новая длина: {len(self.chain)}")
            return True

        print(" Не найдено подходящей цепочки для замены")
        return False


# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(
        values['sender_address'], values['recipient_address'], values['amount'], values['signature'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {
            'message': 'Transaction will be added to Block ' + str(transaction_result)}
        return jsonify(response), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(
        sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/validate', methods=['GET'])
def validate_chain():
    is_valid = blockchain.valid_chain(blockchain.chain)
    response = {
        'valid': is_valid,
        'message': 'Chain is valid!' if is_valid else 'Chain is INVALID!'
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    # Передаём порт в блокчейн → уникальная БД
    blockchain = Blockchain(port=port)

    app.run(host='127.0.0.1', port=port)
