from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import sqlite3
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Any
import secrets
import ecdsa
import base58

class NovaraBlockchainServer:
    def __init__(self, socketio):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 6  # ⚡ AUMENTATA DIFFICOLTÀ! (6 zeri)
        self.mining_reward = 10
        self.transaction_fee = 0.001
        self.max_supply = 1000
        self.total_mined = 0
        self.db_path = "novara_server.db"
        self.peers = set()
        self.socketio = socketio
        self.mining_stats = {
            'total_attempts': 0,
            'total_time': 0,
            'last_hash_rate': 0
        }
        
        self.init_database()
        if not self.load_chain_from_db():
            self.create_genesis_block()
        
        self.calculate_total_mined()
        print("✅ Novara Blockchain Server Ready!")
        print(f"💰 Max Supply: {self.max_supply:,} NVR - ULTRA RARI!")
        print(f"⛏️ Total Mined: {self.total_mined:,} NVR")
        print(f"📊 Remaining: {self.max_supply - self.total_mined:,} NVR")
        print(f"🎯 Difficulty: {self.difficulty} (MOLTO DIFFICILE!)")
        print(f"🔌 WebSockets: ATTIVI")

    def calculate_total_mined(self):
        """Calcola il totale di NVR minati"""
        self.total_mined = 0
        for block in self.chain:
            for tx in block['transactions']:
                if tx['from'] == 'NETWORK' and tx.get('type') in ['mining_reward', 'genesis']:
                    self.total_mined += tx['amount']

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER UNIQUE,
                transactions TEXT,
                timestamp REAL,
                previous_hash TEXT,
                hash TEXT UNIQUE,
                nonce INTEGER,
                mining_time REAL,
                attempts INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_address TEXT,
                to_address TEXT,
                amount REAL,
                signature TEXT,
                public_key TEXT,
                transaction_id TEXT UNIQUE,
                timestamp REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blockchain_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_mined REAL,
                max_supply REAL,
                last_update REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mining_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER,
                mining_time REAL,
                attempts INTEGER,
                hash_rate REAL,
                difficulty INTEGER,
                timestamp REAL
            )
        ''')
        
        conn.commit()
        conn.close()

    def load_chain_from_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM blocks ORDER BY block_index')
            blocks_data = cursor.fetchall()
            
            if not blocks_data:
                return False
            
            for block_data in blocks_data:
                block = {
                    'index': block_data[1],
                    'transactions': json.loads(block_data[2]),
                    'timestamp': block_data[3],
                    'previous_hash': block_data[4],
                    'hash': block_data[5],
                    'nonce': block_data[6],
                    'mining_time': block_data[7] if block_data[7] else 0,
                    'attempts': block_data[8] if block_data[8] else 0
                }
                self.chain.append(block)
            
            cursor.execute('SELECT * FROM pending_transactions')
            pending_data = cursor.fetchall()
            
            for tx in pending_data:
                self.pending_transactions.append({
                    'from': tx[1],
                    'to': tx[2],
                    'amount': tx[3],
                    'signature': tx[4],
                    'public_key': tx[5],
                    'transaction_id': tx[6],
                    'timestamp': tx[7]
                })
            
            cursor.execute('SELECT * FROM blockchain_stats WHERE id = 1')
            stats = cursor.fetchone()
            if stats:
                self.total_mined = stats[1] or 0
            
            conn.close()
            print(f"📦 Blockchain caricata: {len(self.chain)} blocchi, {len(self.pending_transactions)} transazioni pendenti")
            return True
        except Exception as e:
            print(f"❌ Error loading chain: {e}")
            return False

    def save_stats_to_db(self):
        """Salva le statistiche nel database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO blockchain_stats (id, total_mined, max_supply, last_update)
            VALUES (1, ?, ?, ?)
        ''', (self.total_mined, self.max_supply, time.time()))
        
        conn.commit()
        conn.close()

    def save_mining_stats(self, block_index, mining_time, attempts, hash_rate):
        """Salva statistiche mining"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO mining_stats (block_index, mining_time, attempts, hash_rate, difficulty, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (block_index, mining_time, attempts, hash_rate, self.difficulty, time.time()))
        
        conn.commit()
        conn.close()

    def create_genesis_block(self):
        """Crea il blocco genesis con 100 NVR per la foundation"""
        genesis_tx = {
            'transaction_id': 'genesis_novara',
            'from': 'NETWORK',
            'to': 'foundation',
            'amount': 100,
            'signature': 'genesis',
            'public_key': 'genesis',
            'timestamp': time.time(),
            'type': 'genesis'
        }
        
        genesis_block = self.create_block(0, [genesis_tx], time.time(), "0")
        genesis_block['hash'] = self.calculate_block_hash(genesis_block)
        self.chain.append(genesis_block)
        self.save_block_to_db(genesis_block)
        self.total_mined += 100
        self.save_stats_to_db()
        print("🎉 Genesis Block Created with 100 NVR!")

    def create_block(self, index, transactions, timestamp, previous_hash):
        return {
            'index': index,
            'transactions': transactions,
            'timestamp': timestamp,
            'previous_hash': previous_hash,
            'nonce': 0,
            'hash': '',
            'mining_time': 0,
            'attempts': 0
        }

    def calculate_block_hash(self, block):
        block_string = f"{block['index']}{json.dumps(block['transactions'], sort_keys=True)}{block['timestamp']}{block['previous_hash']}{block['nonce']}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, block, miner_address):
        """MINING REALE CON DIFFICOLTÀ ELEVATA - Proof of Work"""
        target = "0" * self.difficulty  # Es: "000000" per difficulty=6
        block['hash'] = self.calculate_block_hash(block)
        attempts = 0
        start_time = time.time()
        last_update_time = start_time
        
        print(f"⛏️ INIZIO MINING Blocco #{block['index']}")
        print(f"🎯 Target: hash che inizia con '{target}'")
        print(f"🔍 Difficoltà: {self.difficulty} (MOLTO ALTA)")
        print("=" * 50)
        
        # Notifica inizio mining via WebSocket
        self.socketio.emit('mining_progress', {
            'type': 'mining_started',
            'block_index': block['index'],
            'miner': miner_address,
            'difficulty': self.difficulty,
            'target': target
        })
        
        while block['hash'][:self.difficulty] != target:
            block['nonce'] += 1
            block['hash'] = self.calculate_block_hash(block)
            attempts += 1
            
            # Aggiornamento progressi ogni secondo
            current_time = time.time()
            if current_time - last_update_time >= 1.0:
                elapsed = current_time - start_time
                hash_rate = attempts / elapsed if elapsed > 0 else 0
                last_update_time = current_time
                
                progress_data = {
                    'type': 'mining_progress',
                    'block_index': block['index'],
                    'attempts': attempts,
                    'elapsed_time': elapsed,
                    'hash_rate': hash_rate,
                    'current_hash': block['hash'][:16] + '...',
                    'nonce': block['nonce']
                }
                
                # Stampa progressi nella console
                print(f"⛏️ Tentativi: {attempts:,} | Hash: {block['hash'][:16]}... | Nonce: {block['nonce']:,} | Rate: {hash_rate:,.0f} H/s")
                
                # Invia progressi via WebSocket
                self.socketio.emit('mining_progress', progress_data)
        
        mining_time = time.time() - start_time
        hash_rate = attempts / mining_time if mining_time > 0 else 0
        
        # Salva statistiche
        self.mining_stats['total_attempts'] += attempts
        self.mining_stats['total_time'] += mining_time
        self.mining_stats['last_hash_rate'] = hash_rate
        
        self.save_mining_stats(block['index'], mining_time, attempts, hash_rate)
        
        print("=" * 50)
        print(f"✅ BLOCCO #{block['index']} MINATO CON SUCCESSO!")
        print(f"🎯 Hash trovato: {block['hash']}")
        print(f"⛏️ Statistiche Mining:")
        print(f"   • Tentativi totali: {attempts:,}")
        print(f"   • Tempo impiegato: {mining_time:.2f} secondi")
        print(f"   • Hash rate: {hash_rate:,.0f} H/s")
        print(f"   • Nonce finale: {block['nonce']:,}")
        print(f"   • Difficoltà: {self.difficulty}")
        
        # Notifica completamento mining
        self.socketio.emit('mining_progress', {
            'type': 'mining_completed',
            'block_index': block['index'],
            'attempts': attempts,
            'mining_time': mining_time,
            'hash_rate': hash_rate,
            'final_hash': block['hash'],
            'nonce': block['nonce']
        })
        
        return mining_time, attempts, hash_rate

    def save_block_to_db(self, block):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO blocks (block_index, transactions, timestamp, previous_hash, hash, nonce, mining_time, attempts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            block['index'],
            json.dumps(block['transactions']),
            block['timestamp'],
            block['previous_hash'],
            block['hash'],
            block['nonce'],
            block.get('mining_time', 0),
            block.get('attempts', 0)
        ))
        
        conn.commit()
        conn.close()

    def generate_bitcoin_address(self, public_key_bytes):
        """Genera indirizzo Bitcoin-style dalla public key"""
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        versioned_payload = b'\x00' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        binary_address = versioned_payload + checksum
        
        return base58.b58encode(binary_address).decode('ascii')

    def verify_transaction_signature(self, transaction_data):
        """Verifica la firma ECDSA della transazione"""
        try:
            message = f"{transaction_data['from']}{transaction_data['to']}{transaction_data['amount']}{transaction_data['timestamp']}"
            
            public_key_hex = transaction_data['public_key']
            signature_hex = transaction_data['signature']
            
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=ecdsa.SECP256k1)
            
            public_key_bytes = bytes.fromhex(public_key_hex)
            claimed_address = self.generate_bitcoin_address(public_key_bytes)
            
            if claimed_address != transaction_data['from']:
                return False, "Address doesn't match public key"
            
            if vk.verify(bytes.fromhex(signature_hex), message.encode()):
                return True, "Signature valid"
            else:
                return False, "Invalid signature"
                
        except Exception as e:
            return False, f"Signature verification failed: {e}"

    def add_transaction(self, transaction_data):
        """Aggiunge transazione con verifica firma"""
        required = ['from', 'to', 'amount', 'signature', 'public_key', 'timestamp']
        if not all(k in transaction_data for k in required):
            return False, "Missing required fields"
        
        if transaction_data['amount'] <= 0:
            return False, "Invalid amount"
        
        is_valid, sig_message = self.verify_transaction_signature(transaction_data)
        if not is_valid:
            return False, f"Invalid transaction signature: {sig_message}"
        
        sender_balance = self.get_balance(transaction_data['from'])
        total_cost = transaction_data['amount'] + self.transaction_fee
        if sender_balance < total_cost:
            return False, f"Insufficient funds: {sender_balance} NVR available, need {total_cost} NVR"
        
        tx_id = hashlib.sha256(
            f"{transaction_data['from']}{transaction_data['to']}{transaction_data['amount']}{time.time()}".encode()
        ).hexdigest()
        
        transaction = {
            'transaction_id': tx_id,
            'from': transaction_data['from'],
            'to': transaction_data['to'],
            'amount': transaction_data['amount'],
            'signature': transaction_data['signature'],
            'public_key': transaction_data['public_key'],
            'timestamp': transaction_data['timestamp']
        }
        
        self.pending_transactions.append(transaction)
        self.save_pending_transaction(transaction)
        
        # NOTIFICA WEBSOCKET
        self.socketio.emit('blockchain_update', {
            'type': 'new_transaction',
            'from': transaction_data['from'][:8] + '...',
            'to': transaction_data['to'][:8] + '...', 
            'amount': transaction_data['amount'],
            'transaction_id': tx_id
        })
        
        print(f"✅ Transazione verificata: {tx_id} - {transaction_data['amount']} NVR")
        return True, f"Transaction added: {tx_id}"

    def save_pending_transaction(self, transaction):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO pending_transactions (from_address, to_address, amount, signature, public_key, transaction_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            transaction['from'],
            transaction['to'],
            transaction['amount'],
            transaction['signature'],
            transaction['public_key'],
            transaction['transaction_id'],
            transaction['timestamp']
        ))
        
        conn.commit()
        conn.close()

    def get_balance(self, address):
        """Calcola il balance CORRETTO per max supply 1000"""
        balance = 0.0
        
        for block in self.chain:
            for tx in block['transactions']:
                if tx['to'] == address:
                    balance += tx['amount']
                
                if (tx['from'] == address and 
                    tx.get('type') not in ['mining_reward', 'genesis'] and
                    tx['from'] != 'NETWORK'):
                    balance -= tx['amount'] + self.transaction_fee
        
        for tx in self.pending_transactions:
            if (tx['from'] == address and 
                tx.get('type') != 'mining_reward' and
                tx['from'] != 'NETWORK'):
                balance -= tx['amount'] + self.transaction_fee
        
        return round(max(0, balance), 6)

    def mine_pending_transactions(self, miner_address):
        """Mining per economia ultra-rara (1000 NVR totali)"""
        print(f"⛏️ INIZIO MINING per {miner_address}")
        print(f"💰 Supply attuale: {self.total_mined}/1000 NVR")
        
        remaining = self.max_supply - self.total_mined
        if remaining <= 0:
            return False, f"🎉 TUTTI I 1000 NVR SONO STATI MINATI! Supply esaurita.", 0
        
        base_reward = self.mining_reward
        if remaining < base_reward:
            reward_amount = remaining
        else:
            reward_amount = base_reward
        
        valid_transactions = [tx for tx in self.pending_transactions if tx['from'] != 'NETWORK']
        
        reward_tx = {
            'transaction_id': f"reward_{int(time.time())}_{secrets.token_hex(4)}",
            'from': 'NETWORK', 
            'to': miner_address,
            'amount': reward_amount,
            'signature': 'mining_reward',
            'public_key': 'mining_reward',
            'timestamp': time.time(),
            'type': 'mining_reward'
        }
        
        transactions_to_mine = valid_transactions + [reward_tx]
        
        new_block = self.create_block(
            len(self.chain),
            transactions_to_mine, 
            time.time(),
            self.chain[-1]['hash'] if self.chain else "0"
        )
        
        # MINING REALE CON DIFFICOLTÀ
        mining_time, attempts, hash_rate = self.mine_block(new_block, miner_address)
        
        # Aggiorna tempi e tentativi nel blocco
        new_block['mining_time'] = mining_time
        new_block['attempts'] = attempts
        
        self.chain.append(new_block)
        self.save_block_to_db(new_block)
        self.total_mined += reward_amount
        self.save_stats_to_db()
        
        self.pending_transactions = [tx for tx in self.pending_transactions if tx not in valid_transactions]
        self.clear_pending_db()
        for tx in self.pending_transactions:
            self.save_pending_transaction(tx)
        
        # NOTIFICA WEBSOCKET
        self.socketio.emit('blockchain_update', {
            'type': 'new_block',
            'block_index': new_block['index'],
            'miner': miner_address,
            'reward': reward_amount,
            'total_mined': self.total_mined,
            'transactions_count': len(valid_transactions),
            'mining_time': mining_time,
            'attempts': attempts,
            'hash_rate': hash_rate
        })
        
        message = f"Block {new_block['index']} mined! {len(valid_transactions)} transactions + {reward_amount} NVR reward"
        message += f"\n📊 Supply: {self.total_mined}/1000 NVR ({(self.total_mined/self.max_supply)*100:.1f}%)"
        message += f"\n⛏️ Stats: {attempts:,} attempts, {mining_time:.2f}s, {hash_rate:,.0f} H/s"
        
        print(f"✅ {message}")
        return True, message, reward_amount

    def clear_pending_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM pending_transactions')
        conn.commit()
        conn.close()

    def get_blockchain_info(self):
        valid_pending = len([tx for tx in self.pending_transactions if tx['from'] != 'NETWORK'])
        remaining_supply = max(0, self.max_supply - self.total_mined)
        
        # Calcola hash rate medio
        avg_hash_rate = 0
        if self.mining_stats['total_time'] > 0:
            avg_hash_rate = self.mining_stats['total_attempts'] / self.mining_stats['total_time']
        
        return {
            'chain_length': len(self.chain),
            'pending_transactions': valid_pending,
            'difficulty': self.difficulty,
            'mining_reward': self.mining_reward,
            'total_transactions': sum(len(block['transactions']) for block in self.chain),
            'latest_block': self.chain[-1] if self.chain else None,
            'mining_available': remaining_supply > 0,
            'max_supply': self.max_supply,
            'total_mined': self.total_mined,
            'remaining_supply': remaining_supply,
            'progress_percent': (self.total_mined / self.max_supply) * 100 if self.max_supply > 0 else 0,
            'transaction_fee': self.transaction_fee,
            'avg_hash_rate': avg_hash_rate,
            'total_mining_attempts': self.mining_stats['total_attempts'],
            'total_mining_time': self.mining_stats['total_time']
        }

# Inizializza Flask App
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
blockchain = NovaraBlockchainServer(socketio)

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    print(f"🔌 Client WebSocket connected: {request.sid}")
    emit('blockchain_update', {'type': 'connected', 'message': 'Benvenuto su Novara Coin!'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"❌ Client WebSocket disconnected: {request.sid}")

# === API ROUTES ===

@app.route('/api/info', methods=['GET'])
def get_info():
    """Restituisce info blockchain"""
    info = blockchain.get_blockchain_info()
    return jsonify(info), 200

@app.route('/api/chain', methods=['GET'])
def get_chain():
    """Restituisce l'intera blockchain"""
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }), 200

@app.route('/api/transactions/new', methods=['POST'])
def new_transaction():
    """Aggiunge una nuova transazione"""
    values = request.get_json()
    success, message = blockchain.add_transaction(values)
    
    if success:
        return jsonify({
            'message': message,
            'transaction_id': values.get('transaction_id', 'unknown')
        }), 201
    else:
        return jsonify({'error': message}), 400

@app.route('/api/mine', methods=['POST'])
def mine_block():
    """Mina un nuovo blocco"""
    values = request.get_json()
    miner_address = values.get('miner_address', 'anonymous_miner')
    
    if not miner_address or miner_address == 'anonymous_miner':
        return jsonify({'error': 'Please provide a valid miner address'}), 400
    
    success, message, reward = blockchain.mine_pending_transactions(miner_address)
    
    if success:
        return jsonify({
            'message': message,
            'block_index': len(blockchain.chain) - 1,
            'reward': reward,
            'total_mined': blockchain.total_mined,
            'remaining_supply': blockchain.max_supply - blockchain.total_mined
        }), 200
    else:
        return jsonify({'error': message}), 400

@app.route('/api/balance/<address>', methods=['GET'])
def get_balance(address):
    """Restituisce balance di un indirizzo"""
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/api/transactions/<address>', methods=['GET'])
def get_address_transactions(address):
    """Restituisce tutte le transazioni di un indirizzo"""
    transactions = []
    
    for block in blockchain.chain:
        for tx in block['transactions']:
            if tx['from'] == address or tx['to'] == address:
                transactions.append({
                    'block_index': block['index'],
                    'transaction': tx,
                    'timestamp': block['timestamp']
                })
    
    return jsonify({'address': address, 'transactions': transactions}), 200

@app.route('/api/mining/stats', methods=['GET'])
def get_mining_stats():
    """Restituisce statistiche mining"""
    stats = blockchain.get_blockchain_info()
    return jsonify(stats), 200

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check del server"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'blockchain_length': len(blockchain.chain),
        'total_mined': blockchain.total_mined,
        'max_supply': blockchain.max_supply,
        'remaining_supply': blockchain.max_supply - blockchain.total_mined,
        'difficulty': blockchain.difficulty,
        'websockets_clients': len(socketio.server.manager.rooms.get('/', {}))
    }), 200

def start_server(host='192.168.1.56', port=5000):
    """Avvia il server blockchain"""
    print(f"🚀 Starting Novara Blockchain Server on {host}:{port}")
    print("🔌 WebSockets ATTIVI - Aggiornamenti in tempo reale!")
    print("⛏️  MINING REALE ATTIVO - Difficoltà: 6 (MOLTO ALTA)")
    print("📡 Available Endpoints:")
    print(f"   GET  http://{host}:{port}/api/info")
    print(f"   GET  http://{host}:{port}/api/chain") 
    print(f"   POST http://{host}:{port}/api/transactions/new")
    print(f"   POST http://{host}:{port}/api/mine")
    print(f"   GET  http://{host}:{port}/api/balance/<address>")
    print(f"   GET  http://{host}:{port}/api/transactions/<address>")
    print(f"   GET  http://{host}:{port}/api/mining/stats")
    print(f"   GET  http://{host}:{port}/api/health")
    print(f"\n💰 Max Supply: {blockchain.max_supply} NVR - ULTRA RARI!")
    print(f"⛏️ Current Supply: {blockchain.total_mined} NVR")
    print(f"🎯 Difficulty: {blockchain.difficulty} (REALE E DIFFICILE!)")
    print(f"💎 Mining Reward: {blockchain.mining_reward} NVR per block")
    print(f"📊 Genesis: 100 NVR allocated to foundation")
    
    socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)

if __name__ == '__main__':
    start_server(host='192.168.1.56', port=5000)
