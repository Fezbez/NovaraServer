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
import os
import atexit

# MongoDB IMPORTS
try:
    from pymongo import MongoClient
    import certifi
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False
    print("⚠️ PyMongo not available, using SQLite fallback")

# EVENTLET FOR RENDER
import eventlet
eventlet.monkey_patch()

app = Flask(__name__)
CORS(app)
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='eventlet',
    logger=True,
    engineio_logger=False
)

class NovaraBlockchainServer:
    def __init__(self, socketio):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 5
        self.mining_reward = 10
        self.max_supply = 1000
        self.total_mined = 0
        self.socketio = socketio
        
        # Mining control
        self.mining_in_progress = False
        self.current_miner = None
        
        # Database setup
        self.setup_database()
        self.load_blockchain()
        
        if not self.chain:
            self.create_genesis_block()
            self.save_blockchain()
        
        self.calculate_total_mined()
        atexit.register(self.backup_on_exit)
        
        print("🚀 Novara Blockchain Server Ready!")
        print(f"💰 Total Mined: {self.total_mined}/{self.max_supply} NVR")
        print(f"💾 Database: {'MongoDB Atlas' if self.use_mongodb else 'SQLite in Memory'}")

    def setup_database(self):
        """Setup database with MongoDB priority"""
        self.mongo_uri = os.environ.get('MONGODB_URI')
        
        if self.mongo_uri and MONGODB_AVAILABLE:
            try:
                print("🔗 Connecting to MongoDB Atlas...")
                self.client = MongoClient(self.mongo_uri, tlsCAFile=certifi.where())
                self.client.admin.command('ping')  # Test connection
                
                self.db = self.client.novara_blockchain
                self.blocks_collection = self.db.blocks
                self.pending_tx_collection = self.db.pending_transactions
                self.stats_collection = self.db.stats
                
                self.use_mongodb = True
                print("✅ Connected to MongoDB Atlas!")
                return
                
            except Exception as e:
                print(f"❌ MongoDB connection failed: {e}")
        
        # Fallback to SQLite
        print("🔄 Using SQLite in-memory fallback")
        self.use_mongodb = False
        self.db_path = ":memory:"
        self.init_sqlite_database()

    def init_sqlite_database(self):
        """Initialize SQLite database"""
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
        
        conn.commit()
        conn.close()

    def load_blockchain(self):
        """Load blockchain from active database"""
        if self.use_mongodb:
            self.load_from_mongodb()
        else:
            self.load_from_sqlite()

    def load_from_mongodb(self):
        """Load blockchain from MongoDB"""
        try:
            print("📦 Loading blockchain from MongoDB...")
            
            # Load blocks sorted by index
            blocks_data = list(self.blocks_collection.find().sort("index", 1))
            self.chain = []
            
            for block_data in blocks_data:
                block = {
                    'index': block_data['index'],
                    'transactions': block_data['transactions'],
                    'timestamp': block_data['timestamp'],
                    'previous_hash': block_data['previous_hash'],
                    'hash': block_data['hash'],
                    'nonce': block_data['nonce'],
                    'mining_time': block_data.get('mining_time', 0),
                    'attempts': block_data.get('attempts', 0)
                }
                self.chain.append(block)
            
            # Load pending transactions
            pending_data = list(self.pending_tx_collection.find())
            self.pending_transactions = []
            
            for tx_data in pending_data:
                transaction = {
                    'from': tx_data['from_address'],
                    'to': tx_data['to_address'],
                    'amount': tx_data['amount'],
                    'signature': tx_data['signature'],
                    'public_key': tx_data['public_key'],
                    'transaction_id': tx_data['transaction_id'],
                    'timestamp': tx_data['timestamp']
                }
                self.pending_transactions.append(transaction)
            
            print(f"✅ Loaded {len(self.chain)} blocks and {len(self.pending_transactions)} pending transactions")
            
        except Exception as e:
            print(f"❌ Error loading from MongoDB: {e}")
            self.chain = []
            self.pending_transactions = []

    def load_from_sqlite(self):
        """Load blockchain from SQLite"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM blocks ORDER BY block_index')
            blocks_data = cursor.fetchall()
            
            if not blocks_data:
                return
            
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
            
            conn.close()
            print(f"📦 SQLite: {len(self.chain)} blocks, {len(self.pending_transactions)} pending transactions")
            
        except Exception as e:
            print(f"❌ Error loading from SQLite: {e}")

    def save_blockchain(self):
        """Save blockchain to active database"""
        if self.use_mongodb:
            self.save_to_mongodb()
        else:
            self.save_to_sqlite()

    def save_to_mongodb(self):
        """Save blockchain to MongoDB"""
        try:
            # Save blocks
            if self.chain:
                self.blocks_collection.delete_many({})
                
                blocks_to_insert = []
                for block in self.chain:
                    block_data = {
                        'index': block['index'],
                        'transactions': block['transactions'],
                        'timestamp': block['timestamp'],
                        'previous_hash': block['previous_hash'],
                        'hash': block['hash'],
                        'nonce': block['nonce'],
                        'mining_time': block.get('mining_time', 0),
                        'attempts': block.get('attempts', 0),
                        'last_updated': datetime.now().isoformat()
                    }
                    blocks_to_insert.append(block_data)
                
                self.blocks_collection.insert_many(blocks_to_insert)
            
            # Save pending transactions
            if self.pending_transactions:
                self.pending_tx_collection.delete_many({})
                
                pending_to_insert = []
                for tx in self.pending_transactions:
                    tx_data = {
                        'from_address': tx['from'],
                        'to_address': tx['to'],
                        'amount': tx['amount'],
                        'signature': tx['signature'],
                        'public_key': tx['public_key'],
                        'transaction_id': tx['transaction_id'],
                        'timestamp': tx['timestamp'],
                        'last_updated': datetime.now().isoformat()
                    }
                    pending_to_insert.append(tx_data)
                
                self.pending_tx_collection.insert_many(pending_to_insert)
            
            # Save stats
            self.stats_collection.delete_many({})
            self.stats_collection.insert_one({
                'total_mined': self.total_mined,
                'max_supply': self.max_supply,
                'last_update': datetime.now().isoformat(),
                'chain_length': len(self.chain),
                'pending_count': len(self.pending_transactions)
            })
            
            print("💾 Blockchain saved to MongoDB Atlas")
            
        except Exception as e:
            print(f"❌ Error saving to MongoDB: {e}")

    def save_to_sqlite(self):
        """Save blockchain to SQLite"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Clear tables
            cursor.execute('DELETE FROM blocks')
            cursor.execute('DELETE FROM pending_transactions')
            
            # Save blocks
            for block in self.chain:
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
            
            # Save pending transactions
            for tx in self.pending_transactions:
                cursor.execute('''
                    INSERT INTO pending_transactions (from_address, to_address, amount, signature, public_key, transaction_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    tx['from'],
                    tx['to'],
                    tx['amount'],
                    tx['signature'],
                    tx['public_key'],
                    tx['transaction_id'],
                    tx['timestamp']
                ))
            
            conn.commit()
            conn.close()
            
            print("💾 Blockchain saved to SQLite")
            
        except Exception as e:
            print(f"❌ Error saving to SQLite: {e}")

    def backup_on_exit(self):
        """Automatic backup on exit"""
        print("💾 Automatic blockchain backup...")
        self.save_blockchain()

    def calculate_total_mined(self):
        """Calculate total NVR mined"""
        self.total_mined = 0
        for block in self.chain:
            for tx in block['transactions']:
                if tx['from'] == 'NETWORK' and tx.get('type') in ['mining_reward', 'genesis']:
                    self.total_mined += tx['amount']

    def create_genesis_block(self):
        """Create genesis block with 100 NVR for foundation"""
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

    def generate_bitcoin_address(self, public_key_bytes):
        """Generate Bitcoin-style address from public key"""
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        versioned_payload = b'\x00' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        binary_address = versioned_payload + checksum
        
        return base58.b58encode(binary_address).decode('ascii')

    def verify_transaction_signature(self, transaction_data):
        """Verify ECDSA transaction signature"""
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

    def get_balance(self, address):
        """Calculate balance - ONLY from confirmed transactions"""
        balance = 0.0
        
        print(f"🔍 Calculating balance for: {address}")
        
        # ONLY confirmed transactions in blocks
        for block_index, block in enumerate(self.chain):
            for tx_index, tx in enumerate(block['transactions']):
                # DEBUG: Log relevant transactions
                if tx['to'] == address or tx['from'] == address:
                    print(f"   Block {block_index}, TX {tx_index}: {tx['from'][:8]}... → {tx['to'][:8]}... : {tx['amount']} NVR")
                
                # Add if you are recipient
                if tx['to'] == address:
                    balance += tx['amount']
                    print(f"   +{tx['amount']} NVR (received)")
                
                # Subtract only if you are sender AND not a reward
                if (tx['from'] == address and 
                    tx.get('type') not in ['mining_reward', 'genesis'] and
                    tx['from'] != 'NETWORK'):
                    balance -= tx['amount']
                    print(f"   -{tx['amount']} NVR (sent)")
        
        print(f"💰 Final balance for {address}: {balance} NVR")
        
        return round(max(0, balance), 6)

    def get_effective_balance(self, address):
        """Balance for transaction validation (includes pending outgoing)"""
        confirmed_balance = self.get_balance(address)
        
        # Calculate pending outgoing transactions
        pending_outgoing = 0
        for tx in self.pending_transactions:
            if tx['from'] == address:
                pending_outgoing += tx['amount']
                print(f"⚠️ Pending transaction: -{tx['amount']} NVR waiting confirmation")
        
        effective_balance = max(0, confirmed_balance - pending_outgoing)
        print(f"🎯 Effective balance for {address}: {effective_balance} NVR (confirmed: {confirmed_balance} NVR)")
        
        return effective_balance

    def add_transaction(self, transaction_data):
        """Add transaction with signature verification - NO FEES"""
        print(f"🎯 New transaction received:")
        print(f"   From: {transaction_data['from']}")
        print(f"   To: {transaction_data['to']}")
        print(f"   Amount: {transaction_data['amount']} NVR")
        
        required = ['from', 'to', 'amount', 'signature', 'public_key', 'timestamp']
        if not all(k in transaction_data for k in required):
            return False, "Missing required fields"
        
        if transaction_data['amount'] <= 0:
            return False, "Invalid amount"
        
        # Verify ECDSA signature
        is_valid, sig_message = self.verify_transaction_signature(transaction_data)
        if not is_valid:
            return False, f"Invalid transaction signature: {sig_message}"
        
        # Check sender balance
        sender_balance = self.get_effective_balance(transaction_data['from'])
        print(f"   Sender available balance: {sender_balance} NVR")
        
        if sender_balance < transaction_data['amount']:
            error_msg = f"Insufficient funds: {sender_balance} NVR available, need {transaction_data['amount']} NVR"
            print(f"❌ {error_msg}")
            return False, error_msg
        
        # Generate transaction ID
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
        
        # WebSocket notification
        self.socketio.emit('blockchain_update', {
            'type': 'new_transaction',
            'from': transaction_data['from'][:8] + '...',
            'to': transaction_data['to'][:8] + '...', 
            'amount': transaction_data['amount'],
            'transaction_id': tx_id
        })
        
        print(f"✅ Transaction verified: {tx_id}")
        return True, f"Transaction added: {tx_id}"

    def save_pending_transaction(self, transaction):
        """Save pending transaction to database"""
        if self.use_mongodb:
            try:
                tx_data = {
                    'from_address': transaction['from'],
                    'to_address': transaction['to'],
                    'amount': transaction['amount'],
                    'signature': transaction['signature'],
                    'public_key': transaction['public_key'],
                    'transaction_id': transaction['transaction_id'],
                    'timestamp': transaction['timestamp'],
                    'created_at': datetime.now().isoformat()
                }
                self.pending_tx_collection.insert_one(tx_data)
            except Exception as e:
                print(f"❌ Error saving transaction to MongoDB: {e}")
        else:
            self.save_pending_transaction_sqlite(transaction)

    def save_pending_transaction_sqlite(self, transaction):
        """Save pending transaction to SQLite"""
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

    def save_block_to_db(self, block):
        """Save single block to database"""
        if self.use_mongodb:
            try:
                block_data = {
                    'index': block['index'],
                    'transactions': block['transactions'],
                    'timestamp': block['timestamp'],
                    'previous_hash': block['previous_hash'],
                    'hash': block['hash'],
                    'nonce': block['nonce'],
                    'mining_time': block.get('mining_time', 0),
                    'attempts': block.get('attempts', 0),
                    'created_at': datetime.now().isoformat()
                }
                self.blocks_collection.insert_one(block_data)
            except Exception as e:
                print(f"❌ Error saving block to MongoDB: {e}")
        else:
            self.save_block_to_sqlite(block)

    def save_block_to_sqlite(self, block):
        """Save block to SQLite"""
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

    def clear_pending_db(self):
        """Clear pending transactions from database"""
        if self.use_mongodb:
            try:
                self.pending_tx_collection.delete_many({})
            except Exception as e:
                print(f"❌ Error clearing pending transactions from MongoDB: {e}")
        else:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM pending_transactions')
            conn.commit()
            conn.close()

    def get_blockchain_info(self):
        """Get blockchain information"""
        valid_pending = len([tx for tx in self.pending_transactions if tx['from'] != 'NETWORK'])
        remaining_supply = max(0, self.max_supply - self.total_mined)
        
        # Calculate average hash rate
        avg_hash_rate = 0
        mining_blocks = [b for b in self.chain if b.get('mining_time', 0) > 0]
        if mining_blocks:
            total_attempts = sum(b.get('attempts', 0) for b in mining_blocks)
            total_time = sum(b.get('mining_time', 0) for b in mining_blocks)
            if total_time > 0:
                avg_hash_rate = total_attempts / total_time
        
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
            'avg_hash_rate': avg_hash_rate,
            'total_mining_attempts': sum(b.get('attempts', 0) for b in self.chain),
            'total_mining_time': sum(b.get('mining_time', 0) for b in self.chain),
            'mining_in_progress': self.mining_in_progress,
            'current_miner': self.current_miner,
            'database_type': 'mongodb' if self.use_mongodb else 'sqlite'
        }

# Initialize blockchain
blockchain = NovaraBlockchainServer(socketio)

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    print(f"🔌 Client WebSocket connected: {request.sid}")
    emit('blockchain_update', {'type': 'connected', 'message': 'Welcome to Novara Coin!'})

@socketio.on('disconnect')
def handle_disconnect():
    print(f"❌ Client WebSocket disconnected: {request.sid}")

# API ROUTES
@app.route('/')
def home():
    """Home page with API information"""
    return jsonify({
        'message': 'Novara Coin Blockchain API',
        'version': '1.0',
        'database': 'MongoDB Atlas' if blockchain.use_mongodb else 'SQLite in Memory',
        'endpoints': {
            'GET /api/info': 'Blockchain information',
            'GET /api/chain': 'Full blockchain',
            'POST /api/transactions/new': 'Create new transaction',
            'GET /api/balance/<address>': 'Get address balance',
            'GET /api/transactions/<address>': 'Get address transactions',
            'GET /health': 'Health check'
        }
    })

@app.route('/api/info', methods=['GET'])
def get_info():
    """Get blockchain info"""
    info = blockchain.get_blockchain_info()
    return jsonify(info), 200

@app.route('/api/chain', methods=['GET'])
def get_chain():
    """Get full blockchain"""
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }), 200

@app.route('/api/transactions/new', methods=['POST'])
def new_transaction():
    """Add new transaction - NO FEES"""
    values = request.get_json()
    success, message = blockchain.add_transaction(values)
    
    if success:
        return jsonify({
            'message': message,
            'transaction_id': values.get('transaction_id', 'unknown')
        }), 201
    else:
        return jsonify({'error': message}), 400

@app.route('/api/balance/<address>', methods=['GET'])
def get_balance(address):
    """Get address balance - NO FEES"""
    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/api/transactions/<address>', methods=['GET'])
def get_address_transactions(address):
    """Get all transactions for an address"""
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

@app.route('/health', methods=['GET'])
def health_check():
    """Health check for Render"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'blockchain_length': len(blockchain.chain),
        'total_mined': blockchain.total_mined,
        'max_supply': blockchain.max_supply,
        'database': 'mongodb' if blockchain.use_mongodb else 'sqlite',
        'pending_transactions': len(blockchain.pending_transactions)
    }), 200

# Error handlers
@socketio.on_error_default
def default_error_handler(e):
    """Default WebSocket error handler"""
    print(f"WebSocket error: {e}")
    return {"error": "Internal server error"}

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def start_server():
    """Start server for Render.com"""
    port = int(os.environ.get('PORT', 5000))
    host = '0.0.0.0'
    
    print(f"🚀 Starting Novara Blockchain Server on port {port}")
    print(f"🌐 Server URL: http://{host}:{port}")
    print(f"💾 Database: {'MongoDB Atlas' if blockchain.use_mongodb else 'SQLite in Memory'}")
    print("🔌 WebSockets: ACTIVE")
    print("💰 Novara Coin - PERSISTENT Blockchain!")
    
    socketio.run(
        app,
        host=host,
        port=port,
        debug=False,
        log_output=True,
        allow_unsafe_werkzeug=True
    )

if __name__ == '__main__':
    start_server()
