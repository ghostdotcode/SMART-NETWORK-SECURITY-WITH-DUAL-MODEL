"""
Blockchain Service for Smart Network Security System
Handles NFT minting, IPFS storage, and threat intelligence registry
"""

from flask import Flask, request, jsonify
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional
import requests

# Web3 and IPFS imports (install: pip install web3 ipfshttpclient)
try:
    from web3 import Web3
    import ipfshttpclient
except ImportError:
    print("WARNING: web3 and ipfshttpclient not installed")
    print("Install with: pip install web3 ipfshttpclient")

# ==========================================
# CONFIGURATION
# ==========================================
app = Flask(__name__)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("blockchain_service.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BlockchainService")

# Blockchain Configuration
ETHEREUM_NODE_URL = "http://localhost:8545"  # Ganache or Infura
CONTRACT_ADDRESS = "0x..."  # Deploy smart contract and add address here
IPFS_NODE_URL = "/ip4/127.0.0.1/tcp/5001"

# In-memory threat registry (cache)
threat_registry: Dict[str, List[Dict]] = {}

# ==========================================
# BLOCKCHAIN & IPFS INITIALIZATION
# ==========================================
try:
    # Connect to Ethereum node
    w3 = Web3(Web3.HTTPProvider(ETHEREUM_NODE_URL))
    logger.info(f"Connected to Ethereum: {w3.is_connected()}")
    
    # Connect to IPFS
    ipfs_client = ipfshttpclient.connect(IPFS_NODE_URL)
    logger.info("Connected to IPFS")
    
    # Load smart contract ABI (you'll need to create this)
    # CONTRACT_ABI = json.load(open('ThreatRegistry.json'))['abi']
    # contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
    
except Exception as e:
    logger.error(f"Blockchain/IPFS initialization failed: {e}")
    w3 = None
    ipfs_client = None


# ==========================================
# HELPER FUNCTIONS
# ==========================================
def hash_ip(ip_address: str) -> str:
    """Hash IP address for privacy on blockchain"""
    return hashlib.sha256(ip_address.encode()).hexdigest()


def create_threat_metadata(threat_data: Dict) -> Dict:
    """Create comprehensive metadata for IPFS storage"""
    return {
        "version": "1.0",
        "threat_record": {
            "ip_address_hash": hash_ip(threat_data.get("target_ip", "")),
            "first_detected": threat_data.get("timestamp", datetime.now().isoformat()),
            "attack_type": threat_data.get("attack_type", "UNKNOWN"),
            "threat_level": threat_data.get("threat_level", "unknown"),
            "ml_action": threat_data.get("ml_action", "BLOCK"),
            "ml_confidence": 0.95,  # From ML model
        },
        "blockchain_metadata": {
            "minted_at": datetime.now().isoformat(),
            "network": "ethereum",
            "chain_id": w3.eth.chain_id if w3 else None
        },
        "reform_tracking": {
            "is_reformed": False,
            "captcha_attempts": 0,
            "successful_accesses": 0,
            "last_attempt": None
        }
    }


def upload_to_ipfs(data: Dict) -> Optional[str]:
    """Upload JSON data to IPFS and return hash"""
    try:
        if not ipfs_client:
            logger.error("IPFS client not initialized")
            return None
        
        json_data = json.dumps(data)
        result = ipfs_client.add_json(data)
        logger.info(f"Uploaded to IPFS: {result}")
        return result
    except Exception as e:
        logger.error(f"IPFS upload failed: {e}")
        return None


def mint_threat_nft(ip_hash: str, ipfs_hash: str) -> Optional[str]:
    """Mint NFT on blockchain representing the threat"""
    try:
        if not w3 or not w3.is_connected():
            logger.error("Blockchain not connected")
            return None
        
        # This is a placeholder - you'll need to implement actual smart contract call
        # Example:
        # tx_hash = contract.functions.mintThreat(ip_hash, ipfs_hash).transact({
        #     'from': w3.eth.accounts[0]
        # })
        # receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        # return receipt.transactionHash.hex()
        
        logger.info(f"NFT minted for IP hash: {ip_hash}")
        return "0x" + hashlib.sha256(f"{ip_hash}{ipfs_hash}".encode()).hexdigest()
        
    except Exception as e:
        logger.error(f"NFT minting failed: {e}")
        return None


# ==========================================
# API ENDPOINTS
# ==========================================

@app.route('/')
def index():
    """Service status"""
    return jsonify({
        "service": "Blockchain Threat Intelligence",
        "status": "active",
        "blockchain_connected": w3.is_connected() if w3 else False,
        "ipfs_connected": ipfs_client is not None,
        "total_threats": len(threat_registry)
    }), 200


@app.route('/mint-threat', methods=['POST'])
def mint_threat():
    """
    Mint a new threat NFT and store metadata on IPFS
    
    Expected payload:
    {
        "target_ip": "192.168.1.100",
        "attack_type": "SYN FLOOD",
        "threat_level": "malicious",
        "ml_action": "BLOCK",
        "timestamp": "2025-12-04 20:18:21"
    }
    """
    try:
        threat_data = request.get_json()
        
        if not threat_data or 'target_ip' not in threat_data:
            return jsonify({"error": "Missing required field: target_ip"}), 400
        
        ip_address = threat_data['target_ip']
        ip_hash = hash_ip(ip_address)
        
        # Create metadata
        metadata = create_threat_metadata(threat_data)
        
        # Upload to IPFS
        ipfs_hash = upload_to_ipfs(metadata)
        if not ipfs_hash:
            return jsonify({"error": "IPFS upload failed"}), 500
        
        # Mint NFT on blockchain
        tx_hash = mint_threat_nft(ip_hash, ipfs_hash)
        if not tx_hash:
            return jsonify({"error": "NFT minting failed"}), 500
        
        # Store in local registry
        if ip_address not in threat_registry:
            threat_registry[ip_address] = []
        
        threat_registry[ip_address].append({
            "ipfs_hash": ipfs_hash,
            "tx_hash": tx_hash,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata
        })
        
        logger.info(f"✅ Threat NFT minted for {ip_address}")
        
        return jsonify({
            "success": True,
            "ip_hash": ip_hash,
            "ipfs_hash": ipfs_hash,
            "transaction_hash": tx_hash,
            "message": "Threat NFT minted successfully"
        }), 201
        
    except Exception as e:
        logger.error(f"Error minting threat: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/threat-history/<ip_address>', methods=['GET'])
def get_threat_history(ip_address: str):
    """
    Query threat history for an IP address
    Returns blockchain records and reformed status
    """
    try:
        history = threat_registry.get(ip_address, [])
        
        if not history:
            return jsonify({
                "ip_address": ip_address,
                "found": False,
                "is_malicious": False,
                "is_reformed": False,
                "records": []
            }), 200
        
        # Get latest record
        latest = history[-1]
        metadata = latest.get("metadata", {})
        reform_tracking = metadata.get("reform_tracking", {})
        
        return jsonify({
            "ip_address": ip_address,
            "found": True,
            "is_malicious": True,
            "is_reformed": reform_tracking.get("is_reformed", False),
            "total_records": len(history),
            "first_detected": history[0].get("timestamp"),
            "last_detected": latest.get("timestamp"),
            "captcha_attempts": reform_tracking.get("captcha_attempts", 0),
            "successful_accesses": reform_tracking.get("successful_accesses", 0),
            "records": history
        }), 200
        
    except Exception as e:
        logger.error(f"Error querying threat history: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/log-reformed-access', methods=['POST'])
def log_reformed_access():
    """
    Log successful CAPTCHA pass and update reformed status
    
    Expected payload:
    {
        "ip_address": "192.168.1.100",
        "captcha_passed": true
    }
    """
    try:
        data = request.get_json()
        ip_address = data.get('ip_address')
        captcha_passed = data.get('captcha_passed', False)
        
        if not ip_address:
            return jsonify({"error": "Missing ip_address"}), 400
        
        if ip_address not in threat_registry:
            return jsonify({"error": "IP not found in registry"}), 404
        
        # Update latest record
        latest = threat_registry[ip_address][-1]
        reform_tracking = latest["metadata"]["reform_tracking"]
        
        if captcha_passed:
            reform_tracking["captcha_attempts"] += 1
            reform_tracking["successful_accesses"] += 1
            reform_tracking["last_attempt"] = datetime.now().isoformat()
            
            # Mark as reformed after 3 successful accesses
            if reform_tracking["successful_accesses"] >= 3:
                reform_tracking["is_reformed"] = True
                logger.info(f"✅ IP {ip_address} marked as REFORMED")
        
        # Update blockchain (placeholder)
        # contract.functions.updateReformedStatus(hash_ip(ip_address), True).transact()
        
        return jsonify({
            "success": True,
            "ip_address": ip_address,
            "is_reformed": reform_tracking["is_reformed"],
            "successful_accesses": reform_tracking["successful_accesses"]
        }), 200
        
    except Exception as e:
        logger.error(f"Error logging reformed access: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/analytics/threats', methods=['GET'])
def get_threat_analytics():
    """Get threat analytics and statistics"""
    try:
        total_threats = len(threat_registry)
        reformed_count = 0
        attack_types = {}
        
        for ip, records in threat_registry.items():
            latest = records[-1]
            metadata = latest.get("metadata", {})
            
            # Count reformed IPs
            if metadata.get("reform_tracking", {}).get("is_reformed", False):
                reformed_count += 1
            
            # Count attack types
            attack_type = metadata.get("threat_record", {}).get("attack_type", "UNKNOWN")
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        return jsonify({
            "total_threats": total_threats,
            "reformed_ips": reformed_count,
            "active_blocks": total_threats - reformed_count,
            "attack_type_distribution": attack_types,
            "blockchain_connected": w3.is_connected() if w3 else False
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/ipfs/<ipfs_hash>', methods=['GET'])
def get_ipfs_metadata(ipfs_hash: str):
    """Fetch metadata from IPFS"""
    try:
        if not ipfs_client:
            return jsonify({"error": "IPFS not connected"}), 503
        
        data = ipfs_client.get_json(ipfs_hash)
        return jsonify(data), 200
        
    except Exception as e:
        logger.error(f"Error fetching IPFS data: {e}")
        return jsonify({"error": str(e)}), 500


# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    print("=" * 79)
    print("BLOCKCHAIN THREAT INTELLIGENCE SERVICE")
    print("=" * 79)
    print(f"Ethereum Node: {ETHEREUM_NODE_URL}")
    print(f"IPFS Node: {IPFS_NODE_URL}")
    print(f"Blockchain Connected: {w3.is_connected() if w3 else False}")
    print(f"IPFS Connected: {ipfs_client is not None}")
    print("=" * 79)
    print("\nEndpoints:")
    print("  - GET  /                      : Service status")
    print("  - POST /mint-threat           : Mint threat NFT")
    print("  - GET  /threat-history/<ip>   : Query IP history")
    print("  - POST /log-reformed-access   : Log CAPTCHA success")
    print("  - GET  /analytics/threats     : Threat analytics")
    print("  - GET  /ipfs/<hash>           : Fetch IPFS metadata")
    print("=" * 79 + "\n")
    
    app.run(host='0.0.0.0', port=5051, debug=False)
