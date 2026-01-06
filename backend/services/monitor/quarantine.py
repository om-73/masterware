import os
import shutil
import time
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
MANIFEST_FILE = os.path.join(QUARANTINE_DIR, "manifest.json")

XOR_KEY = 0x5A # Simple single-byte XOR key for obfuscation

def load_manifest():
    if os.path.exists(MANIFEST_FILE):
        try:
            with open(MANIFEST_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_manifest(data):
    with open(MANIFEST_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def xor_file(input_path, output_path):
    """Obfuscate/De-obfuscate file content using XOR."""
    with open(input_path, 'rb') as fin:
        data = bytearray(fin.read())
    
    for i in range(len(data)):
        data[i] ^= XOR_KEY
        
    with open(output_path, 'wb') as fout:
        fout.write(data)

def quarantine_file(file_path, original_name, risk_level):
    """Moves a file to quarantine with XOR encryption."""
    if not os.path.exists(file_path):
        return False, "File not found"

    # Create unique ID for quarantine
    q_id = f"{int(time.time())}_{original_name}"
    q_path = os.path.join(QUARANTINE_DIR, q_id + ".bin")
    
    try:
        # Encrypt and move
        xor_file(file_path, q_path)
        os.remove(file_path) # Delete original
        
        # Update manifest
        manifest = load_manifest()
        manifest[q_id] = {
            "original_name": original_name,
            "original_path": file_path, # In a real app we might store origin
            "risk": risk_level,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        save_manifest(manifest)
        return True, "File quarantined and encrypted."
    except Exception as e:
        return False, str(e)

def restore_file(q_id, restore_dir="uploads"):
    """Restores a file from quarantine."""
    manifest = load_manifest()
    if q_id not in manifest:
        return False, "Item not found in manifest"
        
    info = manifest[q_id]
    q_path = os.path.join(QUARANTINE_DIR, q_id + ".bin")
    
    if not os.path.exists(q_path):
        return False, "Quarantined file binary missing"
        
    # Restore to specified dir or original path? 
    # For safety, let's restore to 'uploads' or 'restored' folder
    os.makedirs(restore_dir, exist_ok=True)
    target_path = os.path.join(restore_dir, info['original_name'])
    
    try:
        xor_file(q_path, target_path)
        
        # Remove from quarantine
        os.remove(q_path)
        del manifest[q_id]
        save_manifest(manifest)
        
        return True, f"Restored to {target_path}"
    except Exception as e:
        return False, str(e)

def delete_quarantine(q_id):
    """Permanently deletes a quarantined item."""
    manifest = load_manifest()
    if q_id in manifest:
        q_path = os.path.join(QUARANTINE_DIR, q_id + ".bin")
        if os.path.exists(q_path):
            os.remove(q_path)
        del manifest[q_id]
        save_manifest(manifest)
        return True
    return False

def get_quarantine_list():
    manifest = load_manifest()
    # Convert dict to list
    items = []
    for qid, info in manifest.items():
        info['id'] = qid
        items.append(info)
    return items
