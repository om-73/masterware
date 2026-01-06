import math
import hashlib
import os

# Try importing pefile, handle error if not installed (though we installed it)
try:
    import pefile
except ImportError:
    pefile = None

SUSPICIOUS_IMPORTS = [
    b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread",
    b"ShellExecute", b"OpenProcess", b"GetProcAddress",
    b"LoadLibrary", b"InternetOpen", b"UrlDownloadToFile"
]

def get_entropy(file_path):
    """Calculates Shannon Entropy of a file. High entropy (>7) indicates packing/encryption."""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    if not data:
        return 0
        
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_pe(file_path):
    """Analyzes a PE file for suspicious imports/sections using pefile."""
    results = {
        "suspicious_imports": [],
        "sections": [],
        "is_pe": False
    }

    if not pefile:
        return results

    try:
        pe = pefile.PE(file_path)
        results["is_pe"] = True
        
        # Check Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name in SUSPICIOUS_IMPORTS:
                        results["suspicious_imports"].append(imp.name.decode('utf-8', 'ignore'))
        
        # Check Sections for high entropy
        for section in pe.sections:
            results["sections"].append({
                "name": section.Name.decode('utf-8', 'ignore').strip('\x00'),
                "entropy": section.get_entropy()
            })
            
    except pefile.PEFormatError:
        pass # Not a PE file
    except Exception as e:
        print(f"PE Analysis Error: {e}")

    return results

def analyze_local(file_path, file_name):
    """Runs all local analysis heuristics."""
    
    score = 0
    report = {
        "score": 0,
        "details": [],
        "risk": "Safe"
    }
    
    # 1. Entropy Check (Ransomware/Packed)
    # Entropy > 7.0 is very high (compressed or encrypted)
    entropy = get_entropy(file_path)
    report['entropy'] = round(entropy, 2)
    if entropy > 7.2:
        score += 40
        report['details'].append(f"High Entropy ({entropy:.2f}): Possible Ransomware or Packed Code.")
    elif entropy > 6.5:
        score += 15
        report['details'].append(f"Elevated Entropy ({entropy:.2f}): Possible Compression.")

    # 2. Extension Check (Double extensions etc)
    lower_name = file_name.lower()
    suspicious_exts = ['.exe', '.dll', '.bat', '.scr', '.vbs', '.js']
    if any(lower_name.endswith(ext) for ext in suspicious_exts):
        score += 10
        report['details'].append(f"Executable/Script Extension detected: {os.path.splitext(lower_name)[1]}")
    
    # Check for double extensions like "invoice.pdf.exe"
    parts = lower_name.split('.')
    if len(parts) > 2 and f".{parts[-1]}" in suspicious_exts:
        score += 30
        report['details'].append("Double Extension Anomaly detected (e.g. file.pdf.exe)")

    # 3. PE Analysis
    if pefile:
        pe_data = analyze_pe(file_path)
        if pe_data['is_pe']:
            score += 5 # Base score for being an executable
            
            # Imports
            if len(pe_data['suspicious_imports']) > 0:
                count = len(pe_data['suspicious_imports'])
                added = min(count * 10, 50) # Cap at 50
                score += added
                top_imps = ", ".join(pe_data['suspicious_imports'][:3])
                report['details'].append(f"Suspicious API Imports ({count}): {top_imps}...")
                
            # Section Entropy
            for section in pe_data['sections']:
                if section['entropy'] > 7.4:
                    score += 20
                    report['details'].append(f"Packed PE Section '{section['name']}' (Entropy: {section['entropy']:.2f})")
    
    # Finalize Risk
    report['score'] = min(score, 100)
    if score > 75:
        report['risk'] = "Critical"
    elif score > 40:
        report['risk'] = "Suspicious"
    else:
        report['risk'] = "Safe"
        
    return report
