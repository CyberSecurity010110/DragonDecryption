import os
import subprocess
import hashlib
import math
import datetime
import json
import re
import stat
import platform

# --- Configuration ---
SCAN_DIR = os.getcwd()
LOG_FILE = os.path.join(SCAN_DIR, "security_analysis.log")
CONFIG_FILE = os.path.join(SCAN_DIR, "config.json")

# Load configuration from JSON file
def load_config():
    default_config = {
        "decryption_keys": ["testkey", "secret", "password"],
        "ciphers": ["aes-256-cbc", "aes-128-cbc", "des3"],
        "encryption_signatures": ["-----BEGIN PGP MESSAGE-----", "Encrypted with AES-256"],
        "known_checksums": {},
        "entropy_threshold": 7.0,
        "max_xxd_output": 1000,
        "enable_file_extraction": True,
        "enable_executable_check": True,
        "enable_checksum_verification": True,
        "enable_binwalk": True,
        "enable_yara": True,
        "yara_rules_dir": os.path.join(SCAN_DIR, "yara_rules"),
        "max_file_size_analyze": 52428800,  # 50 MB
        "report_suspicious_strings": True,
        "suspicious_string_patterns": [r"eval\(.*\)", r"base64_decode\(.*\)", r"shell_exec\(.*\)", r"system\(.*\)", r"passthru\(.*\)", r"exec\(.*\)", r"phpinfo\(\)"],
        "known_file_extensions": [".exe", ".dll", ".so", ".py", ".sh", ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx"],
        "enable_signature_validation": True,
        "trusted_signatures": {
            "exe": [],
            "dll": []
        },
        "attempt_readonly_handling": True,
        "delete_failed_decryption": True,
        "enable_heuristic_analysis": True,
        "suspicious_file_names": [r".*\.tmp$", r".*\.swp$"],
        "report_file_metadata": True,
        "max_string_length": 200,
        "enable_version_info": True
    }
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            # Merge loaded config with default config to ensure all keys exist
            config = {**default_config, **config}
            log_message("Configuration loaded successfully from config.json")
            return config
        except Exception as e:
            log_message(f"Error loading configuration: {e}. Using default configuration.")
            return default_config
    else:
        log_message("No config.json found. Using default configuration.")
        return default_config

config = load_config()

# --- Logging ---
def log_message(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"{timestamp} - {message}"
    print(full_message)
    with open(LOG_FILE, "a") as log:
        log.write(full_message + "\n")

# --- Helper Functions ---
def run_command(cmd, log_output=True):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if log_output:
            log_message(f"Command: {cmd}")
            log_message(f"Return Code: {result.returncode}")
            if result.stdout:
                log_message(f"Stdout: {result.stdout[:500]}")
            if result.stderr:
                log_message(f"Stderr: {result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        log_message(f"Command {cmd} timed out")
        return None
    except Exception as e:
        log_message(f"Error running command {cmd}: {e}")
        return None

def calculate_entropy(file_path, sample_size=1024):
    try:
        with open(file_path, 'rb') as f:
            data = f.read(sample_size)
        if not data:
            log_message(f"Entropy calculation: No data read from {file_path}")
            return 0
        
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        total = len(data)
        entropy = 0
        for count in freq:
            p = count / total
            if p > 0:
                entropy += -p * math.log2(p)
        
        log_message(f"Entropy calculated for {file_path}: {entropy:.2f}")
        return entropy
    except Exception as e:
        log_message(f"Error calculating entropy for {file_path}: {e}")
        return 0

def calculate_sha256(file_path):
    return calculate_checksum(file_path, "sha256")

def calculate_md5(file_path):
    return calculate_checksum(file_path, "md5")

def calculate_checksum(file_path, algorithm="sha256"):
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            while True:
                buf = f.read(4096)
                if not buf:
                    break
                hasher.update(buf)
        checksum = hasher.hexdigest()
        log_message(f"{algorithm.upper()} checksum for {file_path}: {checksum}")
        return checksum
    except Exception as e:
        log_message(f"Error calculating {algorithm.upper()} for {file_path}: {e}")
        return None

# --- File Analysis Functions ---
def analyze_file(file_path):
    try:
        file_size = os.path.getsize(file_path)
        if file_size > config["max_file_size_analyze"]:
            log_message(f"Skipping {file_path} - file size ({file_size} bytes) exceeds max limit ({config['max_file_size_analyze']} bytes)")
            return False
        
        with open(file_path, "rb") as f:
            content = f.read(1024)
        
        if any(sig.encode() in content for sig in config["encryption_signatures"]):
            log_message(f"Found encryption signature in {file_path}")
            return True
        
        if b"ENCRYPTED" in content or b"AES" in content or b"RSA" in content:
            log_message(f"Found encryption marker in {file_path}")
            return True
        
        entropy = calculate_entropy(file_path)
        if entropy > config["entropy_threshold"]:
            log_message(f"High entropy detected in {file_path}, likely encrypted")
            return True
        
        log_message(f"No encryption indicators found in {file_path}")
        return False
    except Exception as e:
        log_message(f"Error analyzing file {file_path}: {e}")
        return False

def analyze_file_content(file_path):
    log_message(f"Starting content analysis for {file_path}")
    
    # Check if file extension is in known list
    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension not in config["known_file_extensions"]:
        log_message(f"Skipping detailed content analysis for {file_path} - unknown file extension")
        return
    
    # Binwalk Analysis
    if config["enable_binwalk"]:
        log_message(f"Running Binwalk on {file_path}")
        result = run_command(["binwalk", file_path])
        if result:
            log_message(f"Binwalk results:\n{result.stdout}")
    else:
        log_message("Binwalk analysis skipped (disabled in config)")
    
    # Xxd Analysis
    log_message(f"Running Xxd on {file_path}")
    result = run_command(["xxd", file_path])
    if result:
        log_message(f"Xxd results:\n{result.stdout[:config['max_xxd_output']]}...") # Limit output
    else:
        log_message("XXD analysis failed");
    
    # YARA scan
    if config["enable_yara"]:
        yara_rules_dir = config["yara_rules_dir"]
        if os.path.exists(yara_rules_dir) and os.listdir(yara_rules_dir):
            log_message(f"Starting YARA scan on {file_path} using rules in {yara_rules_dir}")
            yara_cmd = ["yara", "-r", yara_rules_dir, file_path]
            result = run_command(yara_cmd)
            if result:
                if result.stdout:
                    log_message(f"YARA matches:\n{result.stdout}")
                else:
                    log_message("No YARA matches found")
            else:
                log_message("Error running YARA scan")
        else:
            log_message(f"YARA scan skipped - {yara_rules_dir} does not exist or is empty")
    else:
        log_message("YARA scan skipped (disabled in config)")
    
    # File Type and Extraction
    if config["enable_file_extraction"]:
        log_message(f"Checking file type for {file_path} and attempting extraction")
        file_type_result = run_command(["file", file_path], log_output=False)
        if file_type_result:
            file_info = file_type_result.stdout.lower()
            log_message(f"File type: {file_info.strip()}")
            
            extraction_cmd = None
            if "zip archive" in file_info:
                extraction_cmd = ["unzip", file_path, "-d", f"{file_path}_extracted"]
            elif "7-zip" in file_info:
                extraction_cmd = ["7z", "x", file_path, f"-o{file_path}_extracted"]
            elif "squashfs" in file_info:
                extraction_cmd = ["unsquashfs", "-d", f"{file_path}_extracted", file_path]
                
            if extraction_cmd:
                log_message(f"Attempting extraction with command: {' '.join(extraction_cmd)}")
                extract_result = run_command(extraction_cmd)
                if extract_result and extract_result.returncode == 0:
                    log_message(f"Extraction successful: {file_path} -> {file_path}_extracted")
                else:
                    log_message(f"Extraction failed: {extract_result.stderr if extract_result else 'Unknown error'}")
    else:
        log_message("File extraction skipped (disabled in config)")
    
    # Suspicious string detection
    if config["report_suspicious_strings"]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            for pattern in config["suspicious_string_patterns"]:
                matches = re.findall(pattern, content)
                if matches:
                    log_message(f"Found suspicious string(s) matching pattern '{pattern}' in {file_path}:")
                    for match in matches:
                        log_message(f"  - {match}")
        except Exception as e:
            log_message(f"Error reading {file_path} for suspicious string detection: {e}")
            
    if config["enable_signature_validation"] and file_extension in (".exe", ".dll"):
        validate_signature(file_path)
        
    if config["report_file_metadata"]:
        report_metadata(file_path)

def get_version_info(file_path):
    try:
        if platform.system() == "Windows":
            # Use PowerShell to get version info
            script = f"""
            $FileVersion = (Get-Item "{file_path}").VersionInfo.FileVersion
            if ($FileVersion) {{
                Write-Output $FileVersion
            }}
            """
            result = subprocess.run(["powershell", "-Command", script], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            else:
                log_message(f"  Could not retrieve version info using PowerShell: {result.stderr.strip()}")
                return None
        else:
            # For Linux, you can try using 'strings' command and grep for version strings
            result = run_command(["strings", file_path], log_output=False)
            if result:
                version_lines = [line for line in result.stdout.splitlines() if "Version" in line]
                if version_lines:
                    return version_lines[0]
                else:
                    log_message("  No version info found using strings command.")
                    return None
            else:
                log_message("  Failed to run strings command.")
                return None
    except Exception as e:
        log_message(f"  Error retrieving version info: {e}")
        return None

# Function to validate file signature
def validate_signature(file_path):
    try:
        log_message(f"Validating signature for {file_path}")
        
        # Check platform for signtool
        if platform.system() == "Windows":
            signtool_path = r"C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
            if not os.path.exists(signtool_path):
                log_message(f"SignTool not found at {signtool_path}. Signature validation skipped.")
                return
        else:
            log_message("Signature validation is only supported on Windows. Skipping.")
            return
        
        # Construct command
        cmd = [signtool_path, "verify", "/pa", "/v", file_path]
        result = run_command(cmd, log_output=False)
        
        if result and result.returncode == 0:
            log_message(f"Signature validation successful for {file_path}")
            # You can add further checks here to validate against trusted signers
        else:
            log_message(f"Signature validation failed for {file_path}: {result.stderr if result else 'Unknown error'}")
    except Exception as e:
        log_message(f"Error during signature validation for {file_path}: {e}")

def report_metadata(file_path):
    try:
        log_message(f"Reporting metadata for {file_path}")
        
        # Get file stats
        file_stats = os.stat(file_path)
        log_message(f"  File size: {file_stats.st_size} bytes")
        log_message(f"  Last modified: {datetime.datetime.fromtimestamp(file_stats.st_mtime)}")
        log_message(f"  Last accessed: {datetime.datetime.fromtimestamp(file_stats.st_atime)}")
        log_message(f"  Created: {datetime.datetime.fromtimestamp(file_stats.st_ctime)}")
        
        # Check file permissions
        permissions = stat.filemode(file_stats.st_mode)
        log_message(f"  Permissions: {permissions}")
        
        # Extract strings
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                strings = re.findall(r'[ -~]{' + str(config["max_string_length"]) + ',}', content)
                if strings:
                    log_message(f"  Extracted strings:")
                    for s in strings[:5]:  # Limit the number of printed strings for brevity
                        log_message(f"    {s}")
        except Exception as e:
            log_message(f"  Error extracting strings: {e}")
            
        if config["enable_version_info"]:
            version_info = get_version_info(file_path)
            if version_info:
                log_message(f"  Version Info: {version_info}")
    except Exception as e:
        log_message(f"Error reporting metadata for {file_path}: {e}")

# --- Decryption Functions ---
def handle_readonly(file_path):
    try:
        if not os.access(file_path, os.W_OK):
            os.chmod(file_path, stat.S_IWRITE)
            log_message(f"Write permissions enabled for {file_path}")
    except Exception as e:
        log_message(f"Could not change file permissions for {file_path}: {e}")

def attempt_decryption(file_path):
    decrypted_file = f"{file_path}.decrypted"
    success = False
    
    # Handle read-only files
    if config["attempt_readonly_handling"]:
        handle_readonly(file_path)
    
    # Try OpenSSL with multiple keys and ciphers
    log_message(f"Starting OpenSSL decryption attempts for {file_path}")
    for cipher in config["ciphers"]:
        for key in config["decryption_keys"]:
            cmd = ["openssl", "enc", "-d", f"-{cipher}", "-in", file_path, "-out", decrypted_file, "-k", key]
            log_message(f"Executing OpenSSL command: {' '.join(cmd)}")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                log_message(f"OpenSSL return code: {result.returncode}")
                if result.returncode == 0 and os.path.exists(decrypted_file) and os.path.getsize(decrypted_file) > 0:
                    log_message(f"OpenSSL decryption successful with cipher '{cipher}' and key '{key}': {file_path} -> {decrypted_file}")
                    success = True
                    break
                else:
                    log_message(f"OpenSSL decryption failed: {result.stderr}")
                    if result.stdout:
                        log_message(f"OpenSSL output: {result.stdout[:500]}")
            except Exception as e:
                log_message(f"Error during OpenSSL decryption of {file_path}: {e}")
        if success:
            break
    
    # If OpenSSL failed, try GPG
    if not success:
        log_message(f"Starting GPG decryption attempt for {file_path}")
        cmd = ["gpg", "--batch", "--decrypt", "--output", decrypted_file, file_path]
        log_message(f"Executing GPG command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            log_message(f"GPG return code: {result.returncode}")
            if result.returncode == 0 and os.path.exists(decrypted_file) and os.path.getsize(decrypted_file) > 0:
                log_message(f"GPG decryption successful: {file_path} -> {decrypted_file}")
                success = True
            else:
                log_message(f"GPG decryption failed: {result.stderr}")
                if result.stdout:
                    log_message(f"GPG output: {result.stdout[:500]}")
        except Exception as e:
            log_message(f"Error during GPG decryption of {file_path}: {e}")
    
    if success:
        return decrypted_file
    else:
        log_message(f"All decryption attempts failed for {file_path}")
        if config["delete_failed_decryption"] and os.path.exists(decrypted_file):
            try:
                os.remove(decrypted_file)
                log_message(f"Deleted failed decryption output file: {decrypted_file}")
            except Exception as e:
                log_message(f"Could not delete failed decryption output file: {e}")
        return None

def perform_heuristic_analysis(file_path):
    if config["enable_heuristic_analysis"]:
        log_message(f"Performing heuristic analysis on {file_path}")
        
        # Check for suspicious file names
        for pattern in config["suspicious_file_names"]:
            if re.match(pattern, os.path.basename(file_path)):
                log_message(f"  [Heuristic] Suspicious file name detected: {os.path.basename(file_path)} matches {pattern}")
        
        # Add more heuristic checks here...

# --- Post-Analysis Functions ---
def make_executable(file_path):
    if config["enable_executable_check"]:
        log_message(f"Checking if {file_path} should be made executable")
        file_type_result = run_command(["file", file_path], log_output=False)
        if file_type_result:
            file_info = file_type_result.stdout.lower()
            log_message(f"File type for executability check: {file_info.strip()}")
            if "executable" in file_info or "script" in file_info:
                os.chmod(file_path, 0o755)
                log_message(f"Set {file_path} as executable (chmod 755)")
            else:
                log_message(f"Skipped making {file_path} executable (not an executable or script)")
    else:
        log_message("Executable check skipped (disabled in config)")

def verify_checksum(file_path):
    if config["enable_checksum_verification"]:
        if file_path in config["known_checksums"]:
            checksum = calculate_sha256(file_path)
            if checksum == config["known_checksums"][file_path]:
                log_message(f"Checksum for {file_path} matches known good checksum")
            else:
                log_message(f"Checksum for {file_path} does NOT match known good checksum")
        else:
            log_message(f"No known checksum for {file_path} to verify")
    else:
        log_message("Checksum verification skipped (disabled in config)")

# --- Main ---
def main():
    log_message("Starting security analysis...")
    
    # Scan Files
    all_files = []
    for root, _, files in os.walk(SCAN_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            all_files.append(file_path)
    log_message(f"Found {len(all_files)} files to process in {SCAN_DIR}")
    
    decrypted_files = []
    # Analyze and Decrypt
    for file_path in all_files:
        log_message(f"Analyzing file: {file_path}")
        if analyze_file(file_path):
            log_message(f"Identified {file_path} as potentially encrypted")
            decrypted_file = attempt_decryption(file_path)
            if decrypted_file:
                log_message(f"Decryption succeeded, analyzing decrypted file: {decrypted_file}")
                analyze_file_content(decrypted_file)
                perform_heuristic_analysis(decrypted_file)
                decrypted_files.append(decrypted_file)
            else:
                log_message(f"Decryption failed for {file_path}, proceeding with original file analysis")
                analyze_file_content(file_path)
                perform_heuristic_analysis(file_path)
        else:
            log_message(f"{file_path} not encrypted, proceeding with analysis")
            analyze_file_content(file_path)
            perform_heuristic_analysis(file_path)
    
    # Post Analysis
    all_processed_files = all_files + decrypted_files
    log_message(f"Performing post-analysis checks on {len(all_processed_files)} files")
    for file_path in all_processed_files:
        if os.path.exists(file_path):
            make_executable(file_path)
            verify_checksum(file_path)
        else:
            log_message(f"Skipping {file_path} - file does not exist")
    
    log_message("Security analysis completed.")

if __name__ == "__main__":
    main()
