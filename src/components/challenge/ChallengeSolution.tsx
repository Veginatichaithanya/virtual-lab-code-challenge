
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Copy, ClipboardCheck } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ChallengeSolutionProps {
  challengeId: string;
  title: string;
  marks: number;
}

const getCodeForChallenge = (challengeId: string) => {
  switch (challengeId) {
    case 'caesar-cipher':
      return `1  def caesar_cipher(text, shift):
2      result = ""
3
4      for char in text:
5          if char.isalpha():
6              start = ord('A') if char.isupper() else ord('a')
7              result += chr(start + (ord(char) - start + shift) % 26)
8          else:
9              result += char
10
11     return result
12
13 # Example usage
14 plain_text = input("Enter the text: ")
15 shift_value = int(input("Enter the shift value: "))
16
17 cipher_text = caesar_cipher(plain_text, shift_value)
18 print("Cipher Text:", cipher_text)`;

    case 'monoalphabetic-cipher':
      return `1  def monoalphabetic_cipher(plaintext, key_mapping):
2      result = ""
3
4      for char in plaintext:
5          # Convert to lowercase for consistency
6          char_lower = char.lower()
7          
8          # Apply mapping if character is in the key
9          if char_lower in key_mapping:
10             # Preserve original case
11             if char.isupper():
12                 result += key_mapping[char_lower].upper()
13             else:
14                 result += key_mapping[char_lower]
15         else:
16             # Keep characters not in the mapping unchanged
17             result += char
18             
19     return result
20
21 # Test with a sample mapping
22 mapping = {'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't'}
23 text = input("Enter text to encrypt: ")
24 encrypted = monoalphabetic_cipher(text, mapping)
25 print(f"Encrypted: {encrypted}")`;

    case 'message-authentication-code':
      return `1  import hashlib
2  import hmac
3  import os
4
5  def generate_mac(message, key):
6      """Generate a Message Authentication Code (MAC) using HMAC-SHA256"""
7      if isinstance(message, str):
8          message = message.encode('utf-8')
9      if isinstance(key, str):
10         key = key.encode('utf-8')
11         
12     # Create the HMAC
13     mac = hmac.new(key, message, hashlib.sha256)
14     return mac.hexdigest()
15
16 def verify_mac(message, key, received_mac):
17     """Verify a received MAC against a newly generated one"""
18     calculated_mac = generate_mac(message, key)
19     # Use a constant-time comparison to prevent timing attacks
20     return hmac.compare_digest(calculated_mac, received_mac)
21
22 # Example usage
23 secret_key = os.urandom(16)  # Generate a random key
24 message = "Transfer $1000 to Account #12345"
25
26 # Generate the MAC
27 mac = generate_mac(message, secret_key)
28 print(f"Message: {message}")
29 print(f"MAC: {mac}")
30
31 # Verify the MAC (should be True)
32 is_valid = verify_mac(message, secret_key, mac)
33 print(f"MAC is valid: {is_valid}")
34
35 # Try with a tampered message
36 tampered_message = "Transfer $9999 to Account #12345"
37 is_valid = verify_mac(tampered_message, secret_key, mac)
38 print(f"Tampered message MAC is valid: {is_valid}")`;

    case 'des-encryption':
      return `1  from Crypto.Cipher import DES
2  from Crypto.Util.Padding import pad, unpad
3  import os
4
5  def des_encrypt(plaintext, key):
6      """Encrypt data using DES in ECB mode"""
7      if isinstance(plaintext, str):
8          plaintext = plaintext.encode('utf-8')
9          
10     # Create the cipher object and encrypt
11     cipher = DES.new(key, DES.MODE_ECB)
12     # DES requires plaintext to be a multiple of 8 bytes
13     padded_plaintext = pad(plaintext, DES.block_size)
14     ciphertext = cipher.encrypt(padded_plaintext)
15     return ciphertext
16
17 def des_decrypt(ciphertext, key):
18     """Decrypt data using DES in ECB mode"""
19     # Create the cipher object and decrypt
20     cipher = DES.new(key, DES.MODE_ECB)
21     padded_plaintext = cipher.decrypt(ciphertext)
22     plaintext = unpad(padded_plaintext, DES.block_size)
23     return plaintext.decode('utf-8')
24
25 # Example usage - in real applications, use a secure key
26 # DES keys must be exactly 8 bytes (64 bits)
27 key = os.urandom(8)
28 message = "Secret message that needs protection"
29
30 # Encrypt the message
31 encrypted = des_encrypt(message, key)
32 print(f"Encrypted (hex): {encrypted.hex()}")
33
34 # Decrypt the message
35 decrypted = des_decrypt(encrypted, key)
36 print(f"Decrypted: {decrypted}")`;

    case 'aes-encryption':
      return `1  from Crypto.Cipher import AES
2  from Crypto.Util.Padding import pad, unpad
3  from Crypto.Random import get_random_bytes
4
5  def aes_encrypt(plaintext, key):
6      """Encrypt data using AES-CBC mode with a random IV"""
7      if isinstance(plaintext, str):
8          plaintext = plaintext.encode('utf-8')
9          
10     # Generate a random Initialization Vector
11     iv = get_random_bytes(AES.block_size)
12     
13     # Create the cipher object and encrypt
14     cipher = AES.new(key, AES.MODE_CBC, iv)
15     padded_plaintext = pad(plaintext, AES.block_size)
16     ciphertext = cipher.encrypt(padded_plaintext)
17     
18     # Return IV + ciphertext for decryption later
19     return iv + ciphertext
20
21 def aes_decrypt(ciphertext, key):
22     """Decrypt data using AES-CBC mode"""
23     # Extract the IV from the ciphertext
24     iv = ciphertext[:AES.block_size]
25     actual_ciphertext = ciphertext[AES.block_size:]
26     
27     # Create the cipher object and decrypt
28     cipher = AES.new(key, AES.MODE_CBC, iv)
29     padded_plaintext = cipher.decrypt(actual_ciphertext)
30     plaintext = unpad(padded_plaintext, AES.block_size)
31     
32     return plaintext.decode('utf-8')
33
34 # Example usage - AES keys must be 16, 24, or 32 bytes
35 key = get_random_bytes(16)  # 128-bit key
36 message = "This is a highly confidential message"
37
38 # Encrypt the message
39 encrypted = aes_encrypt(message, key)
40 print(f"Encrypted (hex): {encrypted.hex()}")
41
42 # Decrypt the message
43 decrypted = aes_decrypt(encrypted, key)
44 print(f"Decrypted: {decrypted}")`;

    case 'asymmetric-encryption':
      return `1  from Crypto.PublicKey import RSA
2  from Crypto.Cipher import PKCS1_OAEP
3  from Crypto.Hash import SHA256
4
5  def generate_rsa_keypair(key_size=2048):
6      """Generate a new RSA key pair"""
7      key = RSA.generate(key_size)
8      private_key = key.export_key()
9      public_key = key.publickey().export_key()
10     return private_key, public_key
11
12 def rsa_encrypt(message, public_key):
13     """Encrypt a message using an RSA public key"""
14     if isinstance(message, str):
15         message = message.encode('utf-8')
16     if isinstance(public_key, str):
17         public_key = public_key.encode('utf-8')
18         
19     # Import the public key
20     recipient_key = RSA.import_key(public_key)
21     
22     # Create a cipher object using PKCS#1 OAEP
23     cipher = PKCS1_OAEP.new(recipient_key, hashAlgo=SHA256)
24     
25     # Encrypt the message
26     ciphertext = cipher.encrypt(message)
27     return ciphertext
28
29 def rsa_decrypt(ciphertext, private_key):
30     """Decrypt a message using an RSA private key"""
31     if isinstance(private_key, str):
32         private_key = private_key.encode('utf-8')
33         
34     # Import the private key
35     key = RSA.import_key(private_key)
36     
37     # Create a cipher object using PKCS#1 OAEP
38     cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
39     
40     # Decrypt the message
41     plaintext = cipher.decrypt(ciphertext)
42     return plaintext.decode('utf-8')
43
44 # Example usage
45 private_key, public_key = generate_rsa_keypair()
46 message = "This message can only be read by the private key holder"
47
48 # Encrypt using the recipient's public key
49 encrypted = rsa_encrypt(message, public_key)
50 print(f"Encrypted (hex): {encrypted.hex()}")
51
52 # Decrypt using the recipient's private key
53 decrypted = rsa_decrypt(encrypted, private_key)
54 print(f"Decrypted: {decrypted}")`;

    case 'secure-key-exchange':
      return `1  import random
2  import sympy
3
4  def generate_diffie_hellman_params(bits=1024):
5      """Generate Diffie-Hellman parameters (p and g)"""
6      # Generate a large prime number p
7      p = sympy.randprime(2**(bits-1), 2**bits)
8      
9      # Choose a generator g (typically a small prime)
10     g = 2  # Common choice for g
11     
12     return p, g
13
14 def generate_private_key(p):
15     """Generate a private key for Diffie-Hellman"""
16     # Private key should be between 2 and p-2
17     return random.randint(2, p-2)
18
19 def compute_public_key(p, g, private_key):
20     """Compute the public key: g^private_key mod p"""
21     return pow(g, private_key, p)
22
23 def compute_shared_secret(p, public_key, private_key):
24     """Compute the shared secret: public_key^private_key mod p"""
25     return pow(public_key, private_key, p)
26
27 # Simulate Diffie-Hellman key exchange between Alice and Bob
28 # 1. System parameters
29 p, g = generate_diffie_hellman_params(512)  # smaller key for demo
30 print(f"System parameters: p = {p}, g = {g}")
31
32 # 2. Alice generates her keys
33 alice_private = generate_private_key(p)
34 alice_public = compute_public_key(p, g, alice_private)
35 print(f"Alice's public key: {alice_public}")
36
37 # 3. Bob generates his keys
38 bob_private = generate_private_key(p)
39 bob_public = compute_public_key(p, g, bob_private)
40 print(f"Bob's public key: {bob_public}")
41
42 # 4. Alice computes the shared secret
43 alice_shared_secret = compute_shared_secret(p, bob_public, alice_private)
44 print(f"Alice's computed shared secret: {alice_shared_secret}")
45
46 # 5. Bob computes the shared secret
47 bob_shared_secret = compute_shared_secret(p, alice_public, bob_private)
48 print(f"Bob's computed shared secret: {bob_shared_secret}")
49
50 # Both shared secrets should be identical
51 print(f"Shared secrets match: {alice_shared_secret == bob_shared_secret}")`;

    case 'digital-signature':
      return `1  from Crypto.PublicKey import RSA
2  from Crypto.Signature import pkcs1_15
3  from Crypto.Hash import SHA256
4
5  def generate_rsa_keypair(key_size=2048):
6      """Generate a new RSA key pair for signing"""
7      key = RSA.generate(key_size)
8      private_key = key.export_key()
9      public_key = key.publickey().export_key()
10     return private_key, public_key
11
12 def sign_message(message, private_key):
13     """Sign a message using an RSA private key"""
14     if isinstance(message, str):
15         message = message.encode('utf-8')
16     if isinstance(private_key, str):
17         private_key = private_key.encode('utf-8')
18         
19     # Import the private key
20     key = RSA.import_key(private_key)
21     
22     # Create a hash of the message
23     h = SHA256.new(message)
24     
25     # Sign the hash with the private key
26     signer = pkcs1_15.new(key)
27     signature = signer.sign(h)
28     
29     return signature
30
31 def verify_signature(message, signature, public_key):
32     """Verify a signature using an RSA public key"""
33     if isinstance(message, str):
34         message = message.encode('utf-8')
35     if isinstance(public_key, str):
36         public_key = public_key.encode('utf-8')
37         
38     # Import the public key
39     key = RSA.import_key(public_key)
40     
41     # Create a hash of the message
42     h = SHA256.new(message)
43     
44     try:
45         # Verify the signature against the hash
46         verifier = pkcs1_15.new(key)
47         verifier.verify(h, signature)
48         return True
49     except (ValueError, TypeError):
50         return False
51
52 # Example usage
53 private_key, public_key = generate_rsa_keypair(512)  # smaller key for demo
54 message = "Important document that needs to be authenticated"
55
56 # Sign the message with the private key
57 signature = sign_message(message, private_key)
58 print(f"Signature (hex): {signature.hex()}")
59
60 # Verify the signature with the public key
61 is_valid = verify_signature(message, signature, public_key)
62 print(f"Signature is valid: {is_valid}")
63
64 # Try verifying a tampered message
65 tampered_message = "Modified document with unauthorized changes"
66 is_valid = verify_signature(tampered_message, signature, public_key)
67 print(f"Tampered message signature is valid: {is_valid}")`;

    case 'mobile-security':
      return `1  class MobileApp:
2      def __init__(self, name):
3          self.name = name
4          self.permissions = []
5          self.data = {}
6          self.encrypted_data = {}
7          self.encryption_key = None
8
9  def request_permission(app, permission):
10     """Simulate requesting a user permission"""
11     print(f"App '{app.name}' is requesting permission: {permission}")
12     # In a real app, this would show a UI prompt
13     user_response = input(f"Allow '{app.name}' access to {permission}? (yes/no): ")
14     
15     if user_response.lower() in ('yes', 'y'):
16         app.permissions.append(permission)
17         print(f"Permission '{permission}' granted to {app.name}")
18         return True
19     else:
20         print(f"Permission '{permission}' denied to {app.name}")
21         return False
22
23 def check_permission(app, permission):
24     """Check if an app has a specific permission"""
25     return permission in app.permissions
26
27 def encrypt_sensitive_data(app, data_key, data_value, encryption_key):
28     """Simulate encrypting sensitive app data"""
29     if encryption_key is None:
30         print("Error: No encryption key provided")
31         return False
32         
33     # In a real app, we would use proper encryption
34     # This is a simple simulation
35     app.data[data_key] = data_value
36     encrypted = "".join(chr(ord(c) ^ encryption_key) for c in data_value)
37     app.encrypted_data[data_key] = encrypted
38     print(f"Data '{data_key}' encrypted and stored")
39     return True
40
41 def decrypt_sensitive_data(app, data_key, encryption_key):
42     """Simulate decrypting sensitive app data"""
43     if encryption_key is None:
44         print("Error: No encryption key provided")
45         return None
46         
47     if data_key not in app.encrypted_data:
48         print(f"Error: No encrypted data found for '{data_key}'")
49         return None
50         
51     # Simulate decryption
52     encrypted = app.encrypted_data[data_key]
53     decrypted = "".join(chr(ord(c) ^ encryption_key) for c in encrypted)
54     return decrypted
55
56 # Demo
57 banking_app = MobileApp("SecureBanking")
58
59 # Request permissions
60 request_permission(banking_app, "CAMERA")
61 request_permission(banking_app, "LOCATION")
62 request_permission(banking_app, "CONTACTS")
63
64 # Check permissions
65 can_access_camera = check_permission(banking_app, "CAMERA")
66 print(f"App can access camera: {can_access_camera}")
67
68 # Encrypt some sensitive data
69 encryption_key = 42  # In real apps, use a secure encryption key
70 banking_app.encryption_key = encryption_key
71 encrypt_sensitive_data(banking_app, "account_number", "12345678", encryption_key)
72 encrypt_sensitive_data(banking_app, "balance", "5000.00", encryption_key)
73
74 # Try to access the data
75 decrypted_account = decrypt_sensitive_data(banking_app, "account_number", encryption_key)
76 print(f"Decrypted account number: {decrypted_account}")`;

    case 'intrusion-detection':
      return `1  class Packet:
2      def __init__(self, source_ip, dest_ip, protocol, payload, flags=None):
3          self.source_ip = source_ip
4          self.dest_ip = dest_ip
5          self.protocol = protocol
6          self.payload = payload
7          self.flags = flags or {}
8
9  class SnortRule:
10     def __init__(self, rule_text):
11         self.rule_text = rule_text
12         self.parse_rule(rule_text)
13         
14     def parse_rule(self, rule_text):
15         # Very simplified Snort rule parsing
16         parts = rule_text.split("(")
17         header = parts[0].strip()
18         header_parts = header.split()
19         
20         # Extract rule action, protocol, source, destination
21         self.action = header_parts[0]
22         self.protocol = header_parts[1]
23         self.source = header_parts[2]
24         self.destination = header_parts[4]
25         
26         # Extract options
27         self.options = {}
28         if len(parts) > 1:
29             options_text = parts[1].rstrip(")")
30             options_parts = options_text.split(";")
31             
32             for opt in options_parts:
33                 opt = opt.strip()
34                 if ":" in opt:
35                     key, value = opt.split(":", 1)
36                     self.options[key.strip()] = value.strip()
37                 else:
38                     self.options[opt] = True
39     
40     def match(self, packet):
41         """Check if a packet matches this rule"""
42         # Check protocol
43         if self.protocol != "any" and packet.protocol != self.protocol:
44             return False
45             
46         # Check source and destination (simplified)
47         if self.source != "any" and packet.source_ip != self.source:
48             return False
49             
50         if self.destination != "any" and packet.dest_ip != self.destination:
51             return False
52             
53         # Check content
54         if "content" in self.options:
55             content = self.options["content"].strip('"')
56             if content not in packet.payload:
57                 return False
58                 
59         # Rule matched
60         return True
61         
62     def apply(self, packet):
63         """Apply the rule action to a packet"""
64         if self.match(packet):
65             return self.action
66         return None
67
68 class SnortIDS:
69     def __init__(self):
70         self.rules = []
71         
72     def add_rule(self, rule_text):
73         rule = SnortRule(rule_text)
74         self.rules.append(rule)
75         print(f"Added rule: {rule_text}")
76         
77     def process_packet(self, packet):
78         """Process a packet through all rules"""
79         results = []
80         for rule in self.rules:
81             action = rule.apply(packet)
82             if action:
83                 results.append((rule, action))
84                 
85         return results
86
87 # Demo
88 ids = SnortIDS()
89
90 # Add some rules
91 ids.add_rule("alert tcp any any -> 192.168.1.100 80 (content:\"haxor\"; msg:\"Potential attack\";)")
92 ids.add_rule("alert icmp any any -> any any (msg:\"ICMP packet\";)")
93 ids.add_rule("drop tcp any any -> 192.168.1.100 22 (msg:\"SSH connection attempt\";)")
94
95 # Process some packets
96 packets = [
97     Packet("10.0.0.1", "192.168.1.100", "tcp", "GET /admin HTTP/1.1"),
98     Packet("10.0.0.2", "192.168.1.100", "tcp", "POST /login haxor=1234"),
99     Packet("10.0.0.3", "192.168.1.100", "icmp", "ping request"),
100]
101
102for i, packet in enumerate(packets):
103    print(f"\nProcessing packet {i+1} from {packet.source_ip} to {packet.dest_ip}")
104    results = ids.process_packet(packet)
105    
106    if results:
107        for rule, action in results:
108            print(f"Rule matched: {rule.rule_text}")
109            print(f"Action: {action}")
110    else:
111        print("No rules matched, packet allowed")`;

    case 'trojan-analysis':
      return `1  class Trojan:
2      def __init__(self, filename):
3          self.filename = filename
4          self.malicious_functions = []
5          self.legitimate_functions = []
6          self.hidden = False
7
8  def create_trojan(filename, legitimate_purpose):
9      """Create a simulated Trojan for analysis"""
10     trojan = Trojan(filename)
11     
12     # Add a legitimate purpose to hide the malicious intent
13     trojan.legitimate_functions.append(legitimate_purpose)
14     
15     print(f"Created new file: {filename}")
16     print(f"Legitimate purpose: {legitimate_purpose}")
17     
18     return trojan
19
20 def add_malicious_function(trojan, function_name, description):
21     """Add a malicious function to the Trojan"""
22     trojan.malicious_functions.append({
23         "name": function_name,
24         "description": description
25     })
26     print(f"Added hidden function: {function_name}")
27
28 def hide_file_from_system(trojan):
29     """Make the Trojan hide itself from typical system tools"""
30     trojan.hidden = True
31     print(f"File {trojan.filename} now hidden from directory listings")
32
33 def analyze_suspicious_file(file):
34     """Analyze a suspicious file for Trojan characteristics"""
35     print(f"\nAnalyzing file: {file.filename}")
36     
37     # Check for dual nature (legitimate + malicious)
38     if file.legitimate_functions and file.malicious_functions:
39         print("WARNING: File exhibits dual nature - legitimate frontend with hidden functions")
40         print(f"Legitimate purpose: {', '.join(file.legitimate_functions)}")
41         print("Hidden malicious functions:")
42         for func in file.malicious_functions:
43             print(f" - {func['name']}: {func['description']}")
44     
45     # Check if the file is hiding itself
46     if file.hidden:
47         print("WARNING: File is attempting to hide from system")
48     
49     # Overall assessment
50     if file.malicious_functions:
51         threat_level = "High" if len(file.malicious_functions) > 2 else "Medium"
52         print(f"Threat assessment: {threat_level} - File is likely a Trojan")
53     else:
54         print("Threat assessment: Low - No malicious functions detected")
55
56 # Demo: Create and analyze a simulated Trojan
57 update_app = create_trojan("system_update.exe", "System performance optimizer")
58
59 # Add malicious behavior
60 add_malicious_function(update_app, "keylogger", "Records all keystrokes and sends to remote server")
61 add_malicious_function(update_app, "backdoor", "Creates hidden admin account with remote access")
62 add_malicious_function(update_app, "data_theft", "Locates and exfiltrates sensitive files")
63
64 # Make it stealthy
65 hide_file_from_system(update_app)
66
67 # Later, a security expert analyzes the file
68 analyze_suspicious_file(update_app)
69
70 # Compare with a legitimate file
71 print("\n---Comparison with legitimate file---")
72 legitimate_app = create_trojan("actual_update.exe", "System performance optimizer")
73 analyze_suspicious_file(legitimate_app)`;

    case 'rootkit-hunter':
      return `1  class System:
2      def __init__(self, name):
3          self.name = name
4          self.processes = {}
5          self.files = {}
6          self.hidden_processes = {}
7          self.hidden_files = {}
8          self.kernel_modules = []
9
10 class RootkitHunter:
11     def __init__(self):
12         self.signatures = []
13         self.scan_results = {
14             "suspicious_files": [],
15             "hidden_processes": [],
16             "hidden_files": [],
17             "kernel_hook_detected": False
18         }
19     
20     def add_signature(self, signature, description):
21         """Add a known rootkit signature"""
22         self.signatures.append({
23             "signature": signature,
24             "description": description
25         })
26         print(f"Added rootkit signature: {description}")
27         
28     def scan_processes(self, system):
29         """Scan for hidden processes using cross-view technique"""
30         print("\nScanning processes...")
31         
32         # Compare processes visible through different APIs
33         for pid, process in system.hidden_processes.items():
34             self.scan_results["hidden_processes"].append({
35                 "pid": pid,
36                 "name": process
37             })
38             print(f"Found hidden process: {process} (PID: {pid})")
39             
40     def scan_files(self, system):
41         """Scan for hidden files"""
42         print("\nScanning file system...")
43         
44         # Look for hidden files
45         for path, file in system.hidden_files.items():
46             self.scan_results["hidden_files"].append({
47                 "path": path,
48                 "name": file
49             })
50             print(f"Found hidden file: {path}")
51             
52         # Scan known files against rootkit signatures
53         for path, file in system.files.items():
54             for sig in self.signatures:
55                 if sig["signature"] in file.lower():
56                     self.scan_results["suspicious_files"].append({
57                         "path": path,
58                         "name": file,
59                         "reason": sig["description"]
60                     })
61                     print(f"Found suspicious file: {path} - {sig['description']}")
62                     
63     def check_kernel_integrity(self, system):
64         """Check for signs of kernel manipulation"""
65         print("\nChecking kernel integrity...")
66         
67         # Check for suspicious kernel modules
68         suspicious_modules = ["rootkit", "hidepid", "hidefiles"]
69         found_suspicious = False
70         
71         for module in system.kernel_modules:
72             for suspicious in suspicious_modules:
73                 if suspicious in module.lower():
74                     found_suspicious = True
75                     print(f"Suspicious kernel module found: {module}")
76         
77         if found_suspicious:
78             self.scan_results["kernel_hook_detected"] = True
79             
80     def generate_report(self):
81         """Generate a summary report of findings"""
82         print("\n=== ROOTKIT HUNTER SCAN REPORT ===")
83         
84         total_findings = (len(self.scan_results["suspicious_files"]) +
85                          len(self.scan_results["hidden_processes"]) +
86                          len(self.scan_results["hidden_files"]) +
87                          (1 if self.scan_results["kernel_hook_detected"] else 0))
88         
89         if total_findings == 0:
90             print("No signs of rootkit infection found. System appears clean.")
91             return
92             
93         print(f"Found {total_findings} indicators of possible rootkit infection!")
94         
95         if self.scan_results["suspicious_files"]:
96             print(f"\n{len(self.scan_results['suspicious_files'])} suspicious files:")
97             for file in self.scan_results["suspicious_files"]:
98                 print(f" - {file['path']}: {file['reason']}")
99                 
100        if self.scan_results["hidden_processes"]:
101            print(f"\n{len(self.scan_results['hidden_processes'])} hidden processes:")
102            for proc in self.scan_results["hidden_processes"]:
103                print(f" - {proc['name']} (PID: {proc['pid']})")
104                
105        if self.scan_results["hidden_files"]:
106            print(f"\n{len(self.scan_results['hidden_files'])} hidden files:")
107            for file in self.scan_results["hidden_files"]:
108                print(f" - {file['path']}")
109                
110        if self.scan_results["kernel_hook_detected"]:
111            print("\nKernel integrity compromised! System is likely rootkitted.")
112            
113        print("\nRecommendation: If rootkit infection is confirmed, the safest course")
114        print("of action is to back up important data and reinstall the operating system.")
115
116# Demo simulation
117system = System("TestSystem")
118
119# Add normal processes and files
120system.processes = {
121    "1": "system",
122    "100": "browser",
123    "200": "editor"
124}
125
126system.files = {
127    "/bin/ls": "ls binary",
128    "/etc/passwd": "password file",
129    "/tmp/update.sh": "update script"
130}
131
132system.kernel_modules = ["networking", "usb", "filesystem"]
133
134# Simulate rootkit infection
135system.hidden_processes = {
136    "999": "backdoor",
137    "1001": "keylogger"
138}
139
140system.hidden_files = {
141    "/etc/shadow.bak": "stolen passwords",
142    "/usr/lib/libroot.so": "rootkit module"
143}
144
145system.files["/sbin/modprobe"] = "Infected modprobe with rootkit hooks"
146
147system.kernel_modules.append("hidepid_module")
148
149# Run the rootkit hunter
150hunter = RootkitHunter()
151
152# Add some rootkit signatures
153hunter.add_signature("rootkit", "Known rootkit pattern")
154hunter.add_signature("suterusu", "Suterusu rootkit variant")
155hunter.add_signature("hidepid", "Process hiding functionality")
156
157# Scan the system
158hunter.scan_processes(system)
159hunter.scan_files(system)
160hunter.check_kernel_integrity(system)
161
162# Generate report
163hunter.generate_report()`;

    case 'database-security':
      return `1  import hashlib
2  import os
3  import base64
4
5  class Database:
6      def __init__(self, name):
7          self.name = name
8          self.tables = {}
9          self.users = {}
10         self.roles = {}
11         self.role_permissions = {}
12         self.user_roles = {}
13         self.encrypted_columns = {}
14         self.encryption_keys = {}
15         print(f"Database '{name}' created")
16
17 def create_user(db, username, password):
18     """Create a database user with a secure password hash"""
19     salt = os.urandom(16)
20     
21     # Use a secure hash with salt
22     password_hash = hashlib.pbkdf2_hmac(
23         'sha256', 
24         password.encode('utf-8'), 
25         salt, 
26         100000  # 100,000 iterations
27     )
28     
29     # Store the salt with the hash
30     db.users[username] = {
31         'salt': salt,
32         'password_hash': password_hash
33     }
34     
35     print(f"Created user: {username}")
36     return True
37
38 def authenticate_user(db, username, password):
39     """Authenticate a user against stored credentials"""
40     if username not in db.users:
41         print(f"User {username} does not exist")
42         return False
43         
44     user = db.users[username]
45     salt = user['salt']
46     stored_hash = user['password_hash']
47     
48     # Calculate hash with same salt
49     input_hash = hashlib.pbkdf2_hmac(
50         'sha256', 
51         password.encode('utf-8'), 
52         salt, 
53         100000
54     )
55     
56     if input_hash == stored_hash:
57         print(f"User {username} authenticated successfully")
58         return True
59     else:
60         print(f"Authentication failed for user {username}")
61         return False
62
63 def create_table(db, table_name, columns):
64     """Create a table in the database"""
65     if table_name in db.tables:
66         print(f"Table {table_name} already exists")
67         return False
68         
69     db.tables[table_name] = {
70         'columns': columns,
71         'rows': []
72     }
73     
74     print(f"Created table: {table_name}")
75     return True
76
77 def create_role(db, role_name):
78     """Create a role for access control"""
79     if role_name in db.roles:
80         print(f"Role {role_name} already exists")
81         return False
82         
83     db.roles[role_name] = True
84     db.role_permissions[role_name] = {}
85     
86     print(f"Created role: {role_name}")
87     return True
88
89 def grant_permission(db, role_name, table_name, permission):
90     """Grant a permission to a role"""
91     valid_permissions = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
92     
93     if role_name not in db.roles:
94         print(f"Role {role_name} does not exist")
95         return False
96         
97     if table_name not in db.tables:
98         print(f"Table {table_name} does not exist")
99         return False
100        
101    if permission not in valid_permissions:
102        print(f"Invalid permission: {permission}")
103        return False
104        
105    if table_name not in db.role_permissions[role_name]:
106        db.role_permissions[role_name][table_name] = []
107        
108    db.role_permissions[role_name][table_name].append(permission)
109    print(f"Granted {permission} on {table_name} to role {role_name}")
110    return True
111
112def assign_role_to_user(db, username, role_name):
113    """Assign a role to a user"""
114    if username not in db.users:
115        print(f"User {username} does not exist")
116        return False
117        
118    if role_name not in db.roles:
119        print(f"Role {role_name} does not exist")
120        return False
121        
122    if username not in db.user_roles:
123        db.user_roles[username] = []
124        
125    db.user_roles[username].append(role_name)
126    print(f"Assigned role {role_name} to user {username}")
127    return True
128
129def check_permission(db, username, table_name, permission):
130    """Check if a user has a specific permission"""
131    if username not in db.users:
132        print(f"User {username} does not exist")
133        return False
134        
135    if username not in db.user_roles:
136        print(f"User {username} has no roles assigned")
137        return False
138        
139    # Check each role the user has
140    for role in db.user_roles[username]:
141        if table_name in db.role_permissions[role]:
142            if permission in db.role_permissions[role][table_name]:
143                return True
144                
145    print(f"User {username} does not have {permission} permission on {table_name}")
146    return False
147
148# Demo
149db = Database("SecureDB")
150
151# Create users
152create_user(db, "admin", "securePass123!")
153create_user(db, "analyst", "dataReader456")
154create_user(db, "app_user", "userPass789")
155
156# Create tables
157create_table(db, "customers", ["id", "name", "email", "credit_card"])
158create_table(db, "products", ["id", "name", "price"])
159
160# Create roles
161create_role(db, "db_admin")
162create_role(db, "data_analyst")
163create_role(db, "app_role")
164
165# Assign permissions
166grant_permission(db, "db_admin", "customers", "SELECT")
167grant_permission(db, "db_admin", "customers", "INSERT")
168grant_permission(db, "db_admin", "customers", "UPDATE")
169grant_permission(db, "db_admin", "customers", "DELETE")
170grant_permission(db, "db_admin", "products", "SELECT")
171grant_permission(db, "db_admin", "products", "INSERT")
172
173grant_permission(db, "data_analyst", "customers", "SELECT")
174grant_permission(db, "data_analyst", "products", "SELECT")
175
176grant_permission(db, "app_role", "products", "SELECT")
177
178# Assign roles to users
179assign_role_to_user(db, "admin", "db_admin")
180assign_role_to_user(db, "analyst", "data_analyst")
181assign_role_to_user(db, "app_user", "app_role")
182
183# Test access control
184print("\nTesting database access control:")
185print("1. Can admin select from customers?", 
186      check_permission(db, "admin", "customers", "SELECT"))
187print("2. Can analyst update customers?", 
188      check_permission(db, "analyst", "customers", "UPDATE"))
189print("3. Can app_user select from products?", 
190      check_permission(db, "app_user", "products", "SELECT"))
191print("4. Can app_user select from customers?", 
192      check_permission(db, "app_user", "customers", "SELECT"))`;

    case 'database-encryption':
      return `1  import hashlib
2  import os
3  import base64
4  from cryptography.fernet import Fernet
5
6  class SecureDatabase:
7      def __init__(self, name):
8          self.name = name
9          self.tables = {}
10         self.column_encryption = {}  # Tracks which columns are encrypted
11         self.encryption_keys = {}    # Encryption keys for each table
12         print(f"Secure database '{name}' created")
13
14 def generate_encryption_key():
15     """Generate a secure encryption key"""
16     return Fernet.generate_key()
17
18 def encrypt_value(encryption_key, value):
19     """Encrypt a value using the provided key"""
20     if not isinstance(value, str):
21         value = str(value)
22         
23     f = Fernet(encryption_key)
24     encrypted = f.encrypt(value.encode('utf-8'))
25     return base64.urlsafe_b64encode(encrypted).decode('ascii')
26
27 def decrypt_value(encryption_key, encrypted_value):
28     """Decrypt a value using the provided key"""
29     try:
30         f = Fernet(encryption_key)
31         decoded = base64.urlsafe_b64decode(encrypted_value)
32         decrypted = f.decrypt(decoded)
33         return decrypted.decode('utf-8')
34     except Exception as e:
35         print(f"Decryption error: {e}")
36         return None
37
38 def create_table_with_encryption(db, table_name, columns, encrypted_columns):
39     """Create a table with specified encrypted columns"""
40     if table_name in db.tables:
41         print(f"Table {table_name} already exists")
42         return False
43         
44     # Validate that encrypted_columns exist in columns
45     for col in encrypted_columns:
46         if col not in columns:
47             print(f"Column {col} not in table definition")
48             return False
49             
50     # Generate a key for this table
51     key = generate_encryption_key()
52     db.encryption_keys[table_name] = key
53     
54     # Create the table
55     db.tables[table_name] = {
56         'columns': columns,
57         'rows': []
58     }
59     
60     # Track encrypted columns
61     db.column_encryption[table_name] = encrypted_columns
62     
63     print(f"Created table: {table_name} with encrypted columns: {', '.join(encrypted_columns)}")
64     return True
65
66 def insert_row(db, table_name, row_data):
67     """Insert a row, encrypting sensitive columns"""
68     if table_name not in db.tables:
69         print(f"Table {table_name} does not exist")
70         return False
71         
72     table = db.tables[table_name]
73     columns = table['columns']
74     
75     # Validate row data has correct columns
76     if set(row_data.keys()) != set(columns):
77         print("Row data does not match table columns")
78         return False
79     
80     # Create a copy of the data for insertion
81     processed_row = {}
82     
83     # Encrypt sensitive columns
84     encryption_key = db.encryption_keys[table_name]
85     encrypted_columns = db.column_encryption.get(table_name, [])
86     
87     for col, value in row_data.items():
88         if col in encrypted_columns:
89             # Encrypt sensitive data
90             processed_row[col] = encrypt_value(encryption_key, value)
91         else:
92             # Store non-sensitive data as is
93             processed_row[col] = value
94     
95     # Add row to table
96     table['rows'].append(processed_row)
97     print(f"Row inserted into {table_name}")
98     return True
99
100def query_row(db, table_name, search_column, search_value, decrypt=True):
101    """Query a row, optionally decrypting sensitive columns"""
102    if table_name not in db.tables:
103        print(f"Table {table_name} does not exist")
104        return None
105        
106    table = db.tables[table_name]
107    results = []
108    
109    # Is the search column encrypted?
110    encrypted_columns = db.column_encryption.get(table_name, [])
111    search_on_encrypted = search_column in encrypted_columns
112    
113    encryption_key = db.encryption_keys[table_name]
114    
115    for row in table['rows']:
116        match = False
117        
118        if search_on_encrypted:
119            # For encrypted columns, we need to check all rows since we can't
120            # compare encrypted values directly
121            decrypted_value = decrypt_value(encryption_key, row[search_column])
122            match = (decrypted_value == search_value)
123        else:
124            # For non-encrypted columns, direct comparison works
125            match = (row[search_column] == search_value)
126            
127        if match:
128            # Return the row, decrypting sensitive columns if requested
129            if decrypt:
130                decrypted_row = {}
131                for col, value in row.items():
132                    if col in encrypted_columns:
133                        decrypted_row[col] = decrypt_value(encryption_key, value)
134                    else:
135                        decrypted_row[col] = value
136                results.append(decrypted_row)
137            else:
138                results.append(row)
139                
140    return results
141
142def calculate_hash_integrity(db, table_name):
143    """Calculate a hash for table integrity verification"""
144    if table_name not in db.tables:
145        print(f"Table {table_name} does not exist")
146        return None
147        
148    table = db.tables[table_name]
149    
150    # Create a string representation of all rows
151    data_string = ""
152    for row in table['rows']:
153        # Sort keys to ensure consistent ordering
154        for col in sorted(row.keys()):
155            data_string += str(row[col])
156            
157    # Calculate SHA-256 hash
158    integrity_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
159    return integrity_hash
160
161# Demo
162db = SecureDatabase("EncryptedDB")
163
164# Create a table with encrypted columns
165create_table_with_encryption(
166    db, 
167    "customers", 
168    ["id", "name", "email", "credit_card", "address"], 
169    ["email", "credit_card"]  # Only these columns will be encrypted
170)
171
172# Insert some data
173insert_row(db, "customers", {
174    "id": "1001",
175    "name": "John Doe",
176    "email": "john@example.com",
177    "credit_card": "4111-1111-1111-1111",
178    "address": "123 Main St"
179})
180
181insert_row(db, "customers", {
182    "id": "1002",
183    "name": "Jane Smith",
184    "email": "jane@example.com",
185    "credit_card": "5555-5555-5555-5555",
186    "address": "456 Oak Ave"
187})
188
189# Query by non-encrypted column
190print("\nQuerying by name:")
191results = query_row(db, "customers", "name", "John Doe")
192if results:
193    for row in results:
194        print(f"Found: {row}")
195
196# Calculate integrity hash
197integrity_hash = calculate_hash_integrity(db, "customers")
198print(f"\nTable integrity hash: {integrity_hash}")
199
200# Demonstrate how the hash would change if data is tampered with
201original_hash = integrity_hash
202
203# Tampering simulation - directly access a row and modify it
204db.tables["customers"]["rows"][0]["address"] = "999 Hacked St"
205
206new_hash = calculate_hash_integrity(db, "customers")
207print(f"New hash after tampering: {new_hash}")
208print(f"Integrity violated: {original_hash != new_hash}")`;
  
    default:
      return "// No sample code available for this challenge";
  }
};

export const ChallengeSolution: React.FC<ChallengeSolutionProps> = ({ 
  challengeId, 
  title, 
  marks 
}) => {
  const [copySuccess, setCopySuccess] = useState(false);
  const { toast } = useToast();
  
  const handleCopyToClipboard = () => {
    const solutionCode = getCodeForChallenge(challengeId);
    navigator.clipboard.writeText(solutionCode);
    setCopySuccess(true);
    
    setTimeout(() => {
      setCopySuccess(false);
    }, 2000);

    toast({
      title: "Code Copied!",
      description: "Solution code has been copied to clipboard.",
    });
  };

  return (
    <div className="bg-muted/50 rounded-lg p-4">
      <div className="flex justify-between items-center mb-4">
        <p className="text-muted-foreground">Solution for {title} - {marks} Marks</p>
        <Button 
          variant="outline" 
          size="sm" 
          onClick={handleCopyToClipboard} 
          className="flex items-center gap-1"
        >
          {copySuccess ? (
            <>
              <ClipboardCheck className="h-4 w-4" />
              Copied!
            </>
          ) : (
            <>
              <Copy className="h-4 w-4" />
              Copy Code
            </>
          )}
        </Button>
      </div>
      
      <div className="bg-cyber-dark rounded-lg p-4 font-mono text-sm text-white overflow-auto">
        <pre className="whitespace-pre-wrap">
          {getCodeForChallenge(challengeId)}
        </pre>
      </div>
    </div>
  );
};
