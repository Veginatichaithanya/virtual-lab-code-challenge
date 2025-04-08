
export interface Challenge {
  id: string;
  title: string;
  description: string;
  shortDescription: string;
  difficulty: 'Easy' | 'Medium' | 'Hard';
  marks: number;
  howItWorks: string[];
  examples: {
    input: string;
    output: string;
  }[];
  initialCode: string;
  testCases: {
    input: string;
    expectedOutput: string;
  }[];
}

export const challenges: Challenge[] = [
  {
    id: "caesar-cipher",
    title: "Caesar Cipher",
    shortDescription: "Implement a basic character shifting encryption technique",
    description: "In cryptography, a Caesar cipher is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. The method is named after Julius Caesar, who used it in his private correspondence.",
    difficulty: "Easy",
    marks: 25,
    howItWorks: [
      "Choose a shift value (key) between 1-25",
      "For each letter in the plaintext, shift it forward in the alphabet by the key value",
      "Wrap around to the beginning of the alphabet if necessary",
      "Leave non-alphabetic characters unchanged",
      "Return the resulting ciphertext"
    ],
    examples: [
      {
        input: "Plaintext: HELLO, Shift: 3",
        output: "Ciphertext: KHOOR"
      },
      {
        input: "Plaintext: hello world, Shift: 7",
        output: "Ciphertext: olssv dvysk"
      }
    ],
    initialCode: `def caesar_cipher(text, shift):
    result = ""
    
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr(start + (ord(char) - start + shift) % 26)
        else:
            result += char
            
    return result

# Example usage
plain_text = input("Enter the text: ")
shift_value = int(input("Enter the shift value: "))

cipher_text = caesar_cipher(plain_text, shift_value)
print("Cipher Text:", cipher_text)`,
    testCases: [
      {
        input: "hello, 3",
        expectedOutput: "khoor"
      },
      {
        input: "HELLO WORLD!, 7",
        expectedOutput: "OLSSV DVYSK!"
      },
      {
        input: "ZzYy, 5",
        expectedOutput: "EeDd"
      }
    ]
  },
  {
    id: "monoalphabetic-cipher",
    title: "Basic Monoalphabetic Cipher",
    shortDescription: "Implement a static mapping substitution technique for encryption",
    description: "A monoalphabetic substitution cipher uses a fixed substitution over the entire message. Each letter of the plaintext is replaced with another letter of the alphabet, so that the letter A always becomes the same letter throughout the whole encryption process.",
    difficulty: "Easy",
    marks: 30,
    howItWorks: [
      "Create a substitution key where each letter of the alphabet maps to another unique letter",
      "For each character in the plaintext, find its corresponding value in the mapping",
      "Replace the character with its mapped value",
      "Leave non-alphabetic characters unchanged",
      "Return the resulting ciphertext"
    ],
    examples: [
      {
        input: "Plaintext: HELLO, Key: {'H':'X', 'E':'Y', 'L':'Z', 'O':'W'}",
        output: "Ciphertext: XYZZW"
      }
    ],
    initialCode: `def monoalphabetic_cipher(plaintext, key_mapping):
    result = ""
    
    for char in plaintext:
        # Convert to lowercase for consistency
        char_lower = char.lower()
        
        # Apply mapping if character is in the key
        if char_lower in key_mapping:
            # Preserve original case
            if char.isupper():
                result += key_mapping[char_lower].upper()
            else:
                result += key_mapping[char_lower]
        else:
            # Keep characters not in the mapping unchanged
            result += char
            
    return result

# Test with a sample mapping
mapping = {'a': 'q', 'b': 'w', 'c': 'e', 'd': 'r', 'e': 't'}
text = input("Enter text to encrypt: ")
encrypted = monoalphabetic_cipher(text, mapping)
print(f"Encrypted: {encrypted}")`,
    testCases: [
      {
        input: "hello, {'h': 'x', 'e': 'y', 'l': 'z', 'o': 'w'}",
        expectedOutput: "xyzz"
      },
      {
        input: "Hello World!, {'h': 'x', 'e': 'y', 'l': 'z', 'o': 'w', ' ': '*', 'w': 'q', 'r': 'p', 'd': 'm'}",
        expectedOutput: "Xyzz*Qwpzm!"
      }
    ]
  },
  {
    id: "message-authentication-code",
    title: "Message Authentication Code (MAC)",
    shortDescription: "Ensure message integrity using authentication tags",
    description: "A Message Authentication Code (MAC) is a security mechanism used to verify both the integrity and authenticity of a message. It's a small piece of information (tag) that allows the receiver to verify that the message came from the expected sender and hasn't been altered.",
    difficulty: "Medium",
    marks: 40,
    howItWorks: [
      "Generate a MAC tag by applying a hash function to a combination of the message and a secret key",
      "The sender transmits both the message and the MAC tag",
      "The receiver recalculates the MAC using the same message and key",
      "If the calculated MAC matches the received MAC, the message is authentic and unaltered"
    ],
    examples: [
      {
        input: "Message: 'Transfer $1000', Key: 'secret'",
        output: "MAC: '6d5f8e3a1b9c7d2f'"
      }
    ],
    initialCode: `import hashlib
import hmac
import os

def generate_mac(message, key):
    """Generate a Message Authentication Code (MAC) using HMAC-SHA256"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
        
    # Create the HMAC
    mac = hmac.new(key, message, hashlib.sha256)
    return mac.hexdigest()

def verify_mac(message, key, received_mac):
    """Verify a received MAC against a newly generated one"""
    calculated_mac = generate_mac(message, key)
    # Use a constant-time comparison to prevent timing attacks
    return hmac.compare_digest(calculated_mac, received_mac)

# Example usage
secret_key = os.urandom(16)  # Generate a random key
message = "Transfer $1000 to Account #12345"

# Generate the MAC
mac = generate_mac(message, secret_key)
print(f"Message: {message}")
print(f"MAC: {mac}")

# Verify the MAC (should be True)
is_valid = verify_mac(message, secret_key, mac)
print(f"MAC is valid: {is_valid}")

# Try with a tampered message
tampered_message = "Transfer $9999 to Account #12345"
is_valid = verify_mac(tampered_message, secret_key, mac)
print(f"Tampered message MAC is valid: {is_valid}")`,
    testCases: [
      {
        input: "Hello, secure world!, SecretKey123",
        expectedOutput: "True"
      },
      {
        input: "Tampered message!, SecretKey123, InvalidMAC",
        expectedOutput: "False"
      }
    ]
  },
  {
    id: "des-encryption",
    title: "Data Encryption Standard (DES)",
    shortDescription: "Implement the classic symmetric block cipher encryption",
    description: "The Data Encryption Standard (DES) is a symmetric-key block cipher that was once widely used for data encryption. Although now considered insecure due to its small key size, understanding DES provides fundamental knowledge about how block ciphers work.",
    difficulty: "Medium",
    marks: 45,
    howItWorks: [
      "DES encrypts data in 64-bit blocks using a 56-bit key",
      "The algorithm involves an initial permutation, 16 rounds of complex substitutions and permutations, and a final permutation",
      "For each block, the plaintext is divided, processed through multiple rounds, and combined",
      "The process is reversible, allowing for decryption with the same key"
    ],
    examples: [
      {
        input: "Plaintext: 'Secure Data', Key: [random 8 bytes]",
        output: "Ciphertext: [encrypted bytes]"
      }
    ],
    initialCode: `from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

def des_encrypt(plaintext, key):
    """Encrypt data using DES in ECB mode"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    # Create the cipher object and encrypt
    cipher = DES.new(key, DES.MODE_ECB)
    # DES requires plaintext to be a multiple of 8 bytes
    padded_plaintext = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(ciphertext, key):
    """Decrypt data using DES in ECB mode"""
    # Create the cipher object and decrypt
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES.block_size)
    return plaintext.decode('utf-8')

# Example usage - in real applications, use a secure key
# DES keys must be exactly 8 bytes (64 bits)
key = os.urandom(8)
message = "Secret message that needs protection"

# Encrypt the message
encrypted = des_encrypt(message, key)
print(f"Encrypted (hex): {encrypted.hex()}")

# Decrypt the message
decrypted = des_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")`,
    testCases: [
      {
        input: "Test message, [key]",
        expectedOutput: "Test message"
      }
    ]
  },
  {
    id: "aes-encryption",
    title: "Advanced Encryption Standard (AES)",
    shortDescription: "Implement the modern symmetric encryption standard",
    description: "The Advanced Encryption Standard (AES) is a symmetric encryption algorithm that has become the standard for secure data encryption. It's widely used in various security protocols and applications to protect sensitive information.",
    difficulty: "Medium",
    marks: 50,
    howItWorks: [
      "AES operates on fixed-size blocks of 128 bits (16 bytes)",
      "It supports key sizes of 128, 192, or 256 bits",
      "The encryption process involves multiple rounds of substitution, permutation, mixing, and key addition operations",
      "For added security, AES typically uses modes of operation like CBC (Cipher Block Chaining) with an initialization vector (IV)"
    ],
    examples: [
      {
        input: "Plaintext: 'Confidential Data', Key: [128-bit key], IV: [128-bit IV]",
        output: "Ciphertext: [encrypted bytes]"
      }
    ],
    initialCode: `from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key):
    """Encrypt data using AES-CBC mode with a random IV"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
        
    # Generate a random Initialization Vector
    iv = get_random_bytes(AES.block_size)
    
    # Create the cipher object and encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # Return IV + ciphertext for decryption later
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    """Decrypt data using AES-CBC mode"""
    # Extract the IV from the ciphertext
    iv = ciphertext[:AES.block_size]
    actual_ciphertext = ciphertext[AES.block_size:]
    
    # Create the cipher object and decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(actual_ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext.decode('utf-8')

# Example usage - AES keys must be 16, 24, or 32 bytes
key = get_random_bytes(16)  # 128-bit key
message = "This is a highly confidential message"

# Encrypt the message
encrypted = aes_encrypt(message, key)
print(f"Encrypted (hex): {encrypted.hex()}")

# Decrypt the message
decrypted = aes_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")`,
    testCases: [
      {
        input: "Secret message, [key]",
        expectedOutput: "Secret message"
      }
    ]
  },
  {
    id: "asymmetric-encryption",
    title: "Asymmetric Key Encryption (RSA)",
    shortDescription: "Implement public-private key encryption using RSA",
    description: "Asymmetric encryption, also known as public-key cryptography, uses two different but mathematically linked keys: a public key for encryption and a private key for decryption. RSA is one of the most widely used asymmetric algorithms.",
    difficulty: "Hard",
    marks: 60,
    howItWorks: [
      "Generate a key pair consisting of a public key and a private key",
      "The public key is shared openly, while the private key is kept secret",
      "Anyone can encrypt a message using the recipient's public key",
      "Only the recipient with the corresponding private key can decrypt the message",
      "RSA security relies on the mathematical difficulty of factoring large prime numbers"
    ],
    examples: [
      {
        input: "Plaintext: 'Confidential message', Recipient's Public Key: [public key]",
        output: "Ciphertext: [encrypted data that can only be decrypted with the private key]"
      }
    ],
    initialCode: `from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def generate_rsa_keypair(key_size=2048):
    """Generate a new RSA key pair"""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    """Encrypt a message using an RSA public key"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(public_key, str):
        public_key = public_key.encode('utf-8')
        
    # Import the public key
    recipient_key = RSA.import_key(public_key)
    
    # Create a cipher object using PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(recipient_key, hashAlgo=SHA256)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(message)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    """Decrypt a message using an RSA private key"""
    if isinstance(private_key, str):
        private_key = private_key.encode('utf-8')
        
    # Import the private key
    key = RSA.import_key(private_key)
    
    # Create a cipher object using PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    
    # Decrypt the message
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# Example usage
private_key, public_key = generate_rsa_keypair()
message = "This message can only be read by the private key holder"

# Encrypt using the recipient's public key
encrypted = rsa_encrypt(message, public_key)
print(f"Encrypted (hex): {encrypted.hex()}")

# Decrypt using the recipient's private key
decrypted = rsa_decrypt(encrypted, private_key)
print(f"Decrypted: {decrypted}")`,
    testCases: [
      {
        input: "Test RSA encryption/decryption",
        expectedOutput: "Test RSA encryption/decryption"
      }
    ]
  },
  {
    id: "secure-key-exchange",
    title: "Secure Key Exchange (Diffie-Hellman)",
    shortDescription: "Implement a secure method for exchanging cryptographic keys",
    description: "The Diffie-Hellman key exchange is a method that allows two parties to securely establish a shared secret key over an insecure communication channel without ever sharing the actual key. This shared key can then be used for symmetric encryption.",
    difficulty: "Hard",
    marks: 55,
    howItWorks: [
      "Two parties (e.g., Alice and Bob) agree on public parameters (a prime number p and a generator g)",
      "Each party generates a private key (a random number) and computes a public key",
      "They exchange their public keys",
      "Each party independently computes the same shared secret using their private key and the other's public key",
      "The security relies on the computational difficulty of the discrete logarithm problem"
    ],
    examples: [
      {
        input: "Alice's private key: 6, Bob's private key: 15, Public parameters: p=23, g=5",
        output: "Shared secret: 2"
      }
    ],
    initialCode: `import random
import sympy

def generate_diffie_hellman_params(bits=1024):
    """Generate Diffie-Hellman parameters (p and g)"""
    # Generate a large prime number p
    p = sympy.randprime(2**(bits-1), 2**bits)
    
    # Choose a generator g (typically a small prime)
    g = 2  # Common choice for g
    
    return p, g

def generate_private_key(p):
    """Generate a private key for Diffie-Hellman"""
    # Private key should be between 2 and p-2
    return random.randint(2, p-2)

def compute_public_key(p, g, private_key):
    """Compute the public key: g^private_key mod p"""
    return pow(g, private_key, p)

def compute_shared_secret(p, public_key, private_key):
    """Compute the shared secret: public_key^private_key mod p"""
    return pow(public_key, private_key, p)

# Simulate Diffie-Hellman key exchange between Alice and Bob
# 1. System parameters
p, g = generate_diffie_hellman_params(512)  # smaller key for demo
print(f"System parameters: p = {p}, g = {g}")

# 2. Alice generates her keys
alice_private = generate_private_key(p)
alice_public = compute_public_key(p, g, alice_private)
print(f"Alice's public key: {alice_public}")

# 3. Bob generates his keys
bob_private = generate_private_key(p)
bob_public = compute_public_key(p, g, bob_private)
print(f"Bob's public key: {bob_public}")

# 4. Alice computes the shared secret
alice_shared_secret = compute_shared_secret(p, bob_public, alice_private)
print(f"Alice's computed shared secret: {alice_shared_secret}")

# 5. Bob computes the shared secret
bob_shared_secret = compute_shared_secret(p, alice_public, bob_private)
print(f"Bob's computed shared secret: {bob_shared_secret}")

# Both shared secrets should be identical
print(f"Shared secrets match: {alice_shared_secret == bob_shared_secret}")`,
    testCases: [
      {
        input: "Alice's private key: 6, Bob's private key: 15, p=23, g=5",
        expectedOutput: "True"
      }
    ]
  },
  {
    id: "digital-signature",
    title: "Digital Signature Generation and Verification",
    shortDescription: "Implement cryptographic authentication of digital messages",
    description: "Digital signatures provide a way to verify the authenticity and integrity of a message, document, or software. They use asymmetric cryptography to create a signature that can be verified by anyone who has the signer's public key.",
    difficulty: "Hard",
    marks: 65,
    howItWorks: [
      "The signer creates a hash of the message to be signed",
      "The hash is encrypted with the signer's private key to create the signature",
      "The signature is attached to the message",
      "To verify, the recipient decrypts the signature using the signer's public key to get the original hash",
      "The recipient independently hashes the received message and compares it with the decrypted hash",
      "If they match, the signature is valid and the message is authentic"
    ],
    examples: [
      {
        input: "Message: 'Important document', Private key: [signer's private key]",
        output: "Signature: [digital signature bytes]"
      }
    ],
    initialCode: `from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_rsa_keypair(key_size=2048):
    """Generate a new RSA key pair for signing"""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(message, private_key):
    """Sign a message using an RSA private key"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(private_key, str):
        private_key = private_key.encode('utf-8')
        
    # Import the private key
    key = RSA.import_key(private_key)
    
    # Create a hash of the message
    h = SHA256.new(message)
    
    # Sign the hash with the private key
    signer = pkcs1_15.new(key)
    signature = signer.sign(h)
    
    return signature

def verify_signature(message, signature, public_key):
    """Verify a signature using an RSA public key"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(public_key, str):
        public_key = public_key.encode('utf-8')
        
    # Import the public key
    key = RSA.import_key(public_key)
    
    # Create a hash of the message
    h = SHA256.new(message)
    
    try:
        # Verify the signature against the hash
        verifier = pkcs1_15.new(key)
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example usage
private_key, public_key = generate_rsa_keypair(512)  # smaller key for demo
message = "Important document that needs to be authenticated"

# Sign the message with the private key
signature = sign_message(message, private_key)
print(f"Signature (hex): {signature.hex()}")

# Verify the signature with the public key
is_valid = verify_signature(message, signature, public_key)
print(f"Signature is valid: {is_valid}")

# Try verifying a tampered message
tampered_message = "Modified document with unauthorized changes"
is_valid = verify_signature(tampered_message, signature, public_key)
print(f"Tampered message signature is valid: {is_valid}")`,
    testCases: [
      {
        input: "Original message verification",
        expectedOutput: "True"
      },
      {
        input: "Tampered message verification",
        expectedOutput: "False"
      }
    ]
  },
  {
    id: "mobile-security",
    title: "Mobile Security Implementation",
    shortDescription: "Implement essential mobile app security features",
    description: "Mobile applications require specific security considerations to protect user data and device resources. This module covers implementing key security features like permission management, secure data storage, and protection against common vulnerabilities.",
    difficulty: "Medium",
    marks: 50,
    howItWorks: [
      "Implement a permission management system to control access to sensitive device features",
      "Apply encryption for storing sensitive user data",
      "Implement secure data transmission protocols",
      "Add authentication and authorization mechanisms",
      "Build protection against common mobile app vulnerabilities"
    ],
    examples: [
      {
        input: "App requests camera permission, user grants it",
        output: "Permission granted, app can access camera"
      },
      {
        input: "Store credit card data with encryption key",
        output: "Data securely stored, only accessible with the correct key"
      }
    ],
    initialCode: `class MobileApp:
    def __init__(self, name):
        self.name = name
        self.permissions = []
        self.data = {}
        self.encrypted_data = {}
        self.encryption_key = None

def request_permission(app, permission):
    """Simulate requesting a user permission"""
    print(f"App '{app.name}' is requesting permission: {permission}")
    # In a real app, this would show a UI prompt
    user_response = input(f"Allow '{app.name}' access to {permission}? (yes/no): ")
    
    if user_response.lower() in ('yes', 'y'):
        app.permissions.append(permission)
        print(f"Permission '{permission}' granted to {app.name}")
        return True
    else:
        print(f"Permission '{permission}' denied to {app.name}")
        return False

def check_permission(app, permission):
    """Check if an app has a specific permission"""
    return permission in app.permissions

def encrypt_sensitive_data(app, data_key, data_value, encryption_key):
    """Simulate encrypting sensitive app data"""
    if encryption_key is None:
        print("Error: No encryption key provided")
        return False
        
    # In a real app, we would use proper encryption
    # This is a simple simulation
    app.data[data_key] = data_value
    encrypted = "".join(chr(ord(c) ^ encryption_key) for c in data_value)
    app.encrypted_data[data_key] = encrypted
    print(f"Data '{data_key}' encrypted and stored")
    return True

def decrypt_sensitive_data(app, data_key, encryption_key):
    """Simulate decrypting sensitive app data"""
    if encryption_key is None:
        print("Error: No encryption key provided")
        return None
        
    if data_key not in app.encrypted_data:
        print(f"Error: No encrypted data found for '{data_key}'")
        return None
        
    # Simulate decryption
    encrypted = app.encrypted_data[data_key]
    decrypted = "".join(chr(ord(c) ^ encryption_key) for c in encrypted)
    return decrypted

# Demo
banking_app = MobileApp("SecureBanking")

# Request permissions
request_permission(banking_app, "CAMERA")
request_permission(banking_app, "LOCATION")
request_permission(banking_app, "CONTACTS")

# Check permissions
can_access_camera = check_permission(banking_app, "CAMERA")
print(f"App can access camera: {can_access_camera}")

# Encrypt some sensitive data
encryption_key = 42  # In real apps, use a secure encryption key
banking_app.encryption_key = encryption_key
encrypt_sensitive_data(banking_app, "account_number", "12345678", encryption_key)
encrypt_sensitive_data(banking_app, "balance", "5000.00", encryption_key)

# Try to access the data
decrypted_account = decrypt_sensitive_data(banking_app, "account_number", encryption_key)
print(f"Decrypted account number: {decrypted_account}")`,
    testCases: [
      {
        input: "Store and retrieve 'password', key=42",
        expectedOutput: "password"
      }
    ]
  },
  {
    id: "intrusion-detection",
    title: "Intrusion Detection System with Snort",
    shortDescription: "Implement a simplified IDS using Snort-like rules",
    description: "An Intrusion Detection System (IDS) monitors network or system activities for malicious activities or policy violations. This module implements a simplified version of an IDS using Snort-like rules to detect potential security threats.",
    difficulty: "Hard",
    marks: 70,
    howItWorks: [
      "Define rules to identify suspicious network activity patterns",
      "Parse and analyze network packets for matching these patterns",
      "Generate alerts when suspicious activity is detected",
      "Log detected threats for security analysis",
      "Apply appropriate responses based on the threat level"
    ],
    examples: [
      {
        input: "Rule: 'alert tcp any any -> 192.168.1.100 80 (content:\"haxor\"; msg:\"Potential attack\";)'",
        output: "Alert: Detected 'Potential attack' in packet from 10.0.0.2 to 192.168.1.100"
      }
    ],
    initialCode: `class Packet:
    def __init__(self, source_ip, dest_ip, protocol, payload, flags=None):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.payload = payload
        self.flags = flags or {}

class SnortRule:
    def __init__(self, rule_text):
        self.rule_text = rule_text
        self.parse_rule(rule_text)
        
    def parse_rule(self, rule_text):
        # Very simplified Snort rule parsing
        parts = rule_text.split("(")
        header = parts[0].strip()
        header_parts = header.split()
        
        # Extract rule action, protocol, source, destination
        self.action = header_parts[0]
        self.protocol = header_parts[1]
        self.source = header_parts[2]
        self.destination = header_parts[4]
        
        # Extract options
        self.options = {}
        if len(parts) > 1:
            options_text = parts[1].rstrip(")")
            options_parts = options_text.split(";")
            
            for opt in options_parts:
                opt = opt.strip()
                if ":" in opt:
                    key, value = opt.split(":", 1)
                    self.options[key.strip()] = value.strip()
                else:
                    self.options[opt] = True
    
    def match(self, packet):
        """Check if a packet matches this rule"""
        # Check protocol
        if self.protocol != "any" and packet.protocol != self.protocol:
            return False
            
        # Check source and destination (simplified)
        if self.source != "any" and packet.source_ip != self.source:
            return False
            
        if self.destination != "any" and packet.dest_ip != self.destination:
            return False
            
        # Check content
        if "content" in self.options:
            content = self.options["content"].strip('"')
            if content not in packet.payload:
                return False
                
        # Rule matched
        return True
        
    def apply(self, packet):
        """Apply the rule action to a packet"""
        if self.match(packet):
            return self.action
        return None

class SnortIDS:
    def __init__(self):
        self.rules = []
        
    def add_rule(self, rule_text):
        rule = SnortRule(rule_text)
        self.rules.append(rule)
        print(f"Added rule: {rule_text}")
        
    def process_packet(self, packet):
        """Process a packet through all rules"""
        results = []
        for rule in self.rules:
            action = rule.apply(packet)
            if action:
                results.append((rule, action))
                
        return results

# Demo
ids = SnortIDS()

# Add some rules
ids.add_rule("alert tcp any any -> 192.168.1.100 80 (content:\"haxor\"; msg:\"Potential attack\";)")
ids.add_rule("alert icmp any any -> any any (msg:\"ICMP packet\";)")
ids.add_rule("drop tcp any any -> 192.168.1.100 22 (msg:\"SSH connection attempt\";)")

# Process some packets
packets = [
    Packet("10.0.0.1", "192.168.1.100", "tcp", "GET /admin HTTP/1.1"),
    Packet("10.0.0.2", "192.168.1.100", "tcp", "POST /login haxor=1234"),
    Packet("10.0.0.3", "192.168.1.100", "icmp", "ping request"),
]

for i, packet in enumerate(packets):
    print(f"\nProcessing packet {i+1} from {packet.source_ip} to {packet.dest_ip}")
    results = ids.process_packet(packet)
    
    if results:
        for rule, action in results:
            print(f"Rule matched: {rule.rule_text}")
            print(f"Action: {action}")
    else:
        print("No rules matched, packet allowed")`,
    testCases: [
      {
        input: "Packet with 'haxor' content",
        expectedOutput: "alert"
      },
      {
        input: "ICMP packet",
        expectedOutput: "alert"
      },
      {
        input: "SSH connection attempt",
        expectedOutput: "drop"
      }
    ]
  },
  {
    id: "trojan-analysis",
    title: "Defeating Malware – Building Trojans",
    shortDescription: "Implement and analyze Trojan behavior in a safe simulation",
    description: "This module explores how Trojans work by simulating their behavior in a controlled environment. Understanding how malware operates is essential for building effective defenses against real threats.",
    difficulty: "Hard",
    marks: 75,
    howItWorks: [
      "Simulate the dual-nature of Trojans: legitimate functionality with hidden malicious capabilities",
      "Implement methods for hiding malicious code from detection",
      "Create backdoor functionality for remote access",
      "Add capabilities for stealing sensitive information",
      "Analyze these behaviors to understand how to detect and prevent real Trojans"
    ],
    examples: [
      {
        input: "Create a Trojan disguised as a system utility",
        output: "Analysis: File has hidden backdoor and keylogging functionality"
      }
    ],
    initialCode: `class Trojan:
    def __init__(self, filename):
        self.filename = filename
        self.malicious_functions = []
        self.legitimate_functions = []
        self.hidden = False

def create_trojan(filename, legitimate_purpose):
    """Create a simulated Trojan for analysis"""
    trojan = Trojan(filename)
    
    # Add a legitimate purpose to hide the malicious intent
    trojan.legitimate_functions.append(legitimate_purpose)
    
    print(f"Created new file: {filename}")
    print(f"Legitimate purpose: {legitimate_purpose}")
    
    return trojan

def add_malicious_function(trojan, function_name, description):
    """Add a malicious function to the Trojan"""
    trojan.malicious_functions.append({
        "name": function_name,
        "description": description
    })
    print(f"Added hidden function: {function_name}")

def hide_file_from_system(trojan):
    """Make the Trojan hide itself from typical system tools"""
    trojan.hidden = True
    print(f"File {trojan.filename} now hidden from directory listings")

def analyze_suspicious_file(file):
    """Analyze a suspicious file for Trojan characteristics"""
    print(f"\nAnalyzing file: {file.filename}")
    
    # Check for dual nature (legitimate + malicious)
    if file.legitimate_functions and file.malicious_functions:
        print("WARNING: File exhibits dual nature - legitimate frontend with hidden functions")
        print(f"Legitimate purpose: {', '.join(file.legitimate_functions)}")
        print("Hidden malicious functions:")
        for func in file.malicious_functions:
            print(f" - {func['name']}: {func['description']}")
    
    # Check if the file is hiding itself
    if file.hidden:
        print("WARNING: File is attempting to hide from system")
    
    # Overall assessment
    if file.malicious_functions:
        threat_level = "High" if len(file.malicious_functions) > 2 else "Medium"
        print(f"Threat assessment: {threat_level} - File is likely a Trojan")
    else:
        print("Threat assessment: Low - No malicious functions detected")

# Demo: Create and analyze a simulated Trojan
update_app = create_trojan("system_update.exe", "System performance optimizer")

# Add malicious behavior
add_malicious_function(update_app, "keylogger", "Records all keystrokes and sends to remote server")
add_malicious_function(update_app, "backdoor", "Creates hidden admin account with remote access")
add_malicious_function(update_app, "data_theft", "Locates and exfiltrates sensitive files")

# Make it stealthy
hide_file_from_system(update_app)

# Later, a security expert analyzes the file
analyze_suspicious_file(update_app)

# Compare with a legitimate file
print("\n---Comparison with legitimate file---")
legitimate_app = create_trojan("actual_update.exe", "System performance optimizer")
analyze_suspicious_file(legitimate_app)`,
    testCases: [
      {
        input: "system_update.exe with 3 malicious functions",
        expectedOutput: "High"
      },
      {
        input: "actual_update.exe with no malicious functions",
        expectedOutput: "Low"
      }
    ]
  },
  {
    id: "rootkit-hunter",
    title: "Defeating Malware – Rootkit Hunter",
    shortDescription: "Implement tools to detect and analyze system-level rootkits",
    description: "Rootkits are particularly dangerous forms of malware that operate at the system level, often with kernel privileges, making them difficult to detect and remove. This module simulates a rootkit hunter tool to detect these stealthy threats.",
    difficulty: "Hard",
    marks: 80,
    howItWorks: [
      "Scan the system for hidden processes that might indicate rootkit activity",
      "Search for suspicious files and modified system files",
      "Check kernel integrity for signs of unauthorized modifications",
      "Use cross-view detection techniques to find discrepancies between different system views",
      "Generate comprehensive reports on potential rootkit infections"
    ],
    examples: [
      {
        input: "Scan system with hidden processes and modified kernel modules",
        output: "Rootkit detected: 2 hidden processes, 1 suspicious kernel module"
      }
    ],
    initialCode: `class System:
    def __init__(self, name):
        self.name = name
        self.processes = {}
        self.files = {}
        self.hidden_processes = {}
        self.hidden_files = {}
        self.kernel_modules = []

class RootkitHunter:
    def __init__(self):
        self.signatures = []
        self.scan_results = {
            "suspicious_files": [],
            "hidden_processes": [],
            "hidden_files": [],
            "kernel_hook_detected": False
        }
    
    def add_signature(self, signature, description):
        """Add a known rootkit signature"""
        self.signatures.append({
            "signature": signature,
            "description": description
        })
        print(f"Added rootkit signature: {description}")
        
    def scan_processes(self, system):
        """Scan for hidden processes using cross-view technique"""
        print("\nScanning processes...")
        
        # Compare processes visible through different APIs
        for pid, process in system.hidden_processes.items():
            self.scan_results["hidden_processes"].append({
                "pid": pid,
                "name": process
            })
            print(f"Found hidden process: {process} (PID: {pid})")
            
    def scan_files(self, system):
        """Scan for hidden files"""
        print("\nScanning file system...")
        
        # Look for hidden files
        for path, file in system.hidden_files.items():
            self.scan_results["hidden_files"].append({
                "path": path,
                "name": file
            })
            print(f"Found hidden file: {path}")
            
        # Scan known files against rootkit signatures
        for path, file in system.files.items():
            for sig in self.signatures:
                if sig["signature"] in file.lower():
                    self.scan_results["suspicious_files"].append({
                        "path": path,
                        "name": file,
                        "reason": sig["description"]
                    })
                    print(f"Found suspicious file: {path} - {sig['description']}")
                    
    def check_kernel_integrity(self, system):
        """Check for signs of kernel manipulation"""
        print("\nChecking kernel integrity...")
        
        # Check for suspicious kernel modules
        suspicious_modules = ["rootkit", "hidepid", "hidefiles"]
        found_suspicious = False
        
        for module in system.kernel_modules:
            for suspicious in suspicious_modules:
                if suspicious in module.lower():
                    found_suspicious = True
                    print(f"Suspicious kernel module found: {module}")
        
        if found_suspicious:
            self.scan_results["kernel_hook_detected"] = True
            
    def generate_report(self):
        """Generate a summary report of findings"""
        print("\n=== ROOTKIT HUNTER SCAN REPORT ===")
        
        total_findings = (len(self.scan_results["suspicious_files"]) +
                         len(self.scan_results["hidden_processes"]) +
                         len(self.scan_results["hidden_files"]) +
                         (1 if self.scan_results["kernel_hook_detected"] else 0))
        
        if total_findings == 0:
            print("No signs of rootkit infection found. System appears clean.")
            return
            
        print(f"Found {total_findings} indicators of possible rootkit infection!")
        
        if self.scan_results["suspicious_files"]:
            print(f"\n{len(self.scan_results['suspicious_files'])} suspicious files:")
            for file in self.scan_results["suspicious_files"]:
                print(f" - {file['path']}: {file['reason']}")
                
        if self.scan_results["hidden_processes"]:
            print(f"\n{len(self.scan_results['hidden_processes'])} hidden processes:")
            for proc in self.scan_results["hidden_processes"]:
                print(f" - {proc['name']} (PID: {proc['pid']})")
                
        if self.scan_results["hidden_files"]:
            print(f"\n{len(self.scan_results['hidden_files'])} hidden files:")
            for file in self.scan_results["hidden_files"]:
                print(f" - {file['path']}")
                
        if self.scan_results["kernel_hook_detected"]:
            print("\nKernel integrity compromised! System is likely rootkitted.")
            
        print("\nRecommendation: If rootkit infection is confirmed, the safest course")
        print("of action is to back up important data and reinstall the operating system.")

# Demo simulation
system = System("TestSystem")

# Add normal processes and files
system.processes = {
    "1": "system",
    "100": "browser",
    "200": "editor"
}

system.files = {
    "/bin/ls": "ls binary",
    "/etc/passwd": "password file",
    "/tmp/update.sh": "update script"
}

system.kernel_modules = ["networking", "usb", "filesystem"]

# Simulate rootkit infection
system.hidden_processes = {
    "999": "backdoor",
    "1001": "keylogger"
}

system.hidden_files = {
    "/etc/shadow.bak": "stolen passwords",
    "/usr/lib/libroot.so": "rootkit module"
}

system.files["/sbin/modprobe"] = "Infected modprobe with rootkit hooks"

system.kernel_modules.append("hidepid_module")

# Run the rootkit hunter
hunter = RootkitHunter()

# Add some rootkit signatures
hunter.add_signature("rootkit", "Known rootkit pattern")
hunter.add_signature("suterusu", "Suterusu rootkit variant")
hunter.add_signature("hidepid", "Process hiding functionality")

# Scan the system
hunter.scan_processes(system)
hunter.scan_files(system)
hunter.check_kernel_integrity(system)

# Generate report
hunter.generate_report()`,
    testCases: [
      {
        input: "Scan infected system",
        expectedOutput: "indicators of possible rootkit infection"
      }
    ]
  },
  {
    id: "database-security",
    title: "Database Security Implementation",
    shortDescription: "Implement access control, role-based permissions, and authentication for databases",
    description: "Database security is critical for protecting sensitive information. This module focuses on implementing fundamental database security features including access control, authentication, and role-based permissions.",
    difficulty: "Medium",
    marks: 55,
    howItWorks: [
      "Implement secure user authentication with password hashing and salting",
      "Create a role-based access control (RBAC) system for database operations",
      "Assign permissions to roles for specific database operations",
      "Implement table-level and row-level security controls",
      "Verify user permissions before executing database operations"
    ],
    examples: [
      {
        input: "User 'analyst' attempts to access sensitive customer data",
        output: "Access denied: User 'analyst' does not have DELETE permission on 'customers'"
      }
    ],
    initialCode: `import hashlib
import os
import base64

class Database:
    def __init__(self, name):
        self.name = name
        self.tables = {}
        self.users = {}
        self.roles = {}
        self.role_permissions = {}
        self.user_roles = {}
        self.encrypted_columns = {}
        self.encryption_keys = {}
        print(f"Database '{name}' created")

def create_user(db, username, password):
    """Create a database user with a secure password hash"""
    salt = os.urandom(16)
    
    # Use a secure hash with salt
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        100000  # 100,000 iterations
    )
    
    # Store the salt with the hash
    db.users[username] = {
        'salt': salt,
        'password_hash': password_hash
    }
    
    print(f"Created user: {username}")
    return True

def authenticate_user(db, username, password):
    """Authenticate a user against stored credentials"""
    if username not in db.users:
        print(f"User {username} does not exist")
        return False
        
    user = db.users[username]
    salt = user['salt']
    stored_hash = user['password_hash']
    
    # Calculate hash with same salt
    input_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        100000
    )
    
    if input_hash == stored_hash:
        print(f"User {username} authenticated successfully")
        return True
    else:
        print(f"Authentication failed for user {username}")
        return False

def create_table(db, table_name, columns):
    """Create a table in the database"""
    if table_name in db.tables:
        print(f"Table {table_name} already exists")
        return False
        
    db.tables[table_name] = {
        'columns': columns,
        'rows': []
    }
    
    print(f"Created table: {table_name}")
    return True

def create_role(db, role_name):
    """Create a role for access control"""
    if role_name in db.roles:
        print(f"Role {role_name} already exists")
        return False
        
    db.roles[role_name] = True
    db.role_permissions[role_name] = {}
    
    print(f"Created role: {role_name}")
    return True

def grant_permission(db, role_name, table_name, permission):
    """Grant a permission to a role"""
    valid_permissions = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
    
    if role_name not in db.roles:
        print(f"Role {role_name} does not exist")
        return False
        
    if table_name not in db.tables:
        print(f"Table {table_name} does not exist")
        return False
        
    if permission not in valid_permissions:
        print(f"Invalid permission: {permission}")
        return False
        
    if table_name not in db.role_permissions[role_name]:
        db.role_permissions[role_name][table_name] = []
        
    db.role_permissions[role_name][table_name].append(permission)
    print(f"Granted {permission} on {table_name} to role {role_name}")
    return True

def assign_role_to_user(db, username, role_name):
    """Assign a role to a user"""
    if username not in db.users:
        print(f"User {username} does not exist")
        return False
        
    if role_name not in db.roles:
        print(f"Role {role_name} does not exist")
        return False
        
    if username not in db.user_roles:
        db.user_roles[username] = []
        
    db.user_roles[username].append(role_name)
    print(f"Assigned role {role_name} to user {username}")
    return True

def check_permission(db, username, table_name, permission):
    """Check if a user has a specific permission"""
    if username not in db.users:
        print(f"User {username} does not exist")
        return False
        
    if username not in db.user_roles:
        print(f"User {username} has no roles assigned")
        return False
        
    # Check each role the user has
    for role in db.user_roles[username]:
        if table_name in db.role_permissions[role]:
            if permission in db.role_permissions[role][table_name]:
                return True
                
    print(f"User {username} does not have {permission} permission on {table_name}")
    return False

# Demo
db = Database("SecureDB")

# Create users
create_user(db, "admin", "securePass123!")
create_user(db, "analyst", "dataReader456")
create_user(db, "app_user", "userPass789")

# Create tables
create_table(db, "customers", ["id", "name", "email", "credit_card"])
create_table(db, "products", ["id", "name", "price"])

# Create roles
create_role(db, "db_admin")
create_role(db, "data_analyst")
create_role(db, "app_role")

# Assign permissions
grant_permission(db, "db_admin", "customers", "SELECT")
grant_permission(db, "db_admin", "customers", "INSERT")
grant_permission(db, "db_admin", "customers", "UPDATE")
grant_permission(db, "db_admin", "customers", "DELETE")
grant_permission(db, "db_admin", "products", "SELECT")
grant_permission(db, "db_admin", "products", "INSERT")

grant_permission(db, "data_analyst", "customers", "SELECT")
grant_permission(db, "data_analyst", "products", "SELECT")

grant_permission(db, "app_role", "products", "SELECT")

# Assign roles to users
assign_role_to_user(db, "admin", "db_admin")
assign_role_to_user(db, "analyst", "data_analyst")
assign_role_to_user(db, "app_user", "app_role")

# Test access control
print("\nTesting database access control:")
print("1. Can admin select from customers?", 
      check_permission(db, "admin", "customers", "SELECT"))
print("2. Can analyst update customers?", 
      check_permission(db, "analyst", "customers", "UPDATE"))
print("3. Can app_user select from products?", 
      check_permission(db, "app_user", "products", "SELECT"))
print("4. Can app_user select from customers?", 
      check_permission(db, "app_user", "customers", "SELECT"))`,
    testCases: [
      {
        input: "Admin SELECT from customers",
        expectedOutput: "True"
      },
      {
        input: "Analyst UPDATE customers",
        expectedOutput: "False"
      }
    ]
  },
  {
    id: "database-encryption",
    title: "Database Encryption & Integrity Control",
    shortDescription: "Secure stored data using hashing and encryption techniques",
    description: "Protecting data at rest is a critical aspect of database security. This module focuses on implementing encryption for sensitive database columns and integrity verification mechanisms to detect unauthorized data modifications.",
    difficulty: "Hard",
    marks: 65,
    howItWorks: [
      "Implement column-level encryption for sensitive data",
      "Generate and manage encryption keys securely",
      "Create mechanisms to transparently encrypt data during insertion and decrypt during retrieval",
      "Implement data integrity verification using cryptographic hashing",
      "Detect and alert about potential tampering with database content"
    ],
    examples: [
      {
        input: "Insert customer data with credit card number: 4111-1111-1111-1111",
        output: "Credit card stored encrypted, only accessible with decryption key"
      }
    ],
    initialCode: `import hashlib
import os
import base64
from cryptography.fernet import Fernet

class SecureDatabase:
    def __init__(self, name):
        self.name = name
        self.tables = {}
        self.column_encryption = {}  # Tracks which columns are encrypted
        self.encryption_keys = {}    # Encryption keys for each table
        print(f"Secure database '{name}' created")

def generate_encryption_key():
    """Generate a secure encryption key"""
    return Fernet.generate_key()

def encrypt_value(encryption_key, value):
    """Encrypt a value using the provided key"""
    if not isinstance(value, str):
        value = str(value)
        
    f = Fernet(encryption_key)
    encrypted = f.encrypt(value.encode('utf-8'))
    return base64.urlsafe_b64encode(encrypted).decode('ascii')

def decrypt_value(encryption_key, encrypted_value):
    """Decrypt a value using the provided key"""
    try:
        f = Fernet(encryption_key)
        decoded = base64.urlsafe_b64decode(encrypted_value)
        decrypted = f.decrypt(decoded)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def create_table_with_encryption(db, table_name, columns, encrypted_columns):
    """Create a table with specified encrypted columns"""
    if table_name in db.tables:
        print(f"Table {table_name} already exists")
        return False
        
    # Validate that encrypted_columns exist in columns
    for col in encrypted_columns:
        if col not in columns:
            print(f"Column {col} not in table definition")
            return False
            
    # Generate a key for this table
    key = generate_encryption_key()
    db.encryption_keys[table_name] = key
    
    # Create the table
    db.tables[table_name] = {
        'columns': columns,
        'rows': []
    }
    
    # Track encrypted columns
    db.column_encryption[table_name] = encrypted_columns
    
    print(f"Created table: {table_name} with encrypted columns: {', '.join(encrypted_columns)}")
    return True

def insert_row(db, table_name, row_data):
    """Insert a row, encrypting sensitive columns"""
    if table_name not in db.tables:
        print(f"Table {table_name} does not exist")
        return False
        
    table = db.tables[table_name]
    columns = table['columns']
    
    # Validate row data has correct columns
    if set(row_data.keys()) != set(columns):
        print("Row data does not match table columns")
        return False
    
    # Create a copy of the data for insertion
    processed_row = {}
    
    # Encrypt sensitive columns
    encryption_key = db.encryption_keys[table_name]
    encrypted_columns = db.column_encryption.get(table_name, [])
    
    for col, value in row_data.items():
        if col in encrypted_columns:
            # Encrypt sensitive data
            processed_row[col] = encrypt_value(encryption_key, value)
        else:
            # Store non-sensitive data as is
            processed_row[col] = value
    
    # Add row to table
    table['rows'].append(processed_row)
    print(f"Row inserted into {table_name}")
    return True

def query_row(db, table_name, search_column, search_value, decrypt=True):
    """Query a row, optionally decrypting sensitive columns"""
    if table_name not in db.tables:
        print(f"Table {table_name} does not exist")
        return None
        
    table = db.tables[table_name]
    results = []
    
    # Is the search column encrypted?
    encrypted_columns = db.column_encryption.get(table_name, [])
    search_on_encrypted = search_column in encrypted_columns
    
    encryption_key = db.encryption_keys[table_name]
    
    for row in table['rows']:
        match = False
        
        if search_on_encrypted:
            # For encrypted columns, we need to check all rows since we can't
            # compare encrypted values directly
            decrypted_value = decrypt_value(encryption_key, row[search_column])
            match = (decrypted_value == search_value)
        else:
            # For non-encrypted columns, direct comparison works
            match = (row[search_column] == search_value)
            
        if match:
            # Return the row, decrypting sensitive columns if requested
            if decrypt:
                decrypted_row = {}
                for col, value in row.items():
                    if col in encrypted_columns:
                        decrypted_row[col] = decrypt_value(encryption_key, value)
                    else:
                        decrypted_row[col] = value
                results.append(decrypted_row)
            else:
                results.append(row)
                
    return results

def calculate_hash_integrity(db, table_name):
    """Calculate a hash for table integrity verification"""
    if table_name not in db.tables:
        print(f"Table {table_name} does not exist")
        return None
        
    table = db.tables[table_name]
    
    # Create a string representation of all rows
    data_string = ""
    for row in table['rows']:
        # Sort keys to ensure consistent ordering
        for col in sorted(row.keys()):
            data_string += str(row[col])
            
    # Calculate SHA-256 hash
    integrity_hash = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
    return integrity_hash

# Demo
db = SecureDatabase("EncryptedDB")

# Create a table with encrypted columns
create_table_with_encryption(
    db, 
    "customers", 
    ["id", "name", "email", "credit_card", "address"], 
    ["email", "credit_card"]  # Only these columns will be encrypted
)

# Insert some data
insert_row(db, "customers", {
    "id": "1001",
    "name": "John Doe",
    "email": "john@example.com",
    "credit_card": "4111-1111-1111-1111",
    "address": "123 Main St"
})

insert_row(db, "customers", {
    "id": "1002",
    "name": "Jane Smith",
    "email": "jane@example.com",
    "credit_card": "5555-5555-5555-5555",
    "address": "456 Oak Ave"
})

# Query by non-encrypted column
print("\nQuerying by name:")
results = query_row(db, "customers", "name", "John Doe")
if results:
    for row in results:
        print(f"Found: {row}")

# Calculate integrity hash
integrity_hash = calculate_hash_integrity(db, "customers")
print(f"\nTable integrity hash: {integrity_hash}")

# Demonstrate how the hash would change if data is tampered with
original_hash = integrity_hash

# Tampering simulation - directly access a row and modify it
db.tables["customers"]["rows"][0]["address"] = "999 Hacked St"

new_hash = calculate_hash_integrity(db, "customers")
print(f"New hash after tampering: {new_hash}")
print(f"Integrity violated: {original_hash != new_hash}")`,
    testCases: [
      {
        input: "Query for 'John Doe'",
        expectedOutput: "4111-1111-1111-1111"
      },
      {
        input: "Data tampering detection",
        expectedOutput: "Integrity violated: True"
      }
    ]
  }
];
