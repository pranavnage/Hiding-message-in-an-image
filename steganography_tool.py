import cv2
import numpy as np
import os
import hashlib
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import json
import zlib
import argparse
import sys

class SimpleSecureSteganography:
    def __init__(self):
        self.backend = default_backend()
    
    def derive_keys(self, password: str, salt: bytes = None):
        """Derive encryption keys using PBKDF2"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 64 bytes for two 32-byte keys
            salt=salt,
            iterations=500000,  # High iteration count
            backend=self.backend
        )
        
        derived = kdf.derive(password.encode())
        aes_key = derived[:32]  # First 32 bytes for AES
        auth_key = derived[32:] # Last 32 bytes for authentication
        return aes_key, auth_key, salt
    
    def encrypt(self, message: str, password: str):
        """Encrypt with AES-256-GCM"""
        # Compress first
        compressed = zlib.compress(message.encode(), level=9)
        
        # Derive keys
        aes_key, auth_key, salt = self.derive_keys(password)
        
        # Generate random nonce
        nonce = secrets.token_bytes(12)  # GCM nonce
        
        # Encrypt with AES-GCM (provides authentication)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(compressed) + encryptor.finalize()
        
        # Package everything
        return {
            'salt': salt,
            'nonce': nonce,
            'ciphertext': ciphertext,
            'auth_tag': encryptor.tag,
            'original_size': len(message)
        }
    
    def decrypt(self, encrypted_data: dict, password: str):
        """Decrypt AES-256-GCM"""
        # Derive same keys
        aes_key, auth_key, _ = self.derive_keys(password, encrypted_data['salt'])
        
        # Decrypt with authentication
        cipher = Cipher(
            algorithms.AES(aes_key), 
            modes.GCM(encrypted_data['nonce'], encrypted_data['auth_tag']), 
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        compressed = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        
        # Decompress
        return zlib.decompress(compressed).decode()
    
    def hide(self, image_path: str, message: str, password: str, output_path: str = None):
        """Hide encrypted message in image"""
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Cannot read image")
        
        # Encrypt
        encrypted = self.encrypt(message, password)
        
        # Serialize to binary
        data = json.dumps({
            'salt': base64.b64encode(encrypted['salt']).decode(),
            'nonce': base64.b64encode(encrypted['nonce']).decode(),
            'ciphertext': base64.b64encode(encrypted['ciphertext']).decode(),
            'auth_tag': base64.b64encode(encrypted['auth_tag']).decode(),
            'size': encrypted['original_size']
        })
        
        # Add end marker
        data += "###END###"
        
        # Convert to bits
        bits = ''.join(format(ord(c), '08b') for c in data)
        
        # Check capacity
        h, w, c = img.shape
        max_bits = h * w * c
        if len(bits) > max_bits:
            raise ValueError("Message too large")
        
        # Embed data in LSB sequentially
        bit_index = 0
        for i in range(h):
            for j in range(w):
                for k in range(c):
                    if bit_index < len(bits):
                        img[i, j, k] = (img[i, j, k] & 0xFE) | int(bits[bit_index])
                        bit_index += 1
        
        # Save
        if output_path is None:
            output_path = os.path.splitext(image_path)[0] + '_hidden.png'
        
        cv2.imwrite(output_path, img)
        return output_path
    
    def reveal(self, image_path: str, password: str):
        """Extract and decrypt message"""
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Cannot read image")
        
        h, w, c = img.shape
        
        # Extract all LSB bits until we find the end marker
        bits = ''
        for i in range(h):
            for j in range(w):
                for k in range(c):
                    bits += str(img[i, j, k] & 1)
                    
                    # Check for end marker every 8 bits (1 byte)
                    if len(bits) % 8 == 0:
                        # Convert current bits to text
                        current_text = ''
                        for idx in range(0, len(bits), 8):
                            byte = bits[idx:idx+8]
                            if len(byte) == 8:
                                current_text += chr(int(byte, 2))
                        
                        # Check if we found the end marker
                        if "###END###" in current_text:
                            data = current_text.split("###END###")[0]
                            break
                else:
                    continue
                break
            else:
                continue
            break
        else:
            raise ValueError("No hidden data found")
        
        # Parse JSON
        try:
            encrypted_data = json.loads(data)
        except:
            raise ValueError("Invalid hidden data format")
        
        # Reconstruct encrypted package
        package = {
            'salt': base64.b64decode(encrypted_data['salt']),
            'nonce': base64.b64decode(encrypted_data['nonce']),
            'ciphertext': base64.b64decode(encrypted_data['ciphertext']),
            'auth_tag': base64.b64decode(encrypted_data['auth_tag']),
            'original_size': encrypted_data['size']
        }
        
        # Decrypt
        return self.decrypt(package, password)

def main():
    parser = argparse.ArgumentParser(description='Simple Secure Steganography')
    parser.add_argument('action', choices=['hide', 'reveal'])
    parser.add_argument('-i', '--image', required=True)
    parser.add_argument('-m', '--message')
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-o', '--output')
    
    args = parser.parse_args()
    stego = SimpleSecureSteganography()
    
    try:
        if args.action == 'hide':
            if not args.message:
                print("Message required for hide")
                return
            
            output = stego.hide(args.image, args.message, args.password, args.output)
            print(f"Hidden in: {output}")
            
        elif args.action == 'reveal':
            message = stego.reveal(args.image, args.password)
            print(message)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
