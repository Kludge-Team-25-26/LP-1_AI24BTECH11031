import base64
from math import ceil
import json
import os
import sys

from Crypto.Cipher import AES
from Crypto.Hash import SHA256 
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol import KDF

import hmac

def to_chunks(xs, size):
    """
    Splits an array into chunks
    """
    for start in range(0, len(xs), size):
        yield xs[start: start + size]

def safe_equals(b1: bytes, b2: bytes):
    """
    Byte equality comparison that mitigates timing attacks
    """
    if len(b1) != len(b2):
        fake = bytes(len(b2))
        hmac.compare_digest(fake, b2)
        return False
    return hmac.compare_digest(b1, b2)

def _encrypt_file(input_file_path, output_directory, public_key_path, chunk_size=1048576):
    # Create the output directory
    os.makedirs(output_directory, exist_ok=True)

    # Read the data, generate an AES master key
    data = open(input_file_path, 'rb').read()
    original_size = len(data)
    master_key = Random.get_random_bytes(32)

    # Read RSA public key
    with open(public_key_path) as f:
        pem_data = f.read()
    public_key = RSA.import_key(pem_data)    
    cipher = PKCS1_OAEP.new(public_key)

    encrypted_keys = []
    chunk_metadata = []
    checksums = []

    # Encrypt each chunk
    for i, chunk in enumerate(to_chunks(data, chunk_size)):
        # Generate random IV and use HKDF to create a key for the chunk
        iv = Random.get_random_bytes(12)
        key = key = KDF.HKDF(master_key, 32, i.to_bytes(4), SHA256)
        aes = AES.new(key, mode=AES.MODE_GCM, nonce=iv)

        # Encrpt and compute checksum
        encrypted = aes.encrypt(chunk) 
        checksum = SHA256.new(encrypted).digest()
 
        chunk_metadata.append({
            "chunk_id": i + 1,
            "encrypted_filename": f"chunk_{i+1:03}.enc",
            "iv": base64.b64encode(iv).decode("UTF-8"),
            "checksum": checksum.hex(),
            "size": len(encrypted)
        })

        # Write chunk to file
        with open(f'{output_directory}/chunk_{i+1:03}.enc', 'wb') as f:
            f.write(encrypted)

        checksums.append(checksum)
        encrypted_key = cipher.encrypt(key)
        encrypted_keys.append(encrypted_key)

    # Write encrypted keys
    with open(f'{output_directory}/encrypted_keys.bin', 'wb') as f:
        f.writelines(encrypted_keys)

    # Write checksums
    with open(f'{output_directory}/checksums.txt', 'w') as f:
        for checksum in checksums:
            f.write(base64.b64encode(checksum).decode('UTF-8') + '\n')

    encrypted_master_key = cipher.encrypt(master_key)
    fingerprint = SHA256.new(public_key.export_key(format='DER')).digest()

    metadata = {
        "file_info": {
            "original_name": input_file_path,
            "original_size": original_size,
            "chunk_size": chunk_size,
            "total_chunks": ceil(original_size / chunk_size),
            "encryption_algorithm": "AES-256-GCM",
            "key_encryption": "RSA-4096",
        },
        "chunks": chunk_metadata,
        "keys": {
            "encrypted_master_key": base64.b64encode(encrypted_master_key).decode("UTF-8"),
            "public_key_fingerprint": base64.b64encode(fingerprint).decode("UTF-8")
        }
    }

    # Write metadata
    with open(f'{output_directory}/metadata.json', 'w') as f:
        json.dump(metadata, f, indent=4)

    return 1

def _decrypt_file(encrypted_directory, output_file_path, private_key_path):
    # Read metadata
    with open(f'{encrypted_directory}/metadata.json') as f:
        metadata = json.load(f)

    # Read checksums
    with open(f'{encrypted_directory}/checksums.txt') as f:
        checksums = f.read().splitlines()

    # Read encrypted keys
    with open(f'{encrypted_directory}/encrypted_keys.bin', 'rb') as f:
        encrypted_keys = list(to_chunks(f.read(), 256))

    key = RSA.import_key(open(private_key_path).read())

    # Should have private key data
    if not key.has_private():
        return 0

    cipher = PKCS1_OAEP.new(key)
    fingerprint = base64.b64decode(metadata['keys']['public_key_fingerprint'])
    expected_fingerprint = SHA256.new(key.public_key().export_key(format='DER')).digest()

    # Fingerprint should match
    if not safe_equals(fingerprint, expected_fingerprint):
        return 0

    # Equal no. of chunks, checksums and encrypted keys
    if not (len(metadata['chunks']) == len(checksums) and len(checksums) == len(encrypted_keys)):
        return 0

    # Sum of chunk sizes == file size 
    if sum(chunk['size'] for chunk in metadata['chunks']) != metadata['file_info']['original_size']:
        return 0

    encrypted_master_key = base64.b64decode(metadata['keys']['encrypted_master_key'])
    master_key = cipher.decrypt(encrypted_master_key)

    data = bytes()

    for chunk, checksum, encrypted_key in zip(metadata['chunks'], checksums, encrypted_keys):
        key = cipher.decrypt(encrypted_key) 
        iv = base64.b64decode(chunk['iv'])
        aes = AES.new(key, mode=AES.MODE_GCM, nonce=iv)

        # Verify that key matches the one generated from master_key
        expected_key = KDF.HKDF(master_key, 32, (chunk['chunk_id']-1).to_bytes(4), SHA256)
        if key != expected_key:
            return 0

        with open(f'{encrypted_directory}/{chunk['encrypted_filename']}', 'rb') as f:
            chunk_data = f.read()

        # Chunk size should match 
        if len(chunk_data) != chunk['size']:
            return 0

        # Checksum should match
        if SHA256.new(chunk_data).digest() != base64.b64decode(checksum):
            return 0

        decrypted = aes.decrypt(chunk_data)
        data = data + decrypted

    with open(output_file_path, 'wb') as f:
        f.write(data)

    return 1

# With error handling
def encrypt_file(*args):
    try:
        return _encrypt_file(*args)
    except:
        return 0

def decrypt_file(*args):
    try:
        return _decrypt_file(*args)
    except:
        return 0


def parse_args():
    if len(sys.argv) < 2:
        return None

    if sys.argv[1] == 'encrypt':
        if len(sys.argv) not in [5, 6]:
            return None
        chunk_size = 1048576
        if len(sys.argv) == 6:
            chunk_size = int(sys.argv[5])
        return lambda: encrypt_file(sys.argv[2], sys.argv[3], sys.argv[4], chunk_size)
    
    elif sys.argv[1] == 'decrypt':
        if len(sys.argv) != 5:
            return None
        return lambda: decrypt_file(sys.argv[2], sys.argv[3], sys.argv[4])

if __name__ == '__main__':
    fn = parse_args()
    if fn is None:
        print("Usage:")
        print(f"\t{sys.argv[0]} encrypt <input file> <output dir> <public key path> [chunk size]")
        print(f"\t{sys.argv[0]} decrypt <input dir> <output file> <private key path>")
        exit()

    # Check return code
    if fn() == 0:
        print("Aborted.")
    else:
        print("Completed.")