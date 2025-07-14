# Secure File Processing System Using Hybrid Cryptography

For this task, I've implemented a secure file processing system that encrypts files of arbitrary size using AES-256 and RSA.

## Usage 

For generating a keypair
```
python keygen.py
```

For encrypting a file
```
python script.py encrypt <input file> <output dir> <public key path> [chunk size]
```

For decrypting a file
```
python script.py decrypt <input dir> <output file> <private key path>
```

For key generation, the `keygen.py` script has been provided. 

## Technical Details

The encryption pipeline is as follows:
1. Split input file into chunks
2. Encrypt each chunk using AES-256 with unique initialization vectors
3. Generate cryptographic checksums for each chunk using SHA-256
4. Encrypt the AES keys using RSA public key cryptography and store them along with metadata such as checksums and chunk information.

The decryption pipeline is as follows:
1. Read the metadata and verify its integrity
2. Decrypt AES keys using RSA and decrypt the chunks
3. Verify the checksums of decrypted chunks
4. Combine decrypted chunks to get the original file.

I'm using the `PyCryptodome` library for cryptographic operations, including AES
encryption, RSA key generation and encryption, SHA checksum computation and
random number generation.

The script supports files of arbitrary size and the chunk size can be configured through
a command-line argument.

All exceptions occuring during encryption and
decryption are caught. A generic error message is printed to avoid leaking program details.

The script is written in Python, so it has cross-platform compatibility.

## Security Considerations
 - **Key Management**: Master key is generated in a cryptographically secure manner. AES keys are generated from this using HKDF. However, nonces are assigned based on the index of the chunk, which I think might be insecure.
 - **IV Generation**: IVs are generated using a cryptographically secure RNG.
 - **Integrity Verification**: I'm implementing various checks to prevent tampering. SHA256 checksums and key fingerprints are checked.
 - **Error Handling**: Errors are caught and a generic error message is printed to prevent leakage of information through the error message.
 - **Side-Channel Resistance**: To avoid timing attacks, a secure function is used to check if two bytearrays are equal.




## Performance

A 100MB input file was generated using the command
```
cat /dev/urandom | head -c 104857600 > file.bin
```

```
$ time python script.py encrypt file.bin encrypted public.pem
Completed.

real    0m0.705s
user    0m0.587s
sys     0m0.114s

$ time python script.py decrypt encrypted/ decrypted.bin private.pem 
Completed.

real    0m2.772s
user    0m1.175s
sys     0m1.582s
```
