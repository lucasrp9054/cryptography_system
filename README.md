# cryptography_system
 A cryptographic system involving symmetric and asymmetric cryptography

## Objective:
The goal of this project is to develop an encryption system involving both symmetric and asymmetric cryptography.

## Summary of Features:
* The user can choose which encryption method to use (Symmetric or Asymmetric).
* DES algorithm should be used for the symmetric encryption option.
* RSA algorithm should be used for the asymmetric encryption option.
* For both options:
  - The user can choose to encrypt or decrypt a message.
  - The user must input the text to be encrypted or decrypted.
  - In addition to the message, the user must provide the key (in the case of RSA, only the two prime numbers needed for key generation can be provided).

## Development:
The algorithm will be developed using the Python programming language.

### Installation:
To run this code, you need to have the following libraries installed:

pip install cryptography pycryptodome

These commands will install the necessary dependencies to run the encryption system.

### Running the Code:
To run the code, execute the main script `EncryptionSystem.py`. Follow the instructions provided by the program to choose encryption methods, input text, and keys, and perform encryption or decryption operations.
