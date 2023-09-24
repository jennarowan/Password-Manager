"""
This file will contain all of the implemented encryption algorithms like AES, RSA, DES, 
and Blowfish.
"""

# import the cryptography library to use the encryption algorithms
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import random
import sys

# Define master keys for each algorithm
AES_MASTER_KEY = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
DES_MASTER_KEY = b'\x01\x23\x45\x67\x89\xab\xcd\xef'
RSA_KEY = RSA.generate(2048)


def pad(data):
    """This function will pad the data to ensure it is a multiple of 16 bytes."""
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_text(password, algorithm_choice):
    """This function will encrypt the user's password with the chosen algorithm."""

    if algorithm_choice == "AES":
        # AES encryption
        aes_object = AES.new(AES_MASTER_KEY, AES.MODE_ECB)
        padded_message = pad(password.encode())
        encrypted_message = aes_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        return ciphertext
    elif algorithm_choice == "DES":
        # DES encryption
        des_object = DES.new(DES_MASTER_KEY, DES.MODE_ECB)
        padded_message = pad(password.encode())
        encrypted_message = des_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        return ciphertext
    elif algorithm_choice == "RSA":
        # RSA encryption
        rsa_public_key = RSA_KEY.publickey()
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        padded_message = pad(password.encode())
        encrypted_message = cipher_rsa.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        return ciphertext


def decrypt_password(ciphertext, algorithm_choice):
    """This function will decrypt the encrypted password with the chosen algorithm."""

    if algorithm_choice == "AES":
        # AES decryption
        aes_object = AES.new(AES_MASTER_KEY, AES.MODE_ECB)
        decrypted_bytes = aes_object.decrypt(base64.b64decode(ciphertext))
        password = unpad(decrypted_bytes).decode('utf-8')
        return password
    elif algorithm_choice == "DES":
        # DES decryption
        des_object = DES.new(DES_MASTER_KEY, DES.MODE_ECB)
        decrypted_bytes = des_object.decrypt(base64.b64decode(ciphertext))
        password = unpad(decrypted_bytes).decode('utf-8')
        return password
    elif algorithm_choice == "RSA":
        # RSA decryption
        cipher_rsa = PKCS1_OAEP.new(RSA_KEY)
        decrypted_bytes = cipher_rsa.decrypt(base64.b64decode(ciphertext))
        password = unpad(decrypted_bytes).decode('utf-8')
        return password


# Example usage:
algorithm_choice = "DES"  # Change this to the appropriate algorithm
password = "Works"
encrypted_password = encrypt_text(password, algorithm_choice)
print("Password:", password)
print("Encrypted password:", encrypted_password.decode())


# Now, let's decrypt the password
decrypted_password = decrypt_password(encrypted_password, algorithm_choice)
print("Decrypted password:", decrypted_password)
