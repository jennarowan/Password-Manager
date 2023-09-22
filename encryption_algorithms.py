"""
This file will contain all of the implemented encryption algorithms like AES, RSA, DES, 
and Blowfish.
"""

import random
import sys
import base64

# import the cryptography library to use the encryption algorithms
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def pad(data):
    """This function will pad the data to ensure it is a multiple of 16 bytes."""
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def encrypt_password(password, algorithm_choice):
    """This function will encrypt the user's password with the chosen algorithm."""

    # the users message will be encrypted with the chosen algorithm
    if algorithm_choice == "AES":
        # AES encryption
        # generate a random key for AES
        aes_key = bytes([random.randint(0, 0xFF) for i in range(16)])
        # Pad the message to ensure it is a multiple of 16 bytes
        padded_message = pad(password.encode())
        # create a new AES object
        aes_object = AES.new(aes_key, AES.MODE_ECB)
        # encrypt the message
        encrypted_message = aes_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        # print the encrypted message
        return ciphertext
    elif algorithm_choice == "DES":
        # DES encryption
        # generate a random key for DES
        des_key = bytes([random.randint(0, 0xFF) for i in range(8)])
        # Pad the message to ensure it is a multiple of 8 bytes
        padded_message = pad(password.encode())
        # create a new DES object
        des_object = DES.new(des_key, DES.MODE_ECB)
        # encrypt the message
        encrypted_message = des_object.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        # print the encrypted message
        print("Your message encrypted with DES is: ")
        print(ciphertext)
        return ciphertext
    elif algorithm_choice == "RSA":
        # RSA encryption
        # Generate a random key pair for RSA (public and private keys)
        rsa_key = RSA.generate(2048)
        # Extract the public key for encryption
        rsa_public_key = rsa_key.publickey()
        # Use PKCS1_OAEP padding
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        # Pad the message to ensure it can be encrypted properly
        padded_message = pad(password.encode())
        # Encrypt the message using RSA with OAEP padding
        encrypted_message = cipher_rsa.encrypt(padded_message)
        ciphertext = base64.b64encode(encrypted_message)
        # Print the encrypted message
        print("Your message encrypted with RSA is: ")
        print(ciphertext)
        return ciphertext
