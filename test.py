from os import path
import base64
import secrets
import string
from datetime import datetime, timezone
import bcrypt

from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import login_user, login_required
from flask_login import logout_user, current_user, LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import CAST
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def pad(data):
    """This function will pad the data to ensure it is a multiple of 16 bytes."""
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def unpad(data):
    """Removes padding and returns data."""
    padding_length = data[-1]
    return data[:-padding_length]

def pad_des(data):
    """This function will pad the data to ensure it is a multiple of 8 bytes."""
    block_size = 8
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def unlock_decrpytion(selection, ciphertext, grand_key):
    if selection == 'one':
        padlock = ciphertext
        combo = grand_key
        print('PADLOCK/COMBO: ')
        print(padlock)
        print(combo)
 
    unlocked = aes_decrypt(padlock, combo)
    return unlocked

def encrypt_text(text_to_encrypt, algorithm_choice, unlock_key):
    print(algorithm_choice)
    padded_message = pad(text_to_encrypt.encode())
    padded_key = pad(str.encode(unlock_key))
    aes_object = AES.new(padded_key, AES.MODE_ECB)
    encrypted_message = aes_object.encrypt(padded_message)
    ciphertext = base64.b64encode(encrypted_message)
    return ciphertext

def aes_decrypt(ciphertext, pass_key):
    """Decrypts and returns plain-text versions of AES."""
    padded_key = pad(str.encode(pass_key))
    aes_object = AES.new(padded_key, AES.MODE_ECB)
    decrypted_bytes = aes_object.decrypt(
         base64.b64decode(ciphertext))
    decrypted_value = unpad(decrypted_bytes).decode('utf-8')
    return decrypted_value


#ciphertext = b'Pr1ab1I4mkNrtqW78AJHSQ=='
#grand_key = 'abc123'
#unseen_key = 'RobotsInDisguise'
#locked_unseen_key = encrypt_text(unseen_key, 'AES', grand_key)
#print(locked_unseen_key)
##unlocked_unseen_key = unlock_decrpytion('one', locked_unseen_key, grand_key)
#print('UNLOCKED UNSEEN KEY:')
#print(unlocked_unseen_key)
#ciphertext = encrypt_text('abcdefghijklm', 'AES', unlocked_unseen_key)

#aes_decrypt(ciphertext, pass_key)

yo = pad_des(str.encode('A8SR2dac'))
print(yo)