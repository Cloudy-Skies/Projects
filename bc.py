#import Crypto
import numpy as np
from Crypto.Cipher import AES

def main():
    key = key_gen()
    iv = IV_gen()
    header_size = 54
    info = [key, iv]

    encrypt_file('mustang.bmp','out1.bmp', header_size, 'cbc',info)
    decrypt_file('out1.bmp','out2.bmp', header_size, 'cbc',info)

def aes_ecb_encrypt(key, plaintext,block_size):
    max_val = len(plaintext) - 1
    cipher = AES.new(key,AES.MODE_ECB)
    pos = 0
    result = b''

    while((pos + block_size-1) <= max_val):
        result += get_ciphertext(cipher, plaintext[pos:pos+block_size])
        pos+=block_size
    
    tmp = plaintext[pos:] + b'\0'*(block_size-len(plaintext[pos:]))
    result += get_ciphertext(cipher,tmp)
    return result

def aes_ecb_decrypt(key,ciphertext,block_size):
    max_val = len(ciphertext) - 1
    cipher = AES.new(key,AES.MODE_ECB)
    pos = 0
    result = b''

    while((pos + block_size-1) <= max_val):
        result += get_plaintext(cipher, ciphertext[pos:pos+block_size])
        pos+=block_size
    
    # tmp = ciphertext[pos:] + b'\0'*(block_size-len(ciphertext[pos:]))
    tmp = ciphertext[pos:]
    result += get_plaintext(cipher,tmp)
    return result

def aes_cbc_encrypt(key, plaintext, block_size, IV):
    max_val = len(plaintext) - 1
    cipher = AES.new(key,AES.MODE_ECB)
    pos = 0
    result = b''
    prev_cipher = IV

    while((pos + block_size-1) <= max_val):
        tmp = byte_xor(plaintext[pos:pos+block_size], prev_cipher)
        prev_cipher = get_ciphertext(cipher, tmp)
        result += prev_cipher
        pos+=block_size
    
    tmp = byte_xor(prev_cipher, (plaintext[pos:] + b'\0'*(block_size-len(plaintext[pos:]))))
    result += get_ciphertext(cipher,tmp)
    return result

def aes_cbc_decrypt(key, ciphertext, block_size, IV):
    max_val = len(ciphertext) - 1
    cipher = AES.new(key,AES.MODE_ECB)
    pos = 0
    result = b''
    prev_cipher = IV

    while((pos + block_size-1) <= max_val):
        tmp = get_plaintext(cipher, ciphertext[pos:pos+block_size])
        plaintext = byte_xor(tmp, prev_cipher)

        result += plaintext
        prev_cipher = ciphertext[pos:pos+block_size]
        pos+=block_size
    
    tmp = get_ciphertext(cipher,ciphertext[pos:])
    plaintext = byte_xor(prev_cipher, tmp)

    result += plaintext
    return result

def get_ciphertext(cipher,plaintext):
    cipher_text = cipher.encrypt(plaintext)
    return cipher_text

def get_plaintext(cipher,ciphertext):
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def byte_xor(b1,b2):
    return bytes([a ^ b for a, b in zip(b1,b2)])

def open_file(fileName, header_size):
    with open(fileName,'rb') as f:
        bytes = f.read()
    f.close()

    header = bytes[:header_size]
    data = bytes[header_size:]

    return header,data

def key_gen():
    return Crypto.Random.get_random_bytes(16)

def IV_gen():
    return Crypto.Random.get_random_bytes(16)

def encrypt_file(inputFilename, outputFilename, header_size, mode, info):
    header,data = open_file(inputFilename, header_size)
    key = info[0]

    if mode.lower() == 'cbc':
        encrypted = aes_cbc_encrypt(key, data, 16, info[1])
    else: 
        encrypted = aes_ecb_encrypt(key, data, 16)
    
    enc_bytes = header + encrypted
    with open(outputFilename,'wb') as f1:
        f1.write(enc_bytes)
    f1.close()

    print(info)

def decrypt_file(inputFilename, outputFilename, header_size, mode, info):
    header,data = open_file(inputFilename, header_size)
    key = info[0]

    if mode.lower() == 'cbc':
        decrypted = aes_cbc_decrypt(key, data, 16, info[1])
    else:    
        decrypted = aes_ecb_decrypt(key, data, 16)

    dec_bytes = header + decrypted
    with open(outputFilename,'wb') as f2:
        f2.write(dec_bytes)
    f2.close()

    print(info)

if __name__ == '__main__':
    main()


