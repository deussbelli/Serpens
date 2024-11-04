from flask import render_template, request, send_file
import tempfile
import os
from PIL import Image
import numpy as np
import time
import io

#  AES-128 (128-біт ключ)

# Таблица S-box
Sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# Зворотня таблица S-box
InvSbox = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

# Rcon для розширення ключа
Rcon = [
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000
]

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = Sbox[state[i][j]]

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = InvSbox[state[i][j]]

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = \
        state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = \
        state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = \
        state[3][3], state[3][0], state[3][1], state[3][2]

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = \
        state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = \
        state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = \
        state[3][1], state[3][2], state[3][3], state[3][0]

def mix_columns(state):
    for i in range(4):
        s0 = state[i][0]
        s1 = state[i][1]
        s2 = state[i][2]
        s3 = state[i][3]
        state[i][0] = mul(0x02, s0) ^ mul(0x03, s1) ^ s2 ^ s3
        state[i][1] = s0 ^ mul(0x02, s1) ^ mul(0x03, s2) ^ s3
        state[i][2] = s0 ^ s1 ^ mul(0x02, s2) ^ mul(0x03, s3)
        state[i][3] = mul(0x03, s0) ^ s1 ^ s2 ^ mul(0x02, s3)

def inv_mix_columns(state):
    for i in range(4):
        s0 = state[i][0]
        s1 = state[i][1]
        s2 = state[i][2]
        s3 = state[i][3]
        state[i][0] = mul(0x0e, s0) ^ mul(0x0b, s1) ^ mul(0x0d, s2) ^ mul(0x09, s3)
        state[i][1] = mul(0x09, s0) ^ mul(0x0e, s1) ^ mul(0x0b, s2) ^ mul(0x0d, s3)
        state[i][2] = mul(0x0d, s0) ^ mul(0x09, s1) ^ mul(0x0e, s2) ^ mul(0x0b, s3)
        state[i][3] = mul(0x0b, s0) ^ mul(0x0d, s1) ^ mul(0x09, s2) ^ mul(0x0e, s3)

def mul(a, b):
    # мнеження в полі Галуа GF(2^8)
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        a &= 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[j][i] ^= (round_key[i] >> (24 - j*8)) & 0xFF

def key_expansion(key):
    key_symbols = [k for k in key]
    if len(key_symbols) < 16:
        for i in range(16 - len(key_symbols)):
            key_symbols.append(0x01)
    key_schedule = []
    for i in range(4):
        key_schedule.append(
            (key_symbols[4*i] << 24) |
            (key_symbols[4*i+1] << 16) |
            (key_symbols[4*i+2] << 8) |
            key_symbols[4*i+3]
        )

    for i in range(4, 44):
        temp = key_schedule[i - 1]
        if i % 4 == 0:
            temp = ((Sbox[(temp >> 16) & 0xFF] << 24) |
                    (Sbox[(temp >> 8) & 0xFF] << 16) |
                    (Sbox[temp & 0xFF] << 8) |
                    (Sbox[(temp >> 24) & 0xFF]))
            temp ^= Rcon[i // 4]
        key_schedule.append(key_schedule[i - 4] ^ temp)
    return key_schedule

def aes_encrypt_block(block, key_schedule):
    state = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[j][i] = block[i*4 + j]

    add_round_key(state, key_schedule[0:4])

    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, key_schedule[4*rnd:4*(rnd+1)])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, key_schedule[40:44])

    output = []
    for i in range(4):
        for j in range(4):
            output.append(state[j][i])
    return bytes(output)

def aes_decrypt_block(block, key_schedule):
    state = [[0]*4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[j][i] = block[i*4 + j]

    add_round_key(state, key_schedule[40:44])

    for rnd in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, key_schedule[4*rnd:4*(rnd+1)])
        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, key_schedule[0:4])

    output = []
    for i in range(4):
        for j in range(4):
            output.append(state[j][i])
    return bytes(output)

def aes_encrypt_ecb(data, key):
    key_schedule = key_expansion(key)
    encrypted_data = b''
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        encrypted_block = aes_encrypt_block(block, key_schedule)
        encrypted_data += encrypted_block
    return encrypted_data

def aes_decrypt_ecb(data, key):
    key_schedule = key_expansion(key)
    decrypted_data = b''
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted_block = aes_decrypt_block(block, key_schedule)
        decrypted_data += decrypted_block
    return decrypted_data

def aes_encrypt_cbc(data, key, iv):
    key_schedule = key_expansion(key)
    encrypted_data = b''
    prev_block = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        block = bytes([block[j] ^ prev_block[j] for j in range(16)])
        encrypted_block = aes_encrypt_block(block, key_schedule)
        encrypted_data += encrypted_block
        prev_block = encrypted_block
    return encrypted_data

def aes_decrypt_cbc(data, key, iv):
    key_schedule = key_expansion(key)
    decrypted_data = b''
    prev_block = iv
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        decrypted_block = aes_decrypt_block(block, key_schedule)
        decrypted_block = bytes([decrypted_block[j] ^ prev_block[j] for j in range(16)])
        decrypted_data += decrypted_block
        prev_block = block
    return decrypted_data

def aes_encrypt_cfb(data, key, iv):
    key_schedule = key_expansion(key)
    encrypted_data = b''
    prev_block = iv
    for i in range(0, len(data), 16):
        encrypted_block = aes_encrypt_block(prev_block, key_schedule)
        block = data[i:i+16]
        cipher_block = bytes([block[j] ^ encrypted_block[j] for j in range(len(block))])
        encrypted_data += cipher_block
        prev_block = cipher_block
    return encrypted_data

def aes_decrypt_cfb(data, key, iv):
    key_schedule = key_expansion(key)
    decrypted_data = b''
    prev_block = iv
    for i in range(0, len(data), 16):
        encrypted_block = aes_encrypt_block(prev_block, key_schedule)
        block = data[i:i+16]
        plain_block = bytes([block[j] ^ encrypted_block[j] for j in range(len(block))])
        decrypted_data += plain_block
        prev_block = block
    return decrypted_data

def aes_encrypt_ofb(data, key, iv):
    key_schedule = key_expansion(key)
    encrypted_data = b''
    output_block = iv
    for i in range(0, len(data), 16):
        output_block = aes_encrypt_block(output_block, key_schedule)
        block = data[i:i+16]
        cipher_block = bytes([block[j] ^ output_block[j] for j in range(len(block))])
        encrypted_data += cipher_block
    return encrypted_data

def aes_decrypt_ofb(data, key, iv):
    return aes_encrypt_ofb(data, key, iv)

def aes_form(request):
    key_message = ''
    iv_message = ''
    
    if request.method == 'POST':
        encryption_mode = request.form.get('encryption_mode')
        key_mode = request.form.get('key_mode')
        iv_method = request.form.get('iv_method')
        action = request.form.get('action')
        file = request.files.get('file')
        
        key = None
        iv = None
        file_name = None
        file_ext = None
        
        if file:
            file_name, file_ext = os.path.splitext(file.filename)
            file_ext = file_ext.lower()  
            
        if not file:
            error_message = 'No file selected.'
            return render_template('aes_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)
    
        if key_mode == 'load':
            key_file = request.files.get('key_file')
            if key_file:
                key = key_file.read().strip()
        elif key_mode == 'enter':
            key_hex = request.form.get('key_input').strip()
            if len(key_hex) == 32:
                key = bytes.fromhex(key_hex)
        elif key_mode == 'generate':
            key_hex = request.form.get('generated_key').strip()
            if len(key_hex) == 32:
                key = bytes.fromhex(key_hex)

        if encryption_mode in ['CBC', 'CFB', 'OFB']:
            if iv_method == 'generate':
                iv_hex = request.form.get('generated_iv').strip()
                if len(iv_hex) == 32:
                    iv = bytes.fromhex(iv_hex)
                    iv_message = iv.hex()
            elif iv_method == 'enter':
                iv_hex = request.form.get('iv').strip()
                if len(iv_hex) == 32:  
                    iv = bytes.fromhex(iv_hex)
                    iv_message = iv.hex()
                else:
                    iv_message = 'IV must be 16 bytes (32 hex characters).'
            elif iv_method == 'upload':
                iv_file = request.files.get('iv_file')
                if iv_file:
                    iv = iv_file.read().strip()
                    if len(iv) != 16:
                        iv_message = 'IV must be 16 bytes (32 hex characters).'
                    else:
                        iv_message = iv.hex()
        
        if key and len(key) == 16:  
            try:
                result_filename = None
                result_path = None
                
                if action == 'encrypt' and file:
                    start_time = time.time() 
                    result_filename = f"encrypted_{file_name}_{encryption_mode}{file_ext}"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    data = file.read()
                    if encryption_mode in ['ECB', 'CBC']:
                        padded_data = pad(data, 16)
                    else:
                        padded_data = data

                    if encryption_mode == 'ECB':
                        encrypted_data = aes_encrypt_ecb(padded_data, key)
                    elif encryption_mode == 'CBC':
                        encrypted_data = aes_encrypt_cbc(padded_data, key, iv)
                    elif encryption_mode == 'CFB':
                        encrypted_data = aes_encrypt_cfb(padded_data, key, iv)
                    elif encryption_mode == 'OFB':
                        encrypted_data = aes_encrypt_ofb(padded_data, key, iv)
                    else:
                        raise ValueError("Unsupported mode")

                    with open(result_path, 'wb') as f:
                        f.write(encrypted_data)
                    end_time = time.time() 
                    encryption_time = end_time - start_time
                    print(f"Encryption time: {encryption_time:.4f} second")

                elif action == 'decrypt' and file:
                    start_time = time.time() 
                    result_filename = f"decrypted_{file_name}_{encryption_mode}{file_ext}"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    data = file.read()

                    if encryption_mode == 'ECB':
                        decrypted_data = aes_decrypt_ecb(data, key)
                    elif encryption_mode == 'CBC':
                        decrypted_data = aes_decrypt_cbc(data, key, iv)
                    elif encryption_mode == 'CFB':
                        decrypted_data = aes_decrypt_cfb(data, key, iv)
                    elif encryption_mode == 'OFB':
                        decrypted_data = aes_decrypt_ofb(data, key, iv)
                    else:
                        raise ValueError("Unsupported mode")

                    if encryption_mode in ['ECB', 'CBC']:
                        unpadded_data = unpad(decrypted_data)
                    else:
                        unpadded_data = decrypted_data

                    with open(result_path, 'wb') as f:
                        f.write(unpadded_data)
                    end_time = time.time() 
                    decryption_time = end_time - start_time
                    print(f"Decryption time: {decryption_time:.4f} second")
                
                if action == 'saveimg' and file:
                    start_time = time.time()
                    image = Image.open(file)
                    if image.mode not in ['RGB', 'RGBA']:
                        image = image.convert('RGB')
                    image_format = image.format

                    image_data = np.array(image)
                    shape = image_data.shape
                    flat_data = image_data.tobytes()


                    padding_length = (16 - (len(flat_data) % 16)) % 16
                    padded_data = flat_data + bytes([0] * padding_length)

                    if encryption_mode == 'ECB':
                        encrypted_data = aes_encrypt_ecb(padded_data, key)
                    elif encryption_mode == 'CBC':
                        encrypted_data = aes_encrypt_cbc(padded_data, key, iv)
                    elif encryption_mode == 'CFB':
                        encrypted_data = aes_encrypt_cfb(padded_data, key, iv)
                    elif encryption_mode == 'OFB':
                        encrypted_data = aes_encrypt_ofb(padded_data, key, iv)
                    else:
                        raise ValueError("Unsupported mode")

                    encrypted_data = encrypted_data[:len(flat_data)]

                    encrypted_image_data = np.frombuffer(encrypted_data, dtype=np.uint8)
                    encrypted_image_data = encrypted_image_data.reshape(shape)
                    encrypted_image = Image.fromarray(encrypted_image_data, mode=image.mode)

                    result_filename = f"encrypted_{file_name}_{encryption_mode}.png"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    encrypted_image.save(result_path, format='PNG')

                    end_time = time.time() 
                    encryption_time = end_time - start_time
                    print(f"Encryption img time: {encryption_time:.4f} seconds")
                    return send_file(result_path, as_attachment=True)
                
                elif action == 'unsaveimg' and file:
                    start_time = time.time()
                    image = Image.open(file)
                    if image.mode not in ['RGB', 'RGBA']:
                        image = image.convert('RGB')

                    encrypted_data = np.array(image)
                    shape = encrypted_data.shape
                    flat_encrypted_data = encrypted_data.tobytes()

                    padding_length = (16 - (len(flat_encrypted_data) % 16)) % 16
                    padded_encrypted_data = flat_encrypted_data + bytes([0] * padding_length)

                    if encryption_mode == 'ECB':
                        decrypted_data = aes_decrypt_ecb(padded_encrypted_data, key)
                    elif encryption_mode == 'CBC':
                        decrypted_data = aes_decrypt_cbc(padded_encrypted_data, key, iv)
                    elif encryption_mode == 'CFB':
                        decrypted_data = aes_decrypt_cfb(padded_encrypted_data, key, iv)
                    elif encryption_mode == 'OFB':
                        decrypted_data = aes_decrypt_ofb(padded_encrypted_data, key, iv)
                    else:
                        raise ValueError("Unsupported mode")

                    decrypted_data = decrypted_data[:len(flat_encrypted_data)]

                    decrypted_image_data = np.frombuffer(decrypted_data, dtype=np.uint8)
                    decrypted_image_data = decrypted_image_data.reshape(shape)
                    decrypted_image = Image.fromarray(decrypted_image_data, mode=image.mode)

                    result_filename = f"decrypted_{file_name}_{encryption_mode}{file_ext}"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    decrypted_image.save(result_path, format=image.format)

                    end_time = time.time() 
                    decryption_time = end_time - start_time
                    print(f"Decryption img time: {decryption_time:.4f} seconds")
                    return send_file(result_path, as_attachment=True)
                if result_path:
                    return send_file(result_path, as_attachment=True) 
            except Exception as e:
                key_message = f'Error: {str(e)}'
        else:
            key_message = 'Invalid key format. The key must be 16 bytes (32 hex characters).'
            
    return render_template('aes_form.html', key_message=key_message, iv_message=iv_message)

def pad(data, block_size):
    """Pad data to be a multiple of block size."""
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    """Remove padding from data."""
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding")
    return data[:-padding_length]
