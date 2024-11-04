from flask import render_template, request, send_file, jsonify, Flask
from Crypto.Random import get_random_bytes
from PIL import Image
import time, io, os, tempfile
import numpy as np
import multiprocessing

def generate_key():
    key = get_random_bytes(8)
    if len(key) != 8:
        raise ValueError("Invalid DES key length. Expected 8 bytes.")
    return key

def generate_iv():
    iv = get_random_bytes(8)
    if len(iv) != 8:
        raise ValueError("Invalid DES IV length. Expected 8 bytes.")
    return iv

initial_key_permutation = [57, 49,  41, 33,  25,  17,  9,
                           1, 58,  50, 42,  34,  26, 18,
                           10,  2,  59, 51,  43,  35, 27,
                           19, 11,   3, 60,  52,  44, 36,
                           63, 55,  47, 39,  31,  23, 15,
                           7, 62,  54, 46,  38,  30, 22,
                           14,  6,  61, 53,  45,  37, 29,
                           21, 13,   5, 28,  20,  12,  4]

initial_message_permutation = [58, 50, 42, 34, 26, 18, 10, 2,
                               60, 52, 44, 36, 28, 20, 12, 4,
                               62, 54, 46, 38, 30, 22, 14, 6,
                               64, 56, 48, 40, 32, 24, 16, 8,
                               57, 49, 41, 33, 25, 17,  9, 1,
                               59, 51, 43, 35, 27, 19, 11, 3,
                               61, 53, 45, 37, 29, 21, 13, 5,
                               63, 55, 47, 39, 31, 23, 15, 7]

key_shift_sizes = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

sub_key_permutation = [14, 17, 11, 24,  1,  5,
                       3, 28, 15,  6, 21, 10,
                       23, 19, 12,  4, 26,  8,
                       16,  7, 27, 20, 13,  2,
                       41, 52, 31, 37, 47, 55,
                       30, 40, 51, 45, 33, 48,
                       44, 49, 39, 56, 34, 53,
                       46, 42, 50, 36, 29, 32]

message_expansion = [32,  1,  2,  3,  4,  5,
                     4,  5,  6,  7,  8,  9,
                     8,  9, 10, 11, 12, 13,
                     12, 13, 14, 15, 16, 17,
                     16, 17, 18, 19, 20, 21,
                     20, 21, 22, 23, 24, 25,
                     24, 25, 26, 27, 28, 29,
                     28, 29, 30, 31, 32,  1]

S1 = [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
       0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
       4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
      15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]

S2 = [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
       3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
       0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
      13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]

S3 = [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
      13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
      13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
       1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]

S4 = [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
      13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
      10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
       3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]

S5 = [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
      14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
       4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
      11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]

S6 = [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
      10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
       9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
       4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]

S7 = [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
      13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
       1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
       6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]

S8 = [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
       1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
       7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
       2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]

S_boxes = [S1, S2, S3, S4, S5, S6, S7, S8]

P = [16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25]

final_permutation = [40,  8, 48, 16, 56, 24, 64, 32,
                     39,  7, 47, 15, 55, 23, 63, 31,
                     38,  6, 46, 14, 54, 22, 62, 30,
                     37,  5, 45, 13, 53, 21, 61, 29,
                     36,  4, 44, 12, 52, 20, 60, 28,
                     35,  3, 43, 11, 51, 19, 59, 27,
                     34,  2, 42, 10, 50, 18, 58, 26,
                     33,  1, 41,  9, 49, 17, 57, 25]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def s_box_substitution(bits):
    sub_blocks = [bits[i:i+6] for i in range(0, 48, 6)]
    output = []
    for i, block in enumerate(sub_blocks):
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        value = S_boxes[i][row * 16 + col]
        output += [(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1]
    return output

def f_function(right_bits, sub_key):
    expanded_right = [right_bits[i - 1] for i in message_expansion]
    xor_result = xor(expanded_right, sub_key)
    substituted_bits = s_box_substitution(xor_result)
    permuted_bits = [substituted_bits[i - 1] for i in P]
    return permuted_bits

def des_round(left, right, sub_key):
    new_right = xor(left, f_function(right, sub_key))
    return right, new_right

def generate_sub_keys(key_bits):
    key_permuted = [key_bits[i - 1] for i in initial_key_permutation]
    left, right = key_permuted[:28], key_permuted[28:]
    sub_keys = []
    for shift in key_shift_sizes:
        left = left[shift:] + left[:shift]
        right = right[shift:] + right[:shift]
        combined_key = left + right
        sub_key = [combined_key[i - 1] for i in sub_key_permutation]
        sub_keys.append(sub_key)
    return sub_keys

def bits_to_bytes(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = int(''.join(map(str, bits[i:i+8])), 2)
        byte_array.append(byte)
    return bytes(byte_array)

def string_to_bits(string):
    bits = ''.join(format(byte, '08b') for byte in string)
    return [int(bit) for bit in bits]

def pad_message(message_bits):
    padding_len = 8 - ((len(message_bits) // 8) % 8)
    pad_value = padding_len
    pad_byte = format(pad_value, '08b')
    pad_bits = [int(bit) for bit in pad_byte] * padding_len
    return message_bits + pad_bits

def unpad_message(message_bits):
    if len(message_bits) % 8 != 0:
        return message_bits
    pad_byte = ''.join(map(str, message_bits[-8:]))
    pad_value = int(pad_byte, 2)
    if pad_value < 1 or pad_value > 8:
        return message_bits
    pad_bits = [int(bit) for bit in pad_byte] * pad_value
    if message_bits[-pad_value*8:] != pad_bits:
        return message_bits
    return message_bits[:-pad_value*8]

#################################################

def init_worker(sub_keys_param):
    global sub_keys
    sub_keys = sub_keys_param

def process_block_encrypt(block):
    block = [block[i - 1] for i in initial_message_permutation]
    left, right = block[:32], block[32:]
    for sub_key in sub_keys:
        left, right = des_round(left, right, sub_key)
    combined = right + left
    return [combined[i - 1] for i in final_permutation]

def process_block_decrypt(block):
    block = [block[i - 1] for i in initial_message_permutation]
    left, right = block[:32], block[32:]
    for sub_key in reversed(sub_keys):
        left, right = des_round(left, right, sub_key)
    combined = right + left
    return [combined[i - 1] for i in final_permutation]

def des_ecb_encrypt(plain_text_bits, key_bits):
    sub_keys_local = generate_sub_keys(key_bits)
    plain_text_bits = pad_message(plain_text_bits)
    blocks = [plain_text_bits[i:i+64] for i in range(0, len(plain_text_bits), 64)]
    with multiprocessing.Pool(initializer=init_worker, initargs=(sub_keys_local,)) as pool:
        cipher_blocks = pool.map(process_block_encrypt, blocks)
    cipher_text_bits = []
    for block in cipher_blocks:
        cipher_text_bits += block
    return bits_to_bytes(cipher_text_bits)

def des_ecb_decrypt(encrypted_message, key_bits):
    sub_keys_local = generate_sub_keys(key_bits)
    encrypted_message_bits = string_to_bits(encrypted_message)
    blocks = [encrypted_message_bits[i:i+64] for i in range(0, len(encrypted_message_bits), 64)]
    with multiprocessing.Pool(initializer=init_worker, initargs=(sub_keys_local,)) as pool:
        decrypted_blocks = pool.map(process_block_decrypt, blocks)
    decrypted_message_bits = []
    for block in decrypted_blocks:
        decrypted_message_bits += block
    decrypted_message_bits = unpad_message(decrypted_message_bits)
    return bits_to_bytes(decrypted_message_bits)

#################################################

def des_cbc_encrypt(plain_text_bits, key_bits, iv_bits):
    sub_keys = generate_sub_keys(key_bits)
    plain_text_bits = pad_message(plain_text_bits)
    cipher_text_bits = []
    previous_block = iv_bits
    for block_start in range(0, len(plain_text_bits), 64):
        block = plain_text_bits[block_start:block_start+64]
        block = xor(block, previous_block)
        block = [block[i - 1] for i in initial_message_permutation]
        left, right = block[:32], block[32:]
        for sub_key in sub_keys:
            left, right = des_round(left, right, sub_key)
        combined = right + left
        encrypted_block = [combined[i - 1] for i in final_permutation]
        cipher_text_bits += encrypted_block
        previous_block = encrypted_block
    return bits_to_bytes(cipher_text_bits)

def des_cbc_decrypt(encrypted_message, key_bits, iv_bits):
    sub_keys = generate_sub_keys(key_bits)
    encrypted_message_bits = string_to_bits(encrypted_message)
    decrypted_message_bits = []
    previous_block = iv_bits
    for block_start in range(0, len(encrypted_message_bits), 64):
        block = encrypted_message_bits[block_start:block_start+64]
        block_permuted = [block[i - 1] for i in initial_message_permutation]
        left, right = block_permuted[:32], block_permuted[32:]
        for sub_key in reversed(sub_keys):
            left, right = des_round(left, right, sub_key)
        combined = right + left
        decrypted_block = [combined[i - 1] for i in final_permutation]
        decrypted_block = xor(decrypted_block, previous_block)
        decrypted_message_bits += decrypted_block
        previous_block = block
    decrypted_message_bits = unpad_message(decrypted_message_bits)
    return bits_to_bytes(decrypted_message_bits)

#################################################

def des_cfb_encrypt(plain_text_bits, key_bits, iv_bits):
    plain_text_bits = pad_message(plain_text_bits)
    cipher_text_bits = []
    previous_block = iv_bits
    sub_keys = generate_sub_keys(key_bits)
    for block_start in range(0, len(plain_text_bits), 64):
        encrypted_iv = previous_block
        encrypted_iv = [encrypted_iv[i - 1] for i in initial_message_permutation]
        left, right = encrypted_iv[:32], encrypted_iv[32:]
        for sub_key in sub_keys:
            left, right = des_round(left, right, sub_key)
        combined = right + left
        encrypted_iv = [combined[i - 1] for i in final_permutation]
        block = plain_text_bits[block_start:block_start+64]
        cipher_block = xor(block, encrypted_iv)
        cipher_text_bits += cipher_block
        previous_block = cipher_block
    return bits_to_bytes(cipher_text_bits)

def des_cfb_decrypt(encrypted_message, key_bits, iv_bits):
    encrypted_message_bits = string_to_bits(encrypted_message)
    decrypted_message_bits = []
    previous_block = iv_bits
    sub_keys = generate_sub_keys(key_bits)
    for block_start in range(0, len(encrypted_message_bits), 64):
        encrypted_iv = previous_block
        encrypted_iv = [encrypted_iv[i - 1] for i in initial_message_permutation]
        left, right = encrypted_iv[:32], encrypted_iv[32:]
        for sub_key in sub_keys:
            left, right = des_round(left, right, sub_key)
        combined = right + left
        encrypted_iv = [combined[i - 1] for i in final_permutation]
        block = encrypted_message_bits[block_start:block_start+64]
        decrypted_block = xor(block, encrypted_iv)
        decrypted_message_bits += decrypted_block
        previous_block = block
    decrypted_message_bits = unpad_message(decrypted_message_bits)
    return bits_to_bytes(decrypted_message_bits)

#################################################

def des_ofb_encrypt(plain_text_bits, key_bits, iv_bits):
    plain_text_bits = pad_message(plain_text_bits)
    cipher_text_bits = []
    keystream = iv_bits
    sub_keys = generate_sub_keys(key_bits)
    for block_start in range(0, len(plain_text_bits), 64):
        keystream = [keystream[i - 1] for i in initial_message_permutation]
        left, right = keystream[:32], keystream[32:]
        for sub_key in sub_keys:
            left, right = des_round(left, right, sub_key)
        combined = right + left
        keystream = [combined[i - 1] for i in final_permutation]
        block = plain_text_bits[block_start:block_start+64]
        cipher_block = xor(block, keystream)
        cipher_text_bits += cipher_block
    return bits_to_bytes(cipher_text_bits)

def des_ofb_decrypt(encrypted_message, key_bits, iv_bits):
    encrypted_message_bits = string_to_bits(encrypted_message)
    decrypted_message_bits = []
    keystream = iv_bits
    sub_keys = generate_sub_keys(key_bits)
    for block_start in range(0, len(encrypted_message_bits), 64):
        keystream = [keystream[i - 1] for i in initial_message_permutation]
        left, right = keystream[:32], keystream[32:]
        for sub_key in sub_keys:
            left, right = des_round(left, right, sub_key)
        combined = right + left
        keystream = [combined[i - 1] for i in final_permutation]
        block = encrypted_message_bits[block_start:block_start+64]
        decrypted_block = xor(block, keystream)
        decrypted_message_bits += decrypted_block
    decrypted_message_bits = unpad_message(decrypted_message_bits)
    return bits_to_bytes(decrypted_message_bits)

#################################################
def des_encrypt_message(message, key, iv, mode):
    key_bits = string_to_bits(key)
    message_bits = string_to_bits(message)
    
    if mode == 'ECB':
        return des_ecb_encrypt(message_bits, key_bits)
    elif mode == 'CBC':
        iv_bits = string_to_bits(iv)
        return des_cbc_encrypt(message_bits, key_bits, iv_bits)
    elif mode == 'CFB':
        iv_bits = string_to_bits(iv)
        return des_cfb_encrypt(message_bits, key_bits, iv_bits)
    elif mode == 'OFB':
        iv_bits = string_to_bits(iv)
        return des_ofb_encrypt(message_bits, key_bits, iv_bits)
    else:
        raise ValueError("Unsupported encryption mode")

def des_decrypt_message(encrypted_message, key, iv, mode):
    key_bits = string_to_bits(key)
    
    if mode == 'ECB':
        return des_ecb_decrypt(encrypted_message, key_bits)
    elif mode == 'CBC':
        iv_bits = string_to_bits(iv)
        return des_cbc_decrypt(encrypted_message, key_bits, iv_bits)
    elif mode == 'CFB':
        iv_bits = string_to_bits(iv)
        return des_cfb_decrypt(encrypted_message, key_bits, iv_bits)
    elif mode == 'OFB':
        iv_bits = string_to_bits(iv)
        return des_ofb_decrypt(encrypted_message, key_bits, iv_bits)
    else:
        raise ValueError("Unsupported decryption mode")

def des_encrypt_block(block_bytes, key_bits, sub_keys):
    block_bits = string_to_bits(block_bytes)
    block_bits = [block_bits[i - 1] for i in initial_message_permutation]
    left, right = block_bits[:32], block_bits[32:]
    for sub_key in sub_keys:
        left, right = des_round(left, right, sub_key)
    combined = right + left
    cipher_block_bits = [combined[i - 1] for i in final_permutation]
    return bits_to_bytes(cipher_block_bits)

def des_decrypt_block(block_bytes, key_bits, sub_keys):
    block_bits = string_to_bits(block_bytes)
    block_bits = [block_bits[i - 1] for i in initial_message_permutation]
    left, right = block_bits[:32], block_bits[32:]
    for sub_key in reversed(sub_keys):
        left, right = des_round(left, right, sub_key)
    combined = right + left
    plain_block_bits = [combined[i - 1] for i in final_permutation]
    return bits_to_bytes(plain_block_bits)

def des_form(request):
    key_message = ''
    iv_message = ''
    error_message = ''

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

        if key_mode == 'load':
            key_file = request.files.get('key_file')
            if key_file:
                key = key_file.read()
                if len(key) != 8:
                    key_message = 'The key must be 8 bytes (16 hex characters).'
                    return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)
        elif key_mode in ['enter', 'generate']:
            key_hex = request.form.get('key_input' if key_mode == 'enter' else 'generate_key')
            key = bytes.fromhex(key_hex)

        if iv_method == 'upload':
            iv_file = request.files.get('iv_file')
            if iv_file:
                iv = iv_file.read()
                if len(iv) != 8:
                    iv_message = 'IV must be 8 bytes (16 hex characters).'
                    return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)
        elif iv_method in ['enter', 'generate']:
            iv_hex = request.form.get('iv_input' if iv_method == 'enter' else 'generate_iv')
            iv = bytes.fromhex(iv_hex)

        if not file:
            error_message = 'No file selected.'
            return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)

        if key is None or (encryption_mode in ['CBC', 'CFB', 'OFB'] and iv is None):
            error_message = 'The key and IV are required for the selected mode.'
            return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)

        key_bits = string_to_bits(key)
        sub_keys = generate_sub_keys(key_bits)
        if encryption_mode in ['CBC', 'CFB', 'OFB']:
            iv_bits = string_to_bits(iv)

        if action == 'encrypt':
            start_time = time.time()
            file_data = file.read()
            encrypted_data = des_encrypt_message(file_data, key, iv, encryption_mode)
            end_time = time.time()
            encryption_time = end_time - start_time
            print(f"Encryption time: {encryption_time:.4f} seconds")
            return send_file(io.BytesIO(encrypted_data), download_name=f"encrypted_{file_name}_{encryption_mode}{file_ext}", as_attachment=True)
        elif action == 'decrypt':
            start_time = time.time()
            file_data = file.read()
            decrypted_data = des_decrypt_message(file_data, key, iv, encryption_mode)
            end_time = time.time()
            decryption_time = end_time - start_time
            print(f"Decryption time: {decryption_time:.4f} seconds")
            return send_file(io.BytesIO(decrypted_data), download_name=f"decrypted_{file_name}_{encryption_mode}{file_ext}", as_attachment=True)

        elif action == 'saveimg' and file:
            start_time = time.time()
            if file_ext in ['.png', '.bmp']:
                try:
                    image = Image.open(file)
                    image_array = np.array(image)
                    flat_array = image_array.flatten()
                    image_bytes = flat_array.tobytes()

                    if encryption_mode == 'ECB':
                        # Паралельна обробка блоків для ECB
                        blocks = [image_bytes[i:i+8] for i in range(0, len(image_bytes), 8)]
                        with multiprocessing.Pool(initializer=init_worker, initargs=(sub_keys,)) as pool:
                            encrypted_blocks = pool.map(des_encrypt_block_wrapper, blocks)
                        encrypted_bytes = b''.join(encrypted_blocks)
                    else:
                        encrypted_bytes = b''
                        previous_block = iv_bits
                        for i in range(0, len(image_bytes), 8):
                            block = image_bytes[i:i+8]
                            if len(block) < 8:
                                block += bytes(8 - len(block))
                            block_bits = string_to_bits(block)
                            if encryption_mode == 'CBC':
                                block_bits = xor(block_bits, previous_block)
                                encrypted_block = des_encrypt_block(bits_to_bytes(block_bits), key_bits, sub_keys)
                                previous_block = string_to_bits(encrypted_block)
                            elif encryption_mode == 'CFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                cipher_block_bits = xor(block_bits, encrypted_iv_bits)
                                encrypted_block = bits_to_bytes(cipher_block_bits)
                                previous_block = cipher_block_bits
                            elif encryption_mode == 'OFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                cipher_block_bits = xor(block_bits, encrypted_iv_bits)
                                encrypted_block = bits_to_bytes(cipher_block_bits)
                                previous_block = encrypted_iv_bits
                            encrypted_bytes += encrypted_block

                    encrypted_bytes = encrypted_bytes[:len(image_bytes)]
                    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
                    encrypted_array = encrypted_array.reshape(image_array.shape)
                    encrypted_image = Image.fromarray(encrypted_array, mode=image.mode)

                    result_filename = f"encrypted_{file_name}_{encryption_mode}{file_ext}"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    encrypted_image.save(result_path)
                    
                    end_time = time.time()
                    encryption_time = end_time - start_time
                    print(f"Encryption img time: {encryption_time:.4f} seconds")
                    return send_file(result_path, as_attachment=True, download_name=os.path.basename(result_path))
                except Exception as e:
                    error_message = f"Error while processing image: {str(e)}"
                    return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)
            elif file_ext == '.jpg':
                try:
                    image = Image.open(file)
                    if image.mode != 'RGB':
                        image = image.convert('RGB')
                    image_array = np.array(image)
                    flat_array = image_array.flatten()
                    image_bytes = flat_array.tobytes()

                    if encryption_mode == 'ECB':
                        # Паралельна обробка блоків для ECB
                        blocks = [image_bytes[i:i+8] for i in range(0, len(image_bytes), 8)]
                        with multiprocessing.Pool(initializer=init_worker, initargs=(sub_keys,)) as pool:
                            encrypted_blocks = pool.map(des_encrypt_block_wrapper, blocks)
                        encrypted_bytes = b''.join(encrypted_blocks)
                    else:
                        encrypted_bytes = b''
                        previous_block = iv_bits
                        for i in range(0, len(image_bytes), 8):
                            block = image_bytes[i:i+8]
                            if len(block) < 8:
                                block += bytes(8 - len(block))
                            block_bits = string_to_bits(block)
                            if encryption_mode == 'CBC':
                                block_bits = xor(block_bits, previous_block)
                                encrypted_block = des_encrypt_block(bits_to_bytes(block_bits), key_bits, sub_keys)
                                previous_block = string_to_bits(encrypted_block)
                            elif encryption_mode == 'CFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                cipher_block_bits = xor(block_bits, encrypted_iv_bits)
                                encrypted_block = bits_to_bytes(cipher_block_bits)
                                previous_block = cipher_block_bits
                            elif encryption_mode == 'OFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                cipher_block_bits = xor(block_bits, encrypted_iv_bits)
                                encrypted_block = bits_to_bytes(cipher_block_bits)
                                previous_block = encrypted_iv_bits
                            encrypted_bytes += encrypted_block

                    encrypted_bytes = encrypted_bytes[:len(image_bytes)]
                    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
                    encrypted_array = encrypted_array.reshape(image_array.shape)
                    encrypted_image = Image.fromarray(encrypted_array, mode='RGB')

                    result_filename = f"encrypted_{file_name}_{encryption_mode}.png"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    encrypted_image.save(result_path)

                    end_time = time.time()
                    encryption_time = end_time - start_time
                    print(f"Encryption img time: {encryption_time:.4f} seconds")
                    return send_file(result_path, as_attachment=True, download_name=os.path.basename(result_path))
                except Exception as e:
                    error_message = f"Error when encrypting JPEG file: {str(e)}"
                    return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)

        elif action == 'unsaveimg' and file:
            start_time = time.time()
            if file_ext in ['.png', '.bmp']:
                try:
                    image = Image.open(file)
                    encrypted_array = np.array(image)
                    flat_array = encrypted_array.flatten()
                    encrypted_bytes = flat_array.tobytes()

                    if encryption_mode == 'ECB':
                        # Паралельна обробка блоків для ECB
                        blocks = [encrypted_bytes[i:i+8] for i in range(0, len(encrypted_bytes), 8)]
                        with multiprocessing.Pool(initializer=init_worker, initargs=(sub_keys,)) as pool:
                            decrypted_blocks = pool.map(des_decrypt_block_wrapper, blocks)
                        decrypted_bytes = b''.join(decrypted_blocks)
                    else:
                        decrypted_bytes = b''
                        previous_block = iv_bits
                        for i in range(0, len(encrypted_bytes), 8):
                            block = encrypted_bytes[i:i+8]
                            if len(block) < 8:
                                block += bytes(8 - len(block))
                            block_bits = string_to_bits(block)
                            if encryption_mode == 'CBC':
                                decrypted_block = des_decrypt_block(block, key_bits, sub_keys)
                                decrypted_block_bits = string_to_bits(decrypted_block)
                                decrypted_block_bits = xor(decrypted_block_bits, previous_block)
                                decrypted_block = bits_to_bytes(decrypted_block_bits)
                                previous_block = block_bits
                            elif encryption_mode == 'CFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                decrypted_block_bits = xor(block_bits, encrypted_iv_bits)
                                decrypted_block = bits_to_bytes(decrypted_block_bits)
                                previous_block = block_bits
                            elif encryption_mode == 'OFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                decrypted_block_bits = xor(block_bits, encrypted_iv_bits)
                                decrypted_block = bits_to_bytes(decrypted_block_bits)
                                previous_block = encrypted_iv_bits
                            decrypted_bytes += decrypted_block

                    decrypted_bytes = decrypted_bytes[:len(flat_array)]
                    decrypted_array = np.frombuffer(decrypted_bytes, dtype=np.uint8)
                    decrypted_array = decrypted_array.reshape(encrypted_array.shape)
                    decrypted_image = Image.fromarray(decrypted_array, mode=image.mode)

                    result_filename = f"decrypted_{file_name}_{encryption_mode}{file_ext}"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    decrypted_image.save(result_path)
                    
                    end_time = time.time()
                    decryption_time = end_time - start_time
                    print(f"Decryption img time: {decryption_time:.4f} seconds")
                    return send_file(result_path, as_attachment=True, download_name=os.path.basename(result_path))
                except Exception as e:
                    error_message = f"Error while processing image: {str(e)}"
                    return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)
                
            elif file_ext == '.jpg':
                try:
                    image = Image.open(file)
                    if image.mode != 'RGB':
                        image = image.convert('RGB')
                    encrypted_array = np.array(image)
                    flat_array = encrypted_array.flatten()
                    encrypted_bytes = flat_array.tobytes()

                    if encryption_mode == 'ECB':
                        # Паралельна обробка блоків для ECB
                        blocks = [encrypted_bytes[i:i+8] for i in range(0, len(encrypted_bytes), 8)]
                        with multiprocessing.Pool(initializer=init_worker, initargs=(sub_keys,)) as pool:
                            decrypted_blocks = pool.map(des_decrypt_block_wrapper, blocks)
                        decrypted_bytes = b''.join(decrypted_blocks)
                    else:
                        decrypted_bytes = b''
                        previous_block = iv_bits
                        for i in range(0, len(encrypted_bytes), 8):
                            block = encrypted_bytes[i:i+8]
                            if len(block) < 8:
                                block += bytes(8 - len(block))
                            block_bits = string_to_bits(block)
                            if encryption_mode == 'CBC':
                                decrypted_block = des_decrypt_block(block, key_bits, sub_keys)
                                decrypted_block_bits = string_to_bits(decrypted_block)
                                decrypted_block_bits = xor(decrypted_block_bits, previous_block)
                                decrypted_block = bits_to_bytes(decrypted_block_bits)
                                previous_block = block_bits
                            elif encryption_mode == 'CFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                decrypted_block_bits = xor(block_bits, encrypted_iv_bits)
                                decrypted_block = bits_to_bytes(decrypted_block_bits)
                                previous_block = block_bits
                            elif encryption_mode == 'OFB':
                                encrypted_iv = des_encrypt_block(bits_to_bytes(previous_block), key_bits, sub_keys)
                                encrypted_iv_bits = string_to_bits(encrypted_iv)
                                decrypted_block_bits = xor(block_bits, encrypted_iv_bits)
                                decrypted_block = bits_to_bytes(decrypted_block_bits)
                                previous_block = encrypted_iv_bits
                            decrypted_bytes += decrypted_block

                    decrypted_bytes = decrypted_bytes[:len(flat_array)]
                    decrypted_array = np.frombuffer(decrypted_bytes, dtype=np.uint8)
                    decrypted_array = decrypted_array.reshape(encrypted_array.shape)
                    decrypted_image = Image.fromarray(decrypted_array, mode='RGB')

                    result_filename = f"decrypted_{file_name}_{encryption_mode}.jpg"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    decrypted_image.save(result_path, 'JPEG', quality=95)

                    end_time = time.time()
                    decryption_time = end_time - start_time
                    print(f"Decryption img time: {decryption_time:.4f} seconds")
                    return send_file(result_path, as_attachment=True, download_name=os.path.basename(result_path))
                except Exception as e:
                    error_message = f"Error when decrypting JPEG file: {str(e)}"
                    return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)

    return render_template('des_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)

# Додаткові функції-обгортки для multiprocessing
def des_encrypt_block_wrapper(block):
    if len(block) < 8:
        block += bytes(8 - len(block))
    return des_encrypt_block(block, None, sub_keys)

def des_decrypt_block_wrapper(block):
    if len(block) < 8:
        block += bytes(8 - len(block))
    return des_decrypt_block(block, None, sub_keys)
