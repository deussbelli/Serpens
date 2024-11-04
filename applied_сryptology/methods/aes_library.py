from flask import render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tempfile
import os
from PIL import Image
import numpy as np
import time

def get_aes_cipher(key, mode, iv=None):
    if mode == 'ECB':
        return AES.new(key, AES.MODE_ECB)
    elif mode in ['CBC', 'CFB', 'OFB']:
        if iv is None or len(iv) != 16:
            raise ValueError("IV must be 16 bytes long for AES in CBC, CFB, or OFB mode.")
        return AES.new(key, getattr(AES, f"MODE_{mode}"), iv)
    else:
        raise ValueError("Unsupported mode")

def aes_library_form(request):
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
            return render_template('aes_library_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)
    
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
                iv = get_random_bytes(16)  
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
                cipher = get_aes_cipher(key, encryption_mode, iv)
                result_filename = None
                result_path = None
                
                if action == 'encrypt' and file:
                    start_time = time.time() 
                    result_filename = f"encrypted_{file_name}_{encryption_mode}{file_ext}"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    data = file.read()
                    if encryption_mode in ['ECB', 'CBC']:
                        padded_data = pad(data, AES.block_size)
                        encrypted_data = cipher.encrypt(padded_data)
                    else:
                        encrypted_data = cipher.encrypt(data)
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
                    decrypted_data = cipher.decrypt(data)
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

                    cipher = get_aes_cipher(key, encryption_mode, iv)

                    if encryption_mode in ['ECB', 'CBC']:
                        encrypted_data = b''
                        for i in range(0, len(padded_data), 16):
                            block = padded_data[i:i+16]
                            encrypted_data += cipher.encrypt(block)
                    else:
                        encrypted_data = cipher.encrypt(padded_data)

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

                    cipher = get_aes_cipher(key, encryption_mode, iv)

                    if encryption_mode in ['ECB', 'CBC']:
                        decrypted_data = b''
                        for i in range(0, len(padded_encrypted_data), 16):
                            block = padded_encrypted_data[i:i+16]
                            decrypted_data += cipher.decrypt(block)
                    else:
                        decrypted_data = cipher.decrypt(padded_encrypted_data)

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
            except ValueError as e:
                key_message = str(e)
        else:
            key_message = 'Invalid key format. The key must be 16 bytes (32 hex characters).'
            
    return render_template('aes_library_form.html', key_message=key_message, iv_message=iv_message)

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
    if padding_length < 1 or padding_length > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-padding_length]
