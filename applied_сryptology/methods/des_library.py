from flask import render_template, request, send_file
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import tempfile
import os
from PIL import Image, PngImagePlugin
import numpy as np
import io
import time  

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

def get_cipher(key, mode, iv=None):
    if mode == 'ECB':
        return DES.new(key, DES.MODE_ECB)
    elif mode in ['CBC', 'CFB', 'OFB']:
        if iv is None or len(iv) != 8:
            raise ValueError("IV must be 8 bytes long for DES in CBC, CFB, or OFB mode.")
        return DES.new(key, getattr(DES, f"MODE_{mode}"), iv)
    else:
        raise ValueError("Unsupported mode")
   
  
def des_library_form(request):
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
            return render_template('des_library_form.html', key_message=key_message, iv_message=iv_message, error_message=error_message)
    
        if key_mode == 'load':
            key_file = request.files.get('key_file')
            if key_file:
                key = key_file.read().strip()
        elif key_mode == 'enter':
            key_hex = request.form.get('key_input').strip()
            if len(key_hex) == 16:
                key = bytes.fromhex(key_hex)
        elif key_mode == 'generate':
            key_hex = request.form.get('generated_key').strip()
            if len(key_hex) == 16:
                key = bytes.fromhex(key_hex)

        if encryption_mode in ['CBC', 'CFB', 'OFB']:
            if iv_method == 'generate':
                iv = get_random_bytes(8)  
                iv_message = iv.hex()
            elif iv_method == 'enter':
                iv_hex = request.form.get('iv').strip()
                if len(iv_hex) == 16:  
                    iv = bytes.fromhex(iv_hex)
                    iv_message = iv.hex()
                else:
                    iv_message = 'IV must be 8 bytes (16 hex characters).'
            elif iv_method == 'upload':
                iv_file = request.files.get('iv_file')
                if iv_file:
                    iv = iv_file.read().strip()
                    if len(iv) != 8:
                        iv_message = 'IV must be 8 bytes (16 hex characters).'
                    else:
                        iv_message = iv.hex()
        
        if key and len(key) == 8:  
            try:
                cipher = get_cipher(key, encryption_mode, iv)
                result_filename = None
                result_path = None
                
                if action == 'encrypt' and file:
                    start_time = time.time() 
                    result_filename = f"encrypted_{file_name}_{encryption_mode}{file_ext}"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    data = file.read()
                    padded_data = pad(data)
                    encrypted_data = cipher.encrypt(padded_data)
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
                    unpadded_data = unpad(decrypted_data)
                    with open(result_path, 'wb') as f:
                        f.write(unpadded_data)
                    end_time = time.time() 
                    decryption_time = end_time - start_time
                    print(f"Decryption time: {decryption_time:.4f} second")
                
                if result_path:
                    return send_file(result_path, as_attachment=True)                
          
                    
                elif action == 'saveimg' and file:
                    start_time = time.time() 
                    if file_ext in ['.png', '.bmp']:
                        image = Image.open(file)
                        image_array = np.array(image)
                        flat_array = image_array.flatten()
                        image_bytes = flat_array.tobytes()
                        
                        if len(image_bytes) % 8 != 0:
                            padding_length = 8 - (len(image_bytes) % 8)
                            image_bytes += bytes([0]*padding_length)
                        
                        encrypted_bytes = b''
                        for i in range(0, len(image_bytes), 8):
                            block = image_bytes[i:i+8]
                            encrypted_block = cipher.encrypt(block)
                            encrypted_bytes += encrypted_block
                        encrypted_bytes = encrypted_bytes[:len(flat_array)]
                        encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
                        encrypted_array = encrypted_array.reshape(image_array.shape)
                        encrypted_image = Image.fromarray(encrypted_array, mode=image.mode)
                        
                        result_filename = f"encrypted_{file_name}_{encryption_mode}{file_ext}"
                        result_path = os.path.join(tempfile.gettempdir(), result_filename)
                        encrypted_image.save(result_path)
                        
                        end_time = time.time() 
                        encryption_time = end_time - start_time
                        print(f"Encryption img time: {encryption_time:.4f} second")
                        return send_file(result_path, as_attachment=True)
                    
                    elif file_ext == '.jpg':
                        image = Image.open(file)
                        
                        # Конвертуємо зображення у RGB (якщо воно не в цьому форматі)
                        if image.mode != 'RGB':
                            image = image.convert('RGB')
                        
                        image_array = np.array(image)
                        flat_array = image_array.flatten()
                        image_bytes = flat_array.tobytes()
                        
                        if len(image_bytes) % 8 != 0:
                            padding_length = 8 - (len(image_bytes) % 8)
                            image_bytes += bytes([0]*padding_length)
                        
                        encrypted_bytes = b''
                        for i in range(0, len(image_bytes), 8):
                            block = image_bytes[i:i+8]
                            encrypted_block = cipher.encrypt(block)
                            encrypted_bytes += encrypted_block
                        encrypted_bytes = encrypted_bytes[:len(flat_array)]
                        encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
                        encrypted_array = encrypted_array.reshape(image_array.shape)
                        encrypted_image = Image.fromarray(encrypted_array, mode='RGB')
                        
                        result_filename = f"encrypted_{file_name}_{encryption_mode}.png"
                        result_path = os.path.join(tempfile.gettempdir(), result_filename)
                        encrypted_image.save(result_path)
                        
                        end_time = time.time() 
                        encryption_time = end_time - start_time
                        print(f"Encryption img time: {encryption_time:.4f} second")
                        return send_file(result_path, as_attachment=True)
                
                elif action == 'unsaveimg' and file:
                    start_time = time.time() 
                    if file_ext in ['.png']:
                        image = Image.open(file)
                        encrypted_array = np.array(image)
                        flat_array = encrypted_array.flatten()
                        encrypted_bytes = flat_array.tobytes()
                        
                        decrypted_bytes = b''
                        for i in range(0, len(encrypted_bytes), 8):
                            block = encrypted_bytes[i:i+8]
                            decrypted_block = cipher.decrypt(block)
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
                        print(f"Decryption img time: {decryption_time:.4f} second")
                        return send_file(result_path, as_attachment=True)
                    elif file_ext == '.jpg':
                      if image.mode != 'RGB':
                        image = image.convert('RGB')
                    
                    encrypted_array = np.array(image)
                    flat_array = encrypted_array.flatten()
                    encrypted_bytes = flat_array.tobytes()
                    
                    decrypted_bytes = b''
                    for i in range(0, len(encrypted_bytes), 8):
                        block = encrypted_bytes[i:i+8]
                        decrypted_block = cipher.decrypt(block)
                        decrypted_bytes += decrypted_block
                    decrypted_bytes = decrypted_bytes[:len(flat_array)]
                    decrypted_array = np.frombuffer(decrypted_bytes, dtype=np.uint8)
                    decrypted_array = decrypted_array.reshape(encrypted_array.shape)
                    decrypted_image = Image.fromarray(decrypted_array, mode='RGB')
                    
                    result_filename = f"decrypted_{file_name}_{encryption_mode}.jpg"
                    result_path = os.path.join(tempfile.gettempdir(), result_filename)
                    decrypted_image.save(result_path, quality=95)
                    
                    end_time = time.time() 
                    decryption_time = end_time - start_time
                    print(f"Decryption img time: {decryption_time:.4f} second")
                    return send_file(result_path, as_attachment=True)
                      

            except ValueError as e:
                key_message = str(e)
        else:
            key_message = 'Invalid key format. The key must be 8 bytes (16 hex characters).'
            
    return render_template('des_library_form.html', key_message=key_message, iv_message=iv_message)

def pad(data):
    """Pad data to be a multiple of DES block size."""
    block_size = DES.block_size
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    """Remove padding from data."""
    padding_length = data[-1]
    return data[:-padding_length]