from flask import render_template, request, send_file, jsonify, Flask
from Crypto.Random import get_random_bytes
from PIL import Image
import time, io, os, tempfile
import numpy as np
import multiprocessing
from flask import render_template, request, redirect, url_for
import io
import random
import math
from sympy import mod_inverse 

def merkle_hellman_form(request):
    if request.method == 'GET':
        return render_template('merkle_hellman_form.html')
    else:
        try:
            action = request.form.get('action')
            file = request.files.get('file')
            public_key_file = request.files.get('public_key_file')
            private_key_file = request.files.get('private_key_file')

            if action == 'encrypt':
                start_time = time.time() 
                if not file or not public_key_file:
                    return 'Encryption requires a file and a public key.', 400

                public_key = read_key_file(public_key_file)
                encrypted_data = encrypt(file.read(), public_key)
                
                end_time = time.time() 
                encryption_time = end_time - start_time
                print(f"Encryption time: {encryption_time:.4f} second")

                return send_file(
                    io.BytesIO(encrypted_data),
                    as_attachment=True,
                    download_name='encrypted.txt'
                )

            elif action == 'decrypt':
                start_time = time.time() 
                if not file or not private_key_file:
                    return 'Decryption requires a file and a private key.', 400

                private_key = read_private_key_file(private_key_file)
                decrypted_data = decrypt(file.read(), private_key)

                end_time = time.time() 
                decryption_time = end_time - start_time
                print(f"Decryption time: {decryption_time:.4f} second")

                return send_file(
                    io.BytesIO(decrypted_data),
                    as_attachment=True,
                    download_name='decrypted.txt'
                )
            else:
                return 'Invalid action.', 400
        except Exception as e:
            return f'An error occurred: {str(e)}', 500

def read_key_file(key_file):
    key_data = key_file.read().decode()
    key = list(map(int, key_data.strip().split()))
    return key

def read_private_key_file(key_file):
    key_data = key_file.read().decode()
    lines = key_data.strip().split('\n')
    w = list(map(int, lines[0].split()))
    q = int(lines[1])
    r = int(lines[2])
    return (w, q, r)

def encrypt(data, public_key):
    bits = []
    for byte in data:
        bits.extend([int(bit) for bit in format(byte, '08b')])
    ciphertext = []
    n = len(public_key)
    for i in range(0, len(bits), n):
        chunk = bits[i:i+n]
        if len(chunk) < n:
            chunk += [0]*(n - len(chunk))
        c = sum(bit * pk for bit, pk in zip(chunk, public_key))
        ciphertext.append(c)
    encrypted_data = '\n'.join(map(str, ciphertext)).encode()
    return encrypted_data

def decrypt(encrypted_data, private_key):
    w, q, r = private_key
    try:
        r_inv = mod_inverse(r, q)
    except ValueError:
        raise Exception('Обратный элемент не существует для заданных r и q.')

    ciphertext = list(map(int, encrypted_data.decode().strip().split()))
    plaintext_bits = []
    for c in ciphertext:
        c_prime = (c * r_inv) % q
        bits = solve_superincreasing_knapsack(w, c_prime)
        if bits is None:
            raise Exception(f'Не удалось решить супервозрастающий рюкзак для c\' = {c_prime}')
        plaintext_bits.extend(bits)

    bytes_data = bytearray()
    for i in range(0, len(plaintext_bits), 8):
        byte_bits = plaintext_bits[i:i+8]
        byte = int(''.join(map(str, byte_bits)), 2)
        bytes_data.append(byte)
    return bytes_data

def solve_superincreasing_knapsack(w, c):
    result = []
    for weight in reversed(w):
        if weight <= c:
            result.insert(0,1)
            c -= weight
        else:
            result.insert(0,0)
    if c != 0:
        return None
    return result

def generate_superincreasing_sequence(n, start=2):
    w = []
    total = 0
    for _ in range(n):
        next_w = random.randint(total + 1, 2*total + start)
        w.append(next_w)
        total += next_w
    return w

def generate_keys(n=64):
    w = generate_superincreasing_sequence(n)
    total_w = sum(w)
    q = random.randint(total_w + 1, 2 * total_w)
    r = random.randint(2, q - 1)
    while math.gcd(r, q) != 1:
        r = random.randint(2, q - 1)
    beta = [(r * wi) % q for wi in w]
    return (w, q, r, beta)

def generate_key_pair_route():
    w, q, r, beta = generate_keys()
    private_key_data = ' '.join(map(str, w)) + '\n' + str(q) + '\n' + str(r)
    public_key_data = ' '.join(map(str, beta))
    response = jsonify({
        'public_key': public_key_data,
        'private_key': private_key_data
    })
    return response