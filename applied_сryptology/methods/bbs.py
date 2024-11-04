from flask import render_template, request, send_file, jsonify
import os
import tempfile
import threading
import time
import sympy
from math import gcd
import random

def bbs_form(request):
    if request.method == 'POST':
        action = request.form.get('action')
        p = request.form.get('p')
        q = request.form.get('q')
        n = request.form.get('n')
        x0 = request.form.get('x0')
        file = request.files.get('file')

        if not file:
            error_message = 'No file selected.'
            return render_template('bbs_form.html', error_message=error_message)

        # стрінг в число
        try:
            p = int(p)
            q = int(q)
            n = int(n)
            x0 = int(x0)
        except ValueError:
            error_message = 'Invalid p, q, n or x0 values.'
            return render_template('bbs_form.html', error_message=error_message)

        # перевірка p і q
        if not (sympy.isprime(p) and p % 4 == 3):
            error_message = 'p must be prime and p ≡ 3 mod 4.'
            return render_template('bbs_form.html', error_message=error_message)
        if not (sympy.isprime(q) and q % 4 == 3):
            error_message = 'q must be prime and q ≡ 3 mod 4.'
            return render_template('bbs_form.html', error_message=error_message)
        if gcd(x0, n) != 1:
            error_message = 'x0 must be relatively prime to n.'
            return render_template('bbs_form.html', error_message=error_message)

        if action == 'encrypt':
            result_path = bbs_encrypt(file, n, x0)
        elif action == 'decrypt':
            result_path = bbs_decrypt(file, n, x0)
        else:
            error_message = 'Incorrect action.'
            return render_template('bbs_form.html', error_message=error_message)

        return send_file(result_path, as_attachment=True)

    else:
        return render_template('bbs_form.html')

def bbs_generator(n, seed, length):
    x = seed
    bits = []
    for _ in range(length * 8):
        x = pow(x, 2, n)
        bits.append(x % 2) # Додавання одного біта (0 або 1)
    return bits

def bits_to_bytes(bits):
    """Converts a list of bits into a bytearray."""
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        byte_array.append(byte)
    return byte_array

def bbs_encrypt(file, n, x0):
    start_time = time.time()

    data = file.read()
    data_bytes = bytearray(data)
    length = len(data_bytes)

    # бітовий потік (8 біт на кожен байт)
    key_stream_bits = bbs_generator(n, x0, length)

    # XOR кожен біт даних з відповідним бітом у ключовому потоці
    data_bits = []
    for byte in data_bytes:
        for i in range(8):
            data_bits.append((byte >> (7 - i)) & 1)

    encrypted_bits = [data_bits[i] ^ key_stream_bits[i] for i in range(len(data_bits))]
    encrypted_data = bits_to_bytes(encrypted_bits)

    end_time = time.time()
    encryption_time = end_time - start_time
    print(f"Encryption time: {encryption_time:.4f} seconds")

    result_filename = 'encrypted_' + file.filename
    result_path = os.path.join(tempfile.gettempdir(), result_filename)
    with open(result_path, 'wb') as f:
        f.write(encrypted_data)
    return result_path

def bbs_decrypt(file, n, x0):
    start_time = time.time()

    data = file.read()
    data_bytes = bytearray(data)
    length = len(data_bytes)

    # бітовий потік (8 біт на кожен байт)
    key_stream_bits = bbs_generator(n, x0, length)

    # XOR кожен біт даних з відповідним бітом у ключовому потоці
    data_bits = []
    for byte in data_bytes:
        for i in range(8):
            data_bits.append((byte >> (7 - i)) & 1)

    decrypted_bits = [data_bits[i] ^ key_stream_bits[i] for i in range(len(data_bits))]
    decrypted_data = bits_to_bytes(decrypted_bits)

    end_time = time.time()
    decryption_time = end_time - start_time
    print(f"Decryption time: {decryption_time:.4f} seconds")

    result_filename = 'decrypted_' + file.filename
    result_path = os.path.join(tempfile.gettempdir(), result_filename)
    with open(result_path, 'wb') as f:
        f.write(decrypted_data)
    return result_path



def generate_p_q(bits=16):
    while True:
        p = sympy.randprime(2**(bits-1), 2**bits)
        if p % 4 == 3:
            break
    while True:
        q = sympy.randprime(2**(bits-1), 2**bits)
        if q % 4 == 3 and q != p:
            break
    n = p * q
    return p, q, n

def generate_x0(n):
    while True:
        x0 = random.randrange(2, n)
        if gcd(x0, n) == 1:
            return x0

def calculate_period(n, x0):
    x = x0
    seen = set()
    period = 0
    while True:
        x = pow(x, 2, n)
        if x in seen:
            break
        seen.add(x)
        period += 1
    return period

def generate_p_q_from_x0(x0, bits=16):
    # x0 як seed для генерації
    random.seed(x0)

    # генерація p
    while True:
        p_candidate = random.randrange(2**(bits-1), 2**bits)
        if sympy.isprime(p_candidate) and p_candidate % 4 == 3:
            p = p_candidate
            break

    # генерація q
    while True:
        q_candidate = random.randrange(2**(bits-1), 2**bits)
        if sympy.isprime(q_candidate) and q_candidate % 4 == 3 and q_candidate != p:
            q = q_candidate
            break

    return p, q