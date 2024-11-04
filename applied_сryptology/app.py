from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import tempfile
import os
from PIL import Image
import io
from methods.des_library import des_library_form
from methods.des import des_form
from methods.aes_library import aes_library_form
from methods.aes import aes_form
from methods.merkle_hellman import  merkle_hellman_form, generate_key_pair_route
from methods.bbs import bbs_form, generate_p_q, generate_x0, calculate_period, generate_p_q_from_x0


app = Flask(__name__)

@app.route('/')
def home():
    return render_template('main.html')

@app.route('/main')
def main():
    return render_template('main.html')  

@app.route('/form', methods=['POST'])
def form():
    method = request.form.get('encryption_method')
    if method == 'des_library':
        return redirect(url_for('des_library_form_route'))
    if method == 'des':
        return redirect(url_for('des_form_route'))
    if method == 'aes_library':
        return redirect(url_for('aes_library_form_route'))
    if method == 'aes':
        return redirect(url_for('aes_form_route'))
    if method == 'bbs':
        return redirect(url_for('bbs_form_route'))
    if method == 'merkle_hellman':
        return redirect(url_for('merkle_hellman_form_route'))
    elif method:
        return render_template(get_form_template(method))
    return redirect(url_for('home'))


@app.route('/des_library_form', methods=['GET', 'POST'])
def des_library_form_route():
    return des_library_form(request) 

@app.route('/des_form', methods=['GET', 'POST'])
def des_form_route():
    return des_form(request) 

@app.route('/aes_library_form', methods=['GET', 'POST'])
def aes_library_form_route():
    return aes_library_form(request) 

@app.route('/aes_form', methods=['GET', 'POST'])
def aes_form_route():
    return aes_form(request) 

@app.route('/merkle_hellman_form', methods=['GET', 'POST'])
def merkle_hellman_form_route():
    return merkle_hellman_form(request) 

@app.route('/generate_key_pair', methods=['POST'])
def generate_key_pair():
    return generate_key_pair_route()

@app.route('/bbs_form', methods=['GET', 'POST'])
def bbs_form_route():
    return bbs_form(request) 

@app.route('/generate_values', methods=['POST'])
def generate_values_route():
    bits = 16  
    p, q, n = generate_p_q(bits)
    x0 = generate_x0(n)
    return jsonify({'p': str(p), 'q': str(q), 'n': str(n), 'x0': str(x0)})

@app.route('/calculate_period', methods=['POST'])
def calculate_period_route():
    data = request.get_json()
    n = int(data.get('n'))
    x0 = int(data.get('x0'))
    period = calculate_period(n, x0)
    return jsonify({'period': period})

@app.route('/recalculate_for_x0', methods=['POST'])
def recalculate_for_x0():
    data = request.get_json()
    x0 = int(data.get('x0'))
    p, q = generate_p_q_from_x0(x0)
    n = p * q

    return jsonify({'p': str(p), 'q': str(q), 'n': str(n)})

def get_form_template(method):
    return f'{method}_form.html'

if __name__ == '__main__':
    app.run(debug=True)