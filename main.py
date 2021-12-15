from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
import os
import json
import argparse
import pickle


def key_generation(symmetric_key_path: str, public_key_path: str, private_key_path: str) -> int:
    key = 128
    symmetric_key = algorithms.SM4(os.urandom(16))
    keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    print(private_key)
    print(public_key)

    with open(public_key_path, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(private_key_path, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    encrypted_symmetric = public_key.encrypt(symmetric_key.key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    with open(symmetric_key_path, 'wb') as key_file:
        key_file.write(encrypted_symmetric)
    return key


def text_encryption(text_path: str, private_key_path: str, encrypted_symmetric_path: str,
                    encrypted_text_path: str):
    with open(encrypted_symmetric_path, "rb") as file:
        encrypted_symmetric_key = file.read()
    with open(private_key_path, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key,
                                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    print(decrypted_symmetric_key)
    with open(text_path, "r", encoding='UTF-8') as file:
        text_to_encrypt = file.read()
    padder = padding2.ANSIX923(32).padder()
    text = bytes(text_to_encrypt, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.SM4(decrypted_symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text)
    encrypted_text = {"encrypted_text": c_text, "iv": iv}
    with open(encrypted_text_path, "wb") as file:
        pickle.dump(encrypted_text, file)


def text_decryption(encrypted_text_path: str, private_key_path: str, encrypted_symmetric_path: str,
                    decrypted_text_path: str):
    with open(encrypted_symmetric_path, "rb") as file:
        encrypted_symmetric_key = file.read()
    with open(private_key_path, 'rb') as file:
        private_bytes = file.read()
    d_private_key = load_pem_private_key(private_bytes, password=None)
    decrypted_symmetric_key = d_private_key.decrypt(encrypted_symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))
    with open(encrypted_text_path, 'rb') as file:
        encrypted_text = pickle.load(file)
    text = encrypted_text['encrypted_text']
    iv = encrypted_text['iv']

    cipher = Cipher(algorithms.SM4(decrypted_symmetric_key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    dc_text = decryptor.update(text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(32).unpadder()
    unpadded_dc_text = unpadder.update(dc_text)

    final_text = unpadded_dc_text.decode('UTF-8')
    with open(decrypted_text_path, 'w', encoding='UTF-8') as file:
        file.write(final_text)


parser = argparse.ArgumentParser(description='main.py')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Генерация ключей', dest='generation')
group.add_argument('-enc', '--encryption', help='Шифрование данных')
group.add_argument('-dec', '--decryption', help='Дешифрование данных')
args = parser.parse_args()
if args.generation is not None:
    with open('settings.json') as json_file:
        json_data = json.load(json_file)
        key_generation(json_data['symmetric_key'], json_data['public_key'], json_data['secret_key'])
    print("\nГенерация ключей: Выполнено")
else:
    if args.encryption is not None:
        with open('settings.json') as json_file:
            json_data = json.load(json_file)
            text_encryption(json_data['initial_file'], json_data['secret_key'], json_data['symmetric_key'],
                            json_data['encrypted_file'])
        print("\nШифрование данных: Выполнено")
    else:
        with open('settings.json') as json_file:
            json_data = json.load(json_file)
            text_decryption(json_data['encrypted_file'], json_data['secret_key'], json_data['symmetric_key'],
                            json_data['decrypted_file'])
        print("\nДешифрование данных: Выполнено")
