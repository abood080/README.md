import socket
from Crypto.PublicKey import RSA  # type: ignore
from Crypto.Cipher import PKCS1_OAEP, AES  # type: ignore
from Crypto.Random import get_random_bytes  # type: ignore

# Client connection settings
HOST = '127.0.0.1'
PORT = 65432

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Step 1: Receive the public RSA key from the server
server_public_key_data = client_socket.recv(2048)
server_public_key = RSA.import_key(server_public_key_data)

# Step 2: Generate a random AES key
symmetric_key = get_random_bytes(16)

# Step 3: Encrypt the AES key using server's public RSA key
rsa_cipher = PKCS1_OAEP.new(server_public_key)
encrypted_symmetric_key = rsa_cipher.encrypt(symmetric_key)

# Step 4: Send the encrypted AES key to the server
client_socket.send(encrypted_symmetric_key)

# Step 5: Get message input from the user
message = input("Enter the message to send securely: ")

# Step 6: Encrypt the message using AES
aes_cipher = AES.new(symmetric_key, AES.MODE_EAX)
ciphertext, tag = aes_cipher.encrypt_and_digest(message.encode())

# Step 7: Send the encrypted message
client_socket.send(aes_cipher.nonce)
client_socket.send(tag)
client_socket.send(ciphertext)

print("[+] Message sent securely.")

# Step 8: Receive the reply from the server
reply_nonce = client_socket.recv(16)
reply_tag = client_socket.recv(16)
reply_ciphertext = client_socket.recv(1024)

# Step 9: Decrypt the server's reply
aes_cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=reply_nonce)
reply_plaintext = aes_cipher.decrypt_and_verify(reply_ciphertext, reply_tag)

print("[+] Secure reply received from server:")
print("    " + reply_plaintext.decode())

client_socket.close()
