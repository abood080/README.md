import socket
from Crypto.PublicKey import RSA  # type: ignore
from Crypto.Cipher import PKCS1_OAEP, AES  # type: ignore
from Crypto.Random import get_random_bytes  # type: ignore

# Server settings
HOST = '127.0.0.1'
PORT = 65432

# Generate RSA key pair
rsa_key = RSA.generate(2048)
private_key = rsa_key
public_key = rsa_key.publickey()

# Create TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("[+] Waiting for client connection...")

# Accept connection from client
conn, addr = server_socket.accept()
print(f"[+] Connected by {addr}")

# Step 1: Send public key to client
conn.send(public_key.export_key())

# Step 2: Receive encrypted AES key
encrypted_symmetric_key = conn.recv(256)

# Step 3: Decrypt AES key using RSA
rsa_cipher = PKCS1_OAEP.new(private_key)
symmetric_key = rsa_cipher.decrypt(encrypted_symmetric_key)

# Step 4: Receive encrypted message from client
nonce = conn.recv(16)
tag = conn.recv(16)
ciphertext = conn.recv(1024)

# Step 5: Decrypt the message
aes_cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)

print("[+] Secure message received from client:")
print("    " + plaintext.decode())

# Step 6: Ask server user to input a message to send back
reply = input("Enter your reply to the client: ")

# Step 7: Encrypt the reply using AES and send it
aes_cipher = AES.new(symmetric_key, AES.MODE_EAX)
reply_ciphertext, reply_tag = aes_cipher.encrypt_and_digest(reply.encode())

# Send nonce, tag, and ciphertext
conn.send(aes_cipher.nonce)
conn.send(reply_tag)
conn.send(reply_ciphertext)

print("[+] Reply sent securely to the client.")

# Close connection
conn.close()
server_socket.close()
