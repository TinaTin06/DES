from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def pad(text):
    """
    Pad the input text to make its length a multiple of 8
    """
    while len(text) % 8 != 0:
        text += b' '
    return text

def encrypt_message(message, key):
    """
    Encrypt a message using DES algorithm
    """
    message = pad(message)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(message)

def decrypt_message(ciphertext, key):
    """
    Decrypt a ciphertext using DES algorithm
    """
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def main():
    # Get the user message and key
    user_message = input("Enter your message: ").encode()
    user_password = input("Enter your password: ").encode()

    # Derive a 8-byte key from the password
    salt = get_random_bytes(8)
    key = PBKDF2(user_password, salt, dkLen=8, count=10000)

    # Encrypt the message
    encrypted_message = encrypt_message(user_message, key)
    print("Encrypted message:", encrypted_message.hex())

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, key).strip()
    print("Decrypted message:", decrypted_message.decode())

if __name__ == "__main__":
    main()
