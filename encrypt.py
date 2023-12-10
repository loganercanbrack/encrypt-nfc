from cryptography.fernet import Fernet
import os
import base64
import serial
import shutil

def read_nfc_and_get_keys(serial_port='/dev/cu.usbserial-AB0OL8JJ'):
    keys = []
    try:
        ser_nfc = serial.Serial(serial_port, 9600)
        while len(keys) < 10:
            line = ser_nfc.readline().decode('utf-8').strip()
            if line.startswith("Key "):
                key_value = line.split(": ")[1]
                keys.append(key_value)
        ser_nfc.close()
        return keys
    except Exception as e:
        return []

def multi_encrypt_file(file_name, keys, encryption_pin):
    pin_indices = [int(i) for i in encryption_pin]
    selected_keys = [keys[i] for i in pin_indices]
    with open(file_name, 'rb') as file:
        file_data = file.read()
    for key in selected_keys:
        key_bytes = bytes.fromhex(key)
        if len(key_bytes) == 16:
            key_bytes = key_bytes * 2
        f = Fernet(base64.urlsafe_b64encode(key_bytes))
        file_data = f.encrypt(file_data)
    with open(file_name, 'wb') as file:
        file.write(file_data)

def multi_decrypt_file(file_name, keys, decryption_pin):
    pin_indices = [int(i) for i in decryption_pin]
    selected_keys = [keys[i] for i in reversed(pin_indices)]
    with open(file_name, 'rb') as file:
        file_data = file.read()
    for key in selected_keys:
        key_bytes = bytes.fromhex(key)
        if len(key_bytes) == 16:
            key_bytes = key_bytes * 2
        f = Fernet(base64.urlsafe_b64encode(key_bytes))
        file_data = f.decrypt(file_data)
    with open(file_name, 'wb') as file:
        file.write(file_data)

def main():
    keys_from_nfc = read_nfc_and_get_keys()
    if keys_from_nfc:
        action = input("Would you like to Encrypt or Decrypt? (e/d): ").lower()
        
        if action == 'e':
            encryption_pin = input("Encryption Pin (sequence of key indices): ")
            encrypt_file_or_dir = input("File or Directory to Encrypt: ")

            if os.path.isdir(encrypt_file_or_dir):
                zip_name = f"{encrypt_file_or_dir}.zip"
                shutil.make_archive(encrypt_file_or_dir, 'zip', encrypt_file_or_dir)
                multi_encrypt_file(zip_name, keys_from_nfc, encryption_pin)
                print(f"Directory {encrypt_file_or_dir} compressed and encrypted successfully.")
            elif os.path.exists(encrypt_file_or_dir):
                multi_encrypt_file(encrypt_file_or_dir, keys_from_nfc, encryption_pin)
                print(f"File {encrypt_file_or_dir} encrypted successfully.")
            else:
                print("File or Directory not found.")
                
        elif action == 'd':
            decryption_pin = input("Decryption Pin (sequence of key indices): ")
            decrypt_file = input("File to Decrypt: ")
            if os.path.exists(decrypt_file):
                multi_decrypt_file(decrypt_file, keys_from_nfc, decryption_pin)
                print(f"File {decrypt_file} decrypted successfully.")
            else:
                print("File not found.")
                
        else:
            print("Invalid option. Please enter 'e' for encrypt or 'd' for decrypt.")
            
    else:
        print("Keys not found on NFC card.")

if __name__ == "__main__":
    main()
