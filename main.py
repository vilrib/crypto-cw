import json
from tkinter import *
from tkinter import messagebox
import random
import string
import pyperclip
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# RC4 implementation for stream cipher
class RC4:
    def __init__(self, key):
        self.key = key.encode()
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % len(self.key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = self.j = 0

    def crypt(self, data):
        data = data.encode()
        output = bytearray()
        for byte in data:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            k = self.S[(self.S[self.i] + self.S[self.j]) % 256]
            output.append(byte ^ k)
        return bytes(output)

# Master key for encryption (should be securely stored in a real application)
MASTER_KEY = "MySecretKey12345"  # 16 bytes for AES
rc4_cipher = RC4(MASTER_KEY)

def encrypt_block(plain_text):
    """Encrypt using AES (block cipher)"""
    key = MASTER_KEY.encode()[:16]  # Ensure 16 bytes for AES-128
    iv = get_random_bytes(16)  # Initialization vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = pad(plain_text.encode(), AES.block_size)
    cipher_text = cipher.encrypt(padded_text)
    return base64.b64encode(iv + cipher_text).decode('utf-8')

def decrypt_block(cipher_text):
    """Decrypt using AES (block cipher)"""
    key = MASTER_KEY.encode()[:16]
    raw = base64.b64decode(cipher_text)
    iv = raw[:16]
    cipher_text = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = cipher.decrypt(cipher_text)
    return unpad(padded_text, AES.block_size).decode('utf-8')

def encrypt_stream(plain_text):
    """Encrypt using RC4 (stream cipher)"""
    encrypted = rc4_cipher.crypt(plain_text)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_stream(cipher_text):
    """Decrypt using RC4 (stream cipher)"""
    decoded = base64.b64decode(cipher_text)
    return rc4_cipher.crypt(decoded.decode('latin-1')).decode()

# ---------------------------- PASSWORD GENERATOR ------------------------------- #

def generate_password():
    letters = string.ascii_letters
    numbers = string.digits
    symbols = string.punctuation

    password_letters = [random.choice(letters) for _ in range(random.randint(8, 10))]
    password_symbols = [random.choice(symbols) for _ in range(random.randint(2, 4))]
    password_numbers = [random.choice(numbers) for _ in range(random.randint(2, 4))]

    password_list = password_letters + password_symbols + password_numbers
    random.shuffle(password_list)

    password = "".join(password_list)
    password_entry.delete(0, "end")
    password_entry.insert(0, password)
    pyperclip.copy(password)

# ---------------------------- SAVE PASSWORD ------------------------------- #

def save():
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    if len(website) == 0 or len(email) == 0 or len(password) == 0:
        messagebox.showerror(title="Unacceptable Details", message="Please don't leave any fields empty!")
    else:
        try:
            with open("data.json", "r") as data_file:
                data = json.load(data_file)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        encrypted_block = encrypt_block(password)
        encrypted_stream = encrypt_stream(password)

        data.update({
            website: {
                "email": email,
                "password_block": encrypted_block,
                "password_stream": encrypted_stream
            }
        })
        
        with open("data.json", "w") as data_file:
            json.dump(data, data_file, indent=4)
            website_entry.delete(0, END)
            password_entry.delete(0, END)

def find_password():
    is_found = 0
    try:
        with open("data.json") as data_file:
            data = json.load(data_file)
    except FileNotFoundError:
        messagebox.showinfo(title="No File Found", message="No Data File Found")
    except json.JSONDecodeError:
        messagebox.showinfo(title="No Data Found", message="data.json does not contain data")
    else:
        for key, value in data.items():
            if key == website_entry.get():
                decrypted_block = decrypt_block(value['password_block'])
                decrypted_stream = decrypt_stream(value['password_stream'])
                
                messagebox.showinfo(title=website_entry.get(),
                                  message=f"Username: {key}\n"
                                        f"Password (AES): {decrypted_block}\n"
                                        f"Password (RC4): {decrypted_stream}")
                is_found = 1
                website_entry.delete(0, END)
                password_entry.delete(0, END)
        if is_found == 0:
            messagebox.showinfo(title="Error", message=f"No Details For {website_entry.get()} Found")
            website_entry.delete(0, END)
            password_entry.delete(0, END)

# ---------------------------- UI SETUP ------------------------------- #

window = Tk()
window.title("Password Manager")
window.config(padx=50, pady=50)

website_label = Label(text="Website: ")
website_label.grid(column=0, row=0)  # Adjusted row from 1 to 0 since canvas is removed

website_entry = Entry(width=35)
website_entry.grid(column=1, row=0)
website_entry.focus()

website_search_btn = Button(text="Search", command=find_password)
website_search_btn.grid(column=2, row=0, sticky="EW")

email_label = Label(text="Email/Username: ")
email_label.grid(column=0, row=1)  # Adjusted row from 2 to 1

email_entry = Entry(width=35)
email_entry.grid(column=1, row=1, columnspan=2, sticky="EW")
email_entry.insert(0, "yourmail@gmail.com")

password_label = Label(text="Password: ")
password_label.grid(column=0, row=2)  # Adjusted row from 3 to 2

password_entry = Entry(width=21, show="*")
password_entry.grid(column=1, row=2, sticky="EW")

generate_password_btn = Button(text="Generate Password", command=generate_password)
generate_password_btn.grid(column=2, row=2, sticky="EW")

add_btn = Button(text="Add", width=36, command=save)
add_btn.grid(column=1, row=3, columnspan=2, sticky="EW")  # Adjusted row from 4 to 3

window.mainloop()
