import os
from cryptography.fernet import Fernet
import tkinter as tk 
from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
import base64


# Define the GUI window
root = tk.Tk()
root.title('Henry CryptLock')

# Define the GUI widgets
key_label = tk.Label(root, text='Encryption Key:')
key_label.grid(row=0, column=0)

key_entry = tk.Entry(root, show='*')
key_entry.grid(row=0, column=1)

def browse_folder():
    folder_path = filedialog.askdirectory()
    folder_entry.delete(0, tk.END)
    folder_entry.insert(0, folder_path)

folder_button = tk.Button(root, text='Browse Folder', command=browse_folder)
folder_button.grid(row=1, column=0)

folder_entry = tk.Entry(root)
folder_entry.grid(row=1, column=1)

encrypt_button = tk.Button(root, text='Encrypt', command=lambda: encrypt_folder())
encrypt_button.grid(row=2, column=0)

decrypt_button = tk.Button(root, text='Decrypt', command=lambda: decrypt_folder())
decrypt_button.grid(row=2, column=1)

def generate_fernet_key(password):
    password_hash = hashlib.sha256(password.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(password_hash)
    return fernet_key

def encrypt_folder():
    # Get the encryption key and folder path from the GUI
    password = key_entry.get()
    fernet_key = generate_fernet_key(password)
    folder_path = folder_entry.get()

    # Create an instance of the AES encryption algorithm using the key
    cipher = Fernet(fernet_key)

    # Determine the total number of files to encrypt
    num_files = sum(len(filenames) for _, _, filenames in os.walk(folder_path))

    # Create a progress bar
    progress_bar = ttk.Progressbar(root, maximum=num_files, mode='determinate')
    progress_bar.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Encrypt the contents of the folder
    i = 0
    for foldername, subfolders, filenames in os.walk(folder_path):
        for filename in filenames:
            # Update the progress bar
            i += 1
            progress_bar['value'] = i
            root.update_idletasks()

            # Read the contents of the file
            with open(os.path.join(foldername, filename), 'rb') as f:
                file_contents = f.read()

            # Encrypt the file contents
            encrypted_contents = cipher.encrypt(file_contents)

            # Write the encrypted contents back to the file
            with open(os.path.join(foldername, filename), 'wb') as f:
                f.write(encrypted_contents)
    
    # Destroy the progress bar
    progress_bar.destroy()

    # Show a message box indicating that the encryption is complete
    messagebox.showinfo('Encryption Complete', 'The folder has been encrypted.')

def decrypt_folder():
    # Get the encryption key and folder path from the GUI
    password = key_entry.get()
    fernet_key = generate_fernet_key(password)
    folder_path = folder_entry.get()

    # Create an instance of the AES encryption algorithm using the key
    cipher = Fernet(fernet_key)

    # Determine the total number of files to decrypt
    num_files = sum(len(filenames) for _, _, filenames in os.walk(folder_path))

    # Create a progress bar
    progress_bar = ttk.Progressbar(root, maximum=num_files, mode='determinate')
    progress_bar.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Decrypt the contents of the folder
    i = 0
    for foldername, subfolders, filenames in os.walk(folder_path):
        for filename in filenames:
            # Update the progress bar
            i += 1
            progress_bar['value'] = i
            root.update_idletasks()

            # Read the contents of the file
            with open(os.path.join(foldername, filename), 'rb') as f:
                encrypted_contents = f.read()

            # Decrypt the file contents
            try:
                decrypted_contents = cipher.decrypt(encrypted_contents)
            except Exception as e:
                messagebox.showerror('Decryption Failed', f'An error occurred during decryption: {e}')
                progress_bar.destroy()
                return

            # Write the decrypted contents back to the file
            with open(os.path.join(foldername, filename), 'wb') as f:
                f.write(decrypted_contents)

    # Destroy the progress bar
    progress_bar.destroy()

    # Show a message box indicating that the decryption is complete
    messagebox.showinfo('Decryption Complete', 'The folder has been decrypted.')

# Start the GUI event loop
root.mainloop()

