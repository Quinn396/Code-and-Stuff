import os
import json
import struct
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CatManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CAT File Manager (WinRAR Style)")
        self.root.geometry("750x450")
        self.current_archive_path = None
        self.archive_data = {"files": {}}
        self.create_widgets()

    def create_widgets(self):
        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(toolbar, text="New .CAT", command=self.new_archive).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Open .CAT", command=self.open_archive).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Add Files...", command=self.add_files_to_archive).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Extract Selected", command=self.extract_file).pack(side=tk.LEFT, padx=2)
        
        tree_frame = ttk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree = ttk.Treeview(tree_frame, columns=("size", "encrypted"), selectmode="browse")
        self.tree.heading("#0", text="File Name", anchor=tk.W)
        self.tree.heading("size", text="Size (Bytes)", anchor=tk.W)
        self.tree.heading("encrypted", text="Encrypted Status", anchor=tk.W)
        self.tree.column("#0", width=350, anchor=tk.W)
        self.tree.column("size", width=150, anchor=tk.W)
        self.tree.column("encrypted", width=150, anchor=tk.W)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.status_var = tk.StringVar(value="Ready. Create or Open a .cat archive.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def new_archive(self):
        path = filedialog.asksaveasfilename(defaultextension=".cat", filetypes=[("CAT Archive", "*.cat")])
        if path:
            self.current_archive_path = path
            self.archive_data = {"files": {}}
            self.save_archive_to_disk()
            self.refresh_ui()
            self.status_var.set(f"Created new archive: {os.path.basename(path)}")

    def open_archive(self):
        path = filedialog.askopenfilename(filetypes=[("CAT Archive", "*.cat")])
        if path:
            password = simpledialog.askstring("Password", "Enter archive password:", show="*")
            if not password: return
            try:
                with open(path, "rb") as f: file_bytes = f.read()
                salt = file_bytes[:12]
                enc_len = struct.unpack(">I", file_bytes[12:16])[0]
                ciphertext = file_bytes[16:16+enc_len]
                key = self.derive_key(password, salt)
                decrypted_bytes = AESGCM(key).decrypt(salt, ciphertext, None)
                self.archive_data = json.loads(decrypted_bytes.decode("utf-8"))
                self.current_archive_path = path
                self.refresh_ui()
                self.status_var.set(f"Successfully opened: {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open archive. Wrong password or corrupt file.\nDetails: {e}")

    def add_files_to_archive(self):
        if not self.current_archive_path:
            messagebox.showwarning("Warning", "Please create or open a .cat archive first.")
            return
        filenames = filedialog.askopenfilenames(title="Select files to add")
        if not filenames: return
        password = simpledialog.askstring("Password", "Enter encryption password for files:", show="*")
        if not password: return
        for filepath in filenames:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f: content = f.read()
            salt = os.urandom(12)
            key = self.derive_key(password, salt)
            encrypted_content = AESGCM(key).encrypt(salt, content, None)
            self.archive_data["files"][filename] = {
                "size": len(content),
                "salt": b64encode(salt).decode("utf-8"),
                "data": b64encode(encrypted_content).decode("utf-8")
            }
        self.save_archive_to_disk()
        self.refresh_ui()
        self.status_var.set("Files added and encrypted successfully.")

    def extract_file(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Select a file from the list to extract.")
            return
        filename = self.tree.item(selected_item, "text")
        file_info = self.archive_data["files"].get(filename)
        if not file_info: return
        password = simpledialog.askstring("Password", f"Enter password to decrypt '{filename}':", show="*")
        if not password: return
        out_dir = filedialog.askdirectory(title="Select Destination Directory")
        if not out_dir: return
        try:
            salt = b64decode(file_info["salt"])
            ciphertext = b64decode(file_info["data"])
            key = self.derive_key(password, salt)
            decrypted_content = AESGCM(key).decrypt(salt, ciphertext, None)
            out_path = os.path.join(out_dir, filename)
            with open(out_path, "wb") as f: f.write(decrypted_content)
            messagebox.showinfo("Success", f"Extracted to: {out_path}")
            self.status_var.set(f"Extracted {filename}")
        except Exception as e:
            messagebox.showerror("Decryption Failed", f"Incorrect password or damaged file data.\nDetails: {e}")

    def derive_key(self, password: str, salt: bytes) -> bytes:
        import hashlib
        derived = password.encode("utf-8") + salt
        for _ in range(1000): derived = hashlib.sha256(derived).digest()
        return derived

    def save_archive_to_disk(self):
        if not self.current_archive_path: return
        payload = json.dumps(self.archive_data).encode("utf-8")
        salt = os.urandom(12)
        key = self.derive_key("MasterCatContainerKey2026!", salt)
        ciphertext = AESGCM(key).encrypt(salt, payload, None)
        with open(self.current_archive_path, "wb") as f:
            f.write(salt)
            f.write(struct.pack(">I", len(ciphertext)))
            f.write(ciphertext)

    def refresh_ui(self):
        for row in self.tree.get_children(): self.tree.delete(row)
        for filename, info in self.archive_data.get("files", {}).items():
            self.tree.insert("", tk.END, text=filename, values=(info["size"], "AES-256 Encrypted"))

if __name__ == "__main__":
    root = tk.Tk()
    app = CatManagerApp(root)
    root.mainloop()
