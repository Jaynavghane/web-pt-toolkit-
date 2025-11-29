import os
import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_utils import encrypt_file, decrypt_file, CryptoError

APP_TITLE = "CODTECH Advanced Encryption Tool (AES-256 GCM)"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("640x340")
        self.resizable(False, False)

        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()

        self._build_ui()

    def _build_ui(self):
        header = tk.Label(self, text=APP_TITLE, font=("Segoe UI", 14, "bold"))
        header.pack(pady=10)

        frm_in = tk.Frame(self)
        frm_in.pack(fill="x", padx=20, pady=5)
        tk.Label(frm_in, text="Input file:", width=12, anchor="w").pack(side="left")
        tk.Entry(frm_in, textvariable=self.input_path, width=50).pack(side="left", padx=5)
        tk.Button(frm_in, text="Browse", command=self._choose_input).pack(side="left")

        frm_out = tk.Frame(self)
        frm_out.pack(fill="x", padx=20, pady=5)
        tk.Label(frm_out, text="Output file:", width=12, anchor="w").pack(side="left")
        tk.Entry(frm_out, textvariable=self.output_path, width=50).pack(side="left", padx=5)
        tk.Button(frm_out, text="Save As", command=self._choose_output).pack(side="left")

        frm_pwd = tk.Frame(self)
        frm_pwd.pack(fill="x", padx=20, pady=5)
        tk.Label(frm_pwd, text="Password:", width=12, anchor="w").pack(side="left")
        tk.Entry(frm_pwd, textvariable=self.password, show="•", width=50).pack(side="left", padx=5)

        frm_actions = tk.Frame(self)
        frm_actions.pack(pady=15)
        tk.Button(frm_actions, text="Encrypt", width=15, command=self._encrypt).pack(side="left", padx=10)
        tk.Button(frm_actions, text="Decrypt", width=15, command=self._decrypt).pack(side="left", padx=10)

        footer = tk.Label(self, text="AES-256 GCM • PBKDF2 • Authenticated Encryption", font=("Segoe UI", 9))
        footer.pack(side="bottom", pady=10)

    def _choose_input(self):
        path = filedialog.askopenfilename(title="Select input file")
        if path:
            self.input_path.set(path)
            base, ext = os.path.splitext(path)
            self.output_path.set(base + ".enc")

    def _choose_output(self):
        path = filedialog.asksaveasfilename(title="Select output file")
        if path:
            self.output_path.set(path)

    def _validate(self) -> bool:
        if not self.input_path.get():
            messagebox.showerror("Error", "Please select an input file.")
            return False
        if not self.output_path.get():
            messagebox.showerror("Error", "Please choose an output file path.")
            return False
        if not self.password.get():
            messagebox.showerror("Error", "Please enter a password.")
            return False
        return True

    def _encrypt(self):
        if not self._validate():
            return
        try:
            encrypt_file(self.input_path.get(), self.output_path.get(), self.password.get())
            messagebox.showinfo("Success", f"File encrypted:\n{self.output_path.get()}")
        except CryptoError as e:
            messagebox.showerror("Encryption failed", str(e))
        except Exception as e:
            messagebox.showerror("Unexpected error", str(e))

    def _decrypt(self):
        if not self._validate():
            return
        out = self.output_path.get()
        if out.endswith(".enc"):
            out = out[:-4]
        try:
            decrypt_file(self.input_path.get(), out, self.password.get())
            messagebox.showinfo("Success", f"File decrypted:\n{out}")
        except CryptoError as e:
            messagebox.showerror("Decryption failed", str(e))
        except Exception as e:
            messagebox.showerror("Unexpected error", str(e))

if __name__ == "__main__":
    app = App()
    app.mainloop()
