import tkinter as tk
from tkinter import Toplevel, Label, messagebox
import customtkinter as ctk
from encryption import aes_encrypt_file, aes_decrypt_file, generate_rsa_key_pair
from key_management import derive_key, save_rsa_keys
from access_control import create_acl
from integrity import verify_integrity
from secure_deletion import secure_delete

class ResponsiveTooltip:
    """A responsive tooltip class to display enhanced tooltips."""
    def __init__(self, widget, text, delay=400):
        self.widget = widget
        self.text = text
        self.delay = delay  # Delay in milliseconds
        self.tooltip_window = None
        self.after_id = None
        self.last_event = None

        self.widget.bind("<Enter>", self.schedule_show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)
        self.widget.bind("<Motion>", self.store_event)

        # Bind window resize event to adjust tooltip font dynamically
        self.widget.winfo_toplevel().bind("<Configure>", self.adjust_tooltip_font)

    def schedule_show_tooltip(self, event=None):
        """Schedule the tooltip display."""
        self.last_event = event
        self.after_id = self.widget.after(self.delay, self.show_tooltip)

    def show_tooltip(self, event=None):
        """Display the tooltip."""
        if self.tooltip_window or not self.text or not self.last_event:
            return

        x, y = self.last_event.x_root + 20, self.last_event.y_root + 20

        self.tooltip_window = Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")

        # Adjust font size dynamically
        font_size = self.get_font_size()

        self.label = Label(
            self.tooltip_window,
            text=self.text,
            background="white",
            relief="solid",
            borderwidth=1,
            font=("Arial", font_size),
            padx=8,
            pady=6,
            wraplength=self.widget.winfo_toplevel().winfo_width() // 2
        )
        self.label.pack()

    def store_event(self, event):
        """Store the latest motion event to reposition the tooltip."""
        self.last_event = event

    def hide_tooltip(self, event=None):
        """Hide the tooltip."""
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None

        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

    def adjust_tooltip_font(self, event=None):
        """Adjust the font size dynamically based on window size."""
        if self.tooltip_window and self.label:
            font_size = self.get_font_size()
            self.label.config(font=("Arial", font_size))

    def get_font_size(self):
        """Calculate font size dynamically based on window size."""
        window_width = self.widget.winfo_toplevel().winfo_width()
        return max(8, window_width // 60)  # Slightly smaller font size


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Encryption System")
        self.geometry("600x400")

        # AES Key
        self.aes_key = None
        self.salt = None

        # RSA Keys
        self.public_key = None
        self.private_key = None

        # Main Frame
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(pady=20, padx=40, fill="both", expand=True)

        # Encrypt Button
        self.encrypt_button = ctk.CTkButton(self.main_frame, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)
        ResponsiveTooltip(self.encrypt_button, "Encrypt a file using AES-256. Example: Encrypt 'document.txt' with a password.")

        # Decrypt Button
        self.decrypt_button = ctk.CTkButton(self.main_frame, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)
        ResponsiveTooltip(self.decrypt_button, "Decrypt a file using AES-256. Example: Decrypt 'document.txt.enc' with the same password.")

        # Generate RSA Keys Button
        self.keygen_button = ctk.CTkButton(self.main_frame, text="Generate RSA Keys", command=self.generate_rsa_keys)
        self.keygen_button.pack(pady=10)
        ResponsiveTooltip(self.keygen_button, "Generate a pair of RSA keys (public and private). Example: Save as 'my_keys'.")

        # Create ACL Button
        self.acl_button = ctk.CTkButton(self.main_frame, text="Create ACL", command=self.create_acl)
        self.acl_button.pack(pady=10)
        ResponsiveTooltip(self.acl_button, "Create an Access Control List (ACL) for a file. Example: Add users 'Alice' and 'Bob'.")

        # Verify Integrity Button
        self.verify_button = ctk.CTkButton(self.main_frame, text="Verify Integrity", command=self.verify_integrity)
        self.verify_button.pack(pady=10)
        ResponsiveTooltip(self.verify_button, "Verify the integrity of a file using SHA-256. Example: Check if 'document.txt' is unchanged.")

        # Secure Delete Button
        self.delete_button = ctk.CTkButton(self.main_frame, text="Secure Delete", command=self.secure_delete)
        self.delete_button.pack(pady=10)
        ResponsiveTooltip(self.delete_button, "Securely delete a file by overwriting it. Example: Permanently delete 'document.txt'.")

    def encrypt_file(self):
        file_path = ctk.filedialog.askopenfilename()
        if file_path:
            password = ctk.CTkInputDialog(text="Enter Password:", title="Password").get_input()
            if password:
                key, self.salt = derive_key(password.encode())
                aes_encrypt_file(file_path, key)
                messagebox.showinfo("Encryption", "File encrypted successfully!")

    def decrypt_file(self):
        file_path = ctk.filedialog.askopenfilename()
        if file_path:
            password = ctk.CTkInputDialog(text="Enter Password:", title="Password").get_input()
            if password:
                key, _ = derive_key(password.encode(), self.salt)
                aes_decrypt_file(file_path, key)
                messagebox.showinfo("Decryption", "File decrypted successfully!")

    def generate_rsa_keys(self):
        filename = ctk.CTkInputDialog(text="Enter Filename for Keys:", title="Filename").get_input()
        if filename:
            public_key, private_key = generate_rsa_key_pair()
            save_rsa_keys(public_key, private_key, filename)
            self.public_key = public_key
            self.private_key = private_key
            messagebox.showinfo("Key Generation", "RSA keys generated and saved successfully!")

    def create_acl(self):
        file_path = ctk.filedialog.askopenfilename()
        if file_path:
            users = ctk.CTkInputDialog(text="Enter Usernames (space separated):", title="Users").get_input()
            if users:
                user_list = users.split()
                create_acl(file_path, user_list)
                messagebox.showinfo("ACL Creation", f"ACL created for {file_path} with users: {', '.join(user_list)}.")

    def verify_integrity(self):
        file_path = ctk.filedialog.askopenfilename()
        if file_path:
            expected_hash = ctk.CTkInputDialog(text="Enter Expected SHA-256 Hash:", title="Hash").get_input()
            if expected_hash:
                result = verify_integrity(file_path, expected_hash)
                messagebox.showinfo("Integrity Check", "Integrity verified." if result else "Integrity compromised.")

    def secure_delete(self):
        file_path = ctk.filedialog.askopenfilename()
        if file_path:
            secure_delete(file_path)
            messagebox.showinfo("Secure Delete", "File securely deleted.")

if __name__ == "__main__":
    app = App()
    app.mainloop()
