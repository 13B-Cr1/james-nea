import tkinter as tk
from tkinter import ttk, messagebox
import json
import sqlite3

class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login/Signup System")
        
        # Configure window size and position
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        # Initialize user data storage
        self.users_file = "users.json"
        self.users = self.load_users()
        
        # Create frames
        self.login_frame = ttk.Frame(root)
        self.signup_frame = ttk.Frame(root)
        
        # Initialize all UI elements
        self.create_login_frame()
        self.create_signup_frame()
        
        # Show login frame by default
        self.show_login_frame()

    def load_users(self):
        try:
            with open(self.users_file, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_users(self):
        with open(self.users_file, 'w') as file:
            json.dump(self.users, file)

    def create_login_frame(self):
        # Login frame widgets
        self.login_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        
        self.login_username = ttk.Entry(self.login_frame)
        self.login_password = ttk.Entry(self.login_frame, show="*")
        
        self.login_username.grid(row=0, column=1, padx=10, pady=10)
        self.login_password.grid(row=1, column=1, padx=10, pady=10)
        
        login_btn = ttk.Button(self.login_frame, text="Login", command=self.handle_login)
        login_btn.grid(row=2, column=1, pady=10)
        
        signup_link = ttk.Label(self.login_frame, text="Don't have an account? Sign Up here", foreground="blue", cursor="hand2")
        signup_link.grid(row=3, column=0, columnspan=2, pady=10)
        signup_link.bind("<Button-1>", lambda e: self.show_signup_frame())

    def create_signup_frame(self):
        # Signup frame widgets
        self.signup_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.signup_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        ttk.Label(self.signup_frame, text="Password:").grid(row=1, column=0, padx=10, pady=10)
        ttk.Label(self.signup_frame, text="Confirm Password:").grid(row=2, column=0, padx=10, pady=10)
        
        self.signup_username = ttk.Entry(self.signup_frame)
        self.signup_password = ttk.Entry(self.signup_frame, show="*")
        self.confirm_password = ttk.Entry(self.signup_frame, show="*")
        
        self.signup_username.grid(row=0, column=1, padx=10, pady=10)
        self.signup_password.grid(row=1, column=1, padx=10, pady=10)
        self.confirm_password.grid(row=2, column=1, padx=10, pady=10)
        
        signup_btn = ttk.Button(self.signup_frame, text="Sign Up", command=self.handle_signup)
        signup_btn.grid(row=3, column=1, pady=10)
        
        login_link = ttk.Label(self.signup_frame, text="Already have an account? Login here", foreground="blue", cursor="hand2")
        login_link.grid(row=4, column=0, columnspan=2, pady=10)
        login_link.bind("<Button-1>", lambda e: self.show_login_frame())

    def show_login_frame(self):
        self.signup_frame.grid_remove()
        self.login_frame.grid()
        self.clear_entries()

    def show_signup_frame(self):
        self.login_frame.grid_remove()
        self.signup_frame.grid()
        self.clear_entries()

    def clear_entries(self):
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        self.signup_username.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)

    def handle_login(self):
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if username in self.users and self.users[username] == password:
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()  # Close the window after successful login
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def handle_signup(self):
        username = self.signup_username.get()
        password = self.signup_password.get()
        confirm_password = self.confirm_password.get()
        
        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
            
        self.users[username] = password
        self.save_users()
        messagebox.showinfo("Success", "Account created successfully!")
        self.show_login_frame()

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()
