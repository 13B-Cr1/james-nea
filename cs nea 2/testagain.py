# Libraries

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import *
import json
from subprocess import call
import hashlib


# OOP
class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login/Signup System")
        
        # Configure window size and position
        self.root.geometry("500x500")
        self.root.resizable(True, True)
        
        # Initialize user data storage
        self.users_file = "users.json"
        self.users = self.load_users()
        
        # Create frames
        self.login_frame = ttk.Frame(root)
        self.signup_frame = ttk.Frame(root)
        self.reset_password_frame = ttk.Frame(root)
        
        # Initialize all UI elements
        self.create_login_frame()
        self.create_signup_frame()
        self.create_reset_password_frame()
        
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
        self.login_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=30, pady=30)
        self.login_username = ttk.Entry(self.login_frame)
        self.login_username.grid(row=0, column=1, padx=30, pady=30)
        
        ttk.Label(self.login_frame, text="Email:").grid(row=1, column=0, padx=30, pady=30)
        self.login_email = ttk.Entry(self.login_frame)
        self.login_email.grid(row=1, column=1, padx=30, pady=30)
        
        ttk.Label(self.login_frame, text="Password:").grid(row=2, column=0, padx=30, pady=30)
        self.login_password = ttk.Entry(self.login_frame, show="*")
        self.login_password.grid(row=2, column=1, padx=30, pady=30)
        
        login_btn = ttk.Button(self.login_frame, text="Login", command=self.handle_login)
        login_btn.grid(row=3, column=1, pady=10)
        
        signup_link = ttk.Label(self.login_frame, text="Don't have an account? Sign Up here", foreground="blue", cursor="hand2")
        signup_link.grid(row=4, column=0, columnspan=2, pady=10)
        signup_link.bind("<Button-1>", lambda e: self.show_signup_frame())

        reset_link = ttk.Label(self.login_frame, text="Forgot Password?", foreground="red", cursor="hand2")
        reset_link.grid(row=5, column=0, columnspan=2, pady=10)
        reset_link.bind("<Button-1>", lambda e: self.show_reset_password_frame())


    def create_signup_frame(self):
        self.signup_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.signup_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        self.signup_username = ttk.Entry(self.signup_frame)
        self.signup_username.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(self.signup_frame, text="Email:").grid(row=1, column=0, padx=10, pady=10)
        self.signup_email = ttk.Entry(self.signup_frame)
        self.signup_email.grid(row=1, column=1, padx=10, pady=10)
        
        ttk.Label(self.signup_frame, text="Password:").grid(row=2, column=0, padx=10, pady=10)
        self.signup_password = ttk.Entry(self.signup_frame, show="*")
        self.signup_password.grid(row=2, column=1, padx=10, pady=10)
        
        ttk.Label(self.signup_frame, text="Confirm Password:").grid(row=3, column=0, padx=10, pady=10)
        self.confirm_password = ttk.Entry(self.signup_frame, show="*")
        self.confirm_password.grid(row=3, column=1, padx=10, pady=10)
        
        signup_btn = ttk.Button(self.signup_frame, text="Sign Up", command=self.handle_signup)
        signup_btn.grid(row=4, column=1, pady=10)
        
        login_link = ttk.Label(self.signup_frame, text="Already have an account? Login here", foreground="blue", cursor="hand2")
        login_link.grid(row=5, column=0, columnspan=2, pady=10)
        login_link.bind("<Button-1>", lambda e: self.show_login_frame())

    def create_reset_password_frame(self):
        self.reset_password_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.reset_password_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        self.reset_username = ttk.Entry(self.reset_password_frame)
        self.reset_username.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(self.reset_password_frame, text="Email:").grid(row=1, column=0, padx=10, pady=10)
        self.reset_email = ttk.Entry(self.reset_password_frame)
        self.reset_email.grid(row=1, column=1, padx=10, pady=10)
        
        ttk.Label(self.reset_password_frame, text="New Password:").grid(row=2, column=0, padx=10, pady=10)
        self.reset_new_password = ttk.Entry(self.reset_password_frame, show="*")
        self.reset_new_password.grid(row=2, column=1, padx=10, pady=10)
        
        ttk.Label(self.reset_password_frame, text="Confirm New Password:").grid(row=3, column=0, padx=10, pady=10)
        self.reset_confirm_password = ttk.Entry(self.reset_password_frame, show="*")
        self.reset_confirm_password.grid(row=3, column=1, padx=10, pady=10)
        
        reset_btn = ttk.Button(self.reset_password_frame, text="Reset Password", command=self.handle_reset_password)
        reset_btn.grid(row=4, column=1, pady=10)
        
        back_link = ttk.Label(self.reset_password_frame, text="Back to Login", foreground="blue", cursor="hand2")
        back_link.grid(row=5, column=0, columnspan=2, pady=10)
        back_link.bind("<Button-1>", lambda e: self.show_login_frame())

    def show_login_frame(self):
        self.signup_frame.grid_remove()
        self.reset_password_frame.grid_remove()
        self.login_frame.grid()
        self.clear_entries()

    def show_signup_frame(self):
        self.login_frame.grid_remove()
        self.reset_password_frame.grid_remove()
        self.signup_frame.grid()
        self.clear_entries()

    def show_reset_password_frame(self):
        self.login_frame.grid_remove()
        self.signup_frame.grid_remove()
        self.reset_password_frame.grid()
        self.clear_entries()

    def clear_entries(self):
        self.login_username.delete(0, tk.END)
        self.login_email.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        self.signup_username.delete(0, tk.END)
        self.signup_email.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)
        self.reset_username.delete(0, tk.END)
        self.reset_email.delete(0, tk.END)
        self.reset_new_password.delete(0, tk.END)
        self.reset_confirm_password.delete(0, tk.END)

    def handle_login(self):
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in username and password.")
            return
            
        if username in self.users and self.users[username]['password'] == password:
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()
            call(["python","Main.py"])
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def handle_signup(self):
        username = self.signup_username.get()
        email = self.signup_email.get()
        password = self.signup_password.get()
        confirm_password = self.confirm_password.get()
        
        if not username or not email or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        elif password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        elif username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
        if "@" not in email or "." not in email:
            messagebox.showerror("Error", "Invalid email address")
            return
            
        self.users[username] = {
            'password': password,
            'email': email
        }
        self.save_users()
        messagebox.showinfo("Success", "Account created successfully! \n Please close this box to be redirected to the login page.")
        self.show_login_frame()

    def handle_reset_password(self):
        username = self.reset_username.get()
        email = self.reset_email.get()
        new_password = self.reset_new_password.get()
        confirm_password = self.reset_confirm_password.get()
        
        if not username or not email or not new_password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        if username not in self.users:
            messagebox.showerror("Error", "Username does not exist")
            return
        if self.users[username]['email'] != email:
            messagebox.showerror("Error", "Email does not match the registered email for this username")
            return
        
        self.users[username]['password'] = new_password
        self.save_users()
        messagebox.showinfo("Success", "Password reset successfully!")
        self.show_login_frame()

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()