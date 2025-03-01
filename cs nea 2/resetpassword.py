# Libraries

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import *
import json
from subprocess import call # This is needed after logging in 
import hashlib


# OOP
class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login/Signup System")
        # self.root.configure(bg = 'black') - may not add this, this doesn't seem to be working.
        
        # Configure window size and position
        self.root.geometry("500x500") # might do full screen
        self.root.resizable(True, True) # probably best to change this to False, False because it's better to keep it aligned without anchor?
        
        # Initialize user data storage
        self.users_file = "users.json"
        self.users = self.load_users()
        
        # Create frames
        self.login_frame = ttk.Frame(root)
        self.signup_frame = ttk.Frame(root)
        self.reset_password_frame = ttk.Frame(root)  # New frame for resetting password
        
        # Initialize all UI elements
        self.create_login_frame() # Initialise login frame
        self.create_signup_frame() # Initialise signup frame
        self.create_reset_password_frame()  # Initialize reset password frame
        
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
        
        # Username and Password text and pads
        ttk.Label(self.login_frame, text="Username:").grid(row = 0, column = 0, padx = 30, pady = 30)
        ttk.Label(self.login_frame, text="Password:").grid(row=1, column = 0, padx = 30, pady = 30)
        
        self.login_username = ttk.Entry(self.login_frame)
        self.login_password = ttk.Entry(self.login_frame, show="*")



        self.login_username.grid(row=0, column=1, padx=30, pady=30)
        self.login_password.grid(row=1, column=1, padx=30, pady=30)
        
        login_btn = ttk.Button(self.login_frame, text="Login", command=self.handle_login)
        login_btn.grid(row=2, column=1, pady=10)
        
        signup_link = ttk.Label(self.login_frame, text="Don't have an account? Sign Up here", foreground="blue", cursor="hand2")
        signup_link.grid(row=3, column=0, columnspan=2, pady=10)
        signup_link.bind("<Button-1>", lambda e: self.show_signup_frame())

        # Add "Forgot Password?" link
        reset_link = ttk.Label(self.login_frame, text="Forgot Password?", foreground="red", cursor="hand2")
        reset_link.grid(row=4, column=0, columnspan=2, pady=10)
        reset_link.bind("<Button-1>", lambda e: self.show_reset_password_frame())


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

    def create_reset_password_frame(self):
        # Reset Password frame widgets
        self.reset_password_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.reset_password_frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        ttk.Label(self.reset_password_frame, text="New Password:").grid(row=1, column=0, padx=10, pady=10)
        ttk.Label(self.reset_password_frame, text="Confirm New Password:").grid(row=2, column=0, padx=10, pady=10)
        
        self.reset_username = ttk.Entry(self.reset_password_frame)
        self.reset_new_password = ttk.Entry(self.reset_password_frame, show="*")
        self.reset_confirm_password = ttk.Entry(self.reset_password_frame, show="*")
        
        self.reset_username.grid(row=0, column=1, padx=10, pady=10)
        self.reset_new_password.grid(row=1, column=1, padx=10, pady=10)
        self.reset_confirm_password.grid(row=2, column=1, padx=10, pady=10)
        
        reset_btn = ttk.Button(self.reset_password_frame, text="Reset Password", command=self.handle_reset_password)
        reset_btn.grid(row=3, column=1, pady=10)
        
        back_link = ttk.Label(self.reset_password_frame, text="Back to Login", foreground="blue", cursor="hand2")
        back_link.grid(row=4, column=0, columnspan=2, pady=10)
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
        self.login_password.delete(0, tk.END)
        self.signup_username.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)
        self.reset_username.delete(0, tk.END)
        self.reset_new_password.delete(0, tk.END)
        self.reset_confirm_password.delete(0, tk.END)

    # LOGIN 
    def handle_login(self):
        username = self.login_username.get()
        password = self.login_password.get()
        
        # if login username and password are left blank
        if not username and not password:
            messagebox.showerror("Error", "Please fill in the username and the password.")
            return
        # if password is left blank
        elif not password:
            messagebox.showerror("Error", "Please fill in the password.")
            return
        # if the username is left blank
        elif not username:
            messagebox.showerror("Error", "Error, please fill in your username.")
            return
            
        if username in self.users and self.users[username] == password:
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()  # Close the window after successful login
            # add call here
            call(["python","Main.py"])
        else: #if username and password is not the same as the file in "users.json"
            messagebox.showerror("Error", "Invalid username or password")

    # SIGNING UP
    def handle_signup(self):
        username = self.signup_username.get()
        password = self.signup_password.get()
        confirm_password = self.confirm_password.get()
        
        # if the sign up does not include the username, password and the confirmed password:
        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        # if ONLY the username is not included
        elif not username:
            messagebox.showerror("Error", "Please fill in your username.")
            return
        # if ONLY the password is not included
        elif not password:
            messagebox.showerror("Error", "Please fill in the password.")
            return
        # if ONLY the confirmed password is not included
        elif not confirm_password:
            messagebox.showerror("Error", "Please fill in the second confirm password.")
            return


        # if both password and confirm password are not the same
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
            
        # if the username already exists in users.json
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
            
        self.users[username] = password
        self.save_users()
        messagebox.showinfo("Success", "Account created successfully! \n Please close this box to be redirected to the login page.")
        self.show_login_frame()

    # RESET PASSWORD
    def handle_reset_password(self):
        username = self.reset_username.get()
        new_password = self.reset_new_password.get()
        confirm_password = self.reset_confirm_password.get()
        
        # if the username or new_password or confirm_password is not filled in:
        if not username or not new_password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        # if the new password does not match the confirmed password:
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        # if the username is not in "users.json":
        if username not in self.users:
            messagebox.showerror("Error", "Username does not exist")
            return
        
        # Update the password
        self.users[username] = new_password
        self.save_users()
        messagebox.showinfo("Success", "Password reset successfully!")
        self.show_login_frame() # Brings back to the Login section

if __name__ == "__main__": # stops users from accidentally triggering the script
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()