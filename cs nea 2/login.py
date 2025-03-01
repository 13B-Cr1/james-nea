import tkinter as tk
from tkinter import ttk, messagebox
import json
from subprocess import call

# OOP
class AuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login/Signup System")
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
        
        ttk.Label(self.login_frame, text="Username or Email:").grid(row=0, column=0, padx=30, pady=10)
        self.login_identifier = ttk.Entry(self.login_frame)
        self.login_identifier.grid(row=0, column=1, padx=30, pady=10)
        
        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=30, pady=10)
        self.login_password = ttk.Entry(self.login_frame, show="*")
        self.login_password.grid(row=1, column=1, padx=30, pady=10)
        
        # Show password checkbox moved to row 2
        self.show_login_password_var = tk.BooleanVar()
        show_login_password_checkbox = ttk.Checkbutton(
            self.login_frame,
            text="Show Password",
            variable=self.show_login_password_var,
            command=self.toggle_login_password
        )
        show_login_password_checkbox.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)
        
        # Login button moved to row 3
        login_btn = ttk.Button(self.login_frame, text="Login", command=self.handle_login)
        login_btn.grid(row=3, column=1, pady=10)
        
        # Adjusted row numbers for links
        signup_link = ttk.Label(self.login_frame, text="Don't have an account? Sign Up here", 
                               foreground="blue", cursor="hand2")
        signup_link.grid(row=4, column=0, columnspan=2, pady=10)
        signup_link.bind("<Button-1>", lambda e: self.show_signup_frame())

        reset_link = ttk.Label(self.login_frame, text="Forgot Password?", 
                              foreground="red", cursor="hand2")
        reset_link.grid(row=5, column=0, columnspan=2, pady=10)
        reset_link.bind("<Button-1>", lambda e: self.show_reset_password_frame())

    def create_signup_frame(self):
        self.signup_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.signup_frame, text="Username:").grid(row=0, column=0, padx=10, pady=5)
        self.signup_username = ttk.Entry(self.signup_frame)
        self.signup_username.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(self.signup_frame, text="Email:").grid(row=1, column=0, padx=10, pady=5)
        self.signup_email = ttk.Entry(self.signup_frame)
        self.signup_email.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(self.signup_frame, text="Password:").grid(row=2, column=0, padx=10, pady=5)
        self.signup_password = ttk.Entry(self.signup_frame, show="*")
        self.signup_password.grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Label(self.signup_frame, text="Confirm Password:").grid(row=3, column=0, padx=10, pady=5)
        self.confirm_password = ttk.Entry(self.signup_frame, show="*")
        self.confirm_password.grid(row=3, column=1, padx=10, pady=5)
        
        # Add show password checkbox for the signup section (toggles both fields)
        self.show_signup_password_var = tk.BooleanVar()
        show_signup_password_checkbox = ttk.Checkbutton(
            self.signup_frame,
            text="Show Passwords",
            variable=self.show_signup_password_var,
            command=self.toggle_signup_password
        )
        show_signup_password_checkbox.grid(row=4, column=1, padx=10, pady=5)
        
        signup_btn = ttk.Button(self.signup_frame, text="Sign Up", command=self.handle_signup)
        signup_btn.grid(row=5, column=1, pady=10)
        
        login_link = ttk.Label(self.signup_frame, text="Already have an account? Login here", 
                             foreground="blue", cursor="hand2")
        login_link.grid(row=6, column=0, columnspan=2, pady=10)
        login_link.bind("<Button-1>", lambda e: self.show_login_frame())

    def create_reset_password_frame(self):
        self.reset_password_frame.grid(row=0, column=0, sticky="nsew")
        
        ttk.Label(self.reset_password_frame, text="Username or Email:").grid(row=0, column=0, padx=10, pady=5)
        self.reset_identifier = ttk.Entry(self.reset_password_frame)
        self.reset_identifier.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(self.reset_password_frame, text="New Password:").grid(row=1, column=0, padx=10, pady=5)
        self.reset_new_password = ttk.Entry(self.reset_password_frame, show="*")
        self.reset_new_password.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(self.reset_password_frame, text="Confirm New Password:").grid(row=2, column=0, padx=10, pady=5)
        self.reset_confirm_password = ttk.Entry(self.reset_password_frame, show="*")
        self.reset_confirm_password.grid(row=2, column=1, padx=10, pady=5)
        
        # Add show password checkbox for the reset password section (toggles both fields)
        self.show_reset_password_var = tk.BooleanVar()
        show_reset_password_checkbox = ttk.Checkbutton(
            self.reset_password_frame,
            text="Show Passwords",
            variable=self.show_reset_password_var,
            command=self.toggle_reset_password
        )
        show_reset_password_checkbox.grid(row=3, column=1, padx=10, pady=5)
        
        reset_btn = ttk.Button(self.reset_password_frame, text="Reset Password", command=self.handle_reset_password)
        reset_btn.grid(row=4, column=1, pady=10)
        
        back_link = ttk.Label(self.reset_password_frame, text="Back to Login", 
                            foreground="blue", cursor="hand2")
        back_link.grid(row=5, column=0, columnspan=2, pady=10)
        back_link.bind("<Button-1>", lambda e: self.show_login_frame())

    def toggle_login_password(self):
        # Toggle the visibility of the login password field
        if self.show_login_password_var.get():
            self.login_password.config(show="")
        else:
            self.login_password.config(show="*")

    def toggle_signup_password(self):
        # Toggle the visibility of both signup password fields
        if self.show_signup_password_var.get():
            self.signup_password.config(show="")
            self.confirm_password.config(show="")
        else:
            self.signup_password.config(show="*")
            self.confirm_password.config(show="*")

    def toggle_reset_password(self):
        # Toggle the visibility of both reset password fields
        if self.show_reset_password_var.get():
            self.reset_new_password.config(show="")
            self.reset_confirm_password.config(show="")
        else:
            self.reset_new_password.config(show="*")
            self.reset_confirm_password.config(show="*")

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

# add these in 
#     def show_login_frame(self):
#         self.signup_frame.grid_remove()
#         self.reset_password_frame.grid_remove()
#         self.login_frame.grid()
#         self.clear_entries()
#         self.root.title("Login Section")  # Added title change

#     def show_signup_frame(self):
#         self.login_frame.grid_remove()
#         self.reset_password_frame.grid_remove()
#         self.signup_frame.grid()
#         self.clear_entries()
#         self.root.title("Sign Up Section")  # Added title change

#     def show_reset_password_frame(self):
#         self.login_frame.grid_remove()
#         self.signup_frame.grid_remove()
#         self.reset_password_frame.grid()
#         self.clear_entries()
#         self.root.title("Reset Password Section")  # Added title change

    def clear_entries(self):
        self.login_identifier.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        self.signup_username.delete(0, tk.END)
        self.signup_email.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
        self.confirm_password.delete(0, tk.END)
        self.reset_identifier.delete(0, tk.END)
        self.reset_new_password.delete(0, tk.END)
        self.reset_confirm_password.delete(0, tk.END)

    def handle_login(self):
        identifier = self.login_identifier.get()
        password = self.login_password.get()
        
        if not identifier or not password:
            messagebox.showerror("Error", "Please fill in both fields")
            return
        
        # Check if identifier is username or email
        user = None
        if identifier in self.users:  # Username match
            user = self.users[identifier]
        else:  # Email match
            user = next((u for u in self.users.values() if u['email'] == identifier), None)
        
        if user and user['password'] == password:
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()
            call(["python", "Main.py"])
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def handle_signup(self):
        username = self.signup_username.get()
        email = self.signup_email.get()
        password = self.signup_password.get()
        confirm_password = self.confirm_password.get()
        
        if not all([username, email, password, confirm_password]):
            messagebox.showerror("Error", "All fields are required")
            return
            
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords don't match")
            return
            
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
            
        if any(user['email'] == email for user in self.users.values()):
            messagebox.showerror("Error", "Email already registered")
            return
            
        if "@" not in email or "." not in email:
            messagebox.showerror("Error", "Invalid email format")
            return

        self.users[username] = {
            'password': password,
            'email': email
        }
        self.save_users()
        messagebox.showinfo("Success", "Account created successfully!")
        self.show_login_frame()

    def handle_reset_password(self):
        identifier = self.reset_identifier.get()
        new_password = self.reset_new_password.get()
        confirm_password = self.reset_confirm_password.get()
        
        if not all([identifier, new_password, confirm_password]):
            messagebox.showerror("Error", "All fields are required")
            return
            
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords don't match")
            return
            
        # Find account by username or email
        account = None
        if identifier in self.users:  # Username match
            account = identifier
        else:  # Email match
            account = next((uname for uname, data in self.users.items() 
                          if data['email'] == identifier), None)
            
        if not account:
            messagebox.showerror("Error", "No account found with these details")
            return
            
        self.users[account]['password'] = new_password
        self.save_users()
        messagebox.showinfo("Success", "Password updated successfully!")
        self.show_login_frame()

if __name__ == "__main__":
    root = tk.Tk()
    app = AuthApp(root)
    root.mainloop()
