import tkinter as tk
from tkinter import ttk
from subprocess import call

class WelcomeScreen:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Welcome!")
        self.root.geometry("500x200")
        self.root.resizable(False, False)
        
        self.create_widgets()
        self.root.mainloop()
    
    def create_widgets(self):
        # Welcome message
        welcome_label = ttk.Label(
            self.root,
            text="Welcome to St Thomas More's \n Student University Application!",
            font=("Helvetica", 16)
        )
        welcome_label.pack(pady=20)
        
        # Description
        desc_label = ttk.Label(
            self.root,
            text="Please login or signup to continue",
            font=("Helvetica", 12)
        )
        desc_label.pack(pady=10)
        
        # Start button
        start_btn = ttk.Button(
            self.root,
            text="Get Started",
            command=self.launch_auth
        )
        start_btn.pack(pady=20)
    
    def launch_auth(self):
        self.root.destroy()  # Close the welcome screen
        call(["python", "login.py"]) # leads to the "login.py"

if __name__ == "__main__":
    WelcomeScreen()