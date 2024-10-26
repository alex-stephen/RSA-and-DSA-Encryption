import tkinter as tk
from tkinter import messagebox
import sys
import dsa
import dhkey
import rsa

# Run this program to use GUI
# must import programs into this file, write a function similar to executeDSA() and call it from the buttons
# replacing command= with command={*functioncall*}
# I wrapped my entire program in runDSA() so everything can be executed from the one function call

def executeDSA():
    try:
        # clear the text area 
        clearTextArea() 
        # then run the code for dsa
        dsa.runDSA() 
    # handles any exception thrown
    except Exception as e:
        messagebox.showerror(f"Error: {str(e)} occurred")

def executeRSA():
    try:
        # clear the text area
        clearTextArea()
        # then run the code for dsa
        rsa.runRSA()
    # handles any exception thrown
    except Exception as e:
        messagebox.showerror(f"Error: {str(e)} occurred")

def executeDH():
    try:
        # clear the text area
        clearTextArea()
        # then run the code for dsa
        dhkey.runDH()
    # handles any exception thrown
    except Exception as e:
        messagebox.showerror(f"Error: {str(e)} occurred")

# function clears text area
def clearTextArea():
    textArea.delete(1.0, tk.END)

# Application window 
root = tk.Tk()
root.title("Alex and Jevon's project")

# Create widget to display terminal outputs,
textArea = tk.Text(root, font=("Arial", 20))
textArea.pack(expand=True, fill=tk.BOTH) # parameters fill container's space

# Class responsible for writing to text area widget 
class writeToTextArea:
    # Constructor initializes instance of TextRedirector
    def __init__(self, widget):
        self.widget = widget
    
    # writes/prints output to widget
    def write(self, message):
        self.widget.insert(tk.END, message)

# capture output stream and display in text area 
sys.stdout = writeToTextArea(textArea)
# capture error stream and display in text area 
sys.stderr = writeToTextArea(textArea)

# button that runs dsa program
dsaButton= tk.Button(root, text="Run DSA", command=executeDSA)
dsaButton.pack(pady=10)

# button that runs rsa program (todo: insert rsa program in command=)
rsaButton = tk.Button(root, text="Run RSA", command=executeRSA)
rsaButton.pack(pady=10)

# button that runs key exchange program (todo: insert keyexchange program in command=)
keyExchangeButton = tk.Button(root, text="Run Key Exchange", command=executeDH)
keyExchangeButton.pack(pady=10)

# event loop
root.mainloop()
