import tkinter as tk
from tkinter import messagebox
import re

# Evaluate password strength
def evaluate_password_strength(password):
    score = 0
    suggestions = []

    if not password:
        return score, "Enter a password to check its strength.", suggestions

    # Length checks
    if len(password) < 8:
        suggestions.append("Use at least 8 characters.")
    else:
        score += 1
    if len(password) >= 12:
        score += 1

    # Character type checks
    if re.search(r'[a-z]', password):
        score += 1
    else:
        suggestions.append("Include lowercase letters.")
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        suggestions.append("Include uppercase letters.")
    if re.search(r'\d', password):
        score += 1
    else:
        suggestions.append("Include digits.")
    if re.search(r'[\W_]', password):
        score += 1
    else:
        suggestions.append("Include special characters.")

    score = min(score, 5)

    if score == 5:
        suggestions.clear()

    levels = {
        0: "Very Weak",
        1: "Very Weak",
        2: "Weak",
        3: "Medium",
        4: "Strong",
        5: "Very Strong"
    }

    return score, levels[score], suggestions

# Update UI
def update_strength(*args):
    password = password_var.get()
    score, label, suggestions = evaluate_password_strength(password)

    # Update label and progress bar
    strength_label.config(text=label)
    strength_bar['value'] = score * 20

    # Update suggestions list
    suggestions_text.set("\n".join(suggestions))

# Copy password to clipboard
def copy_to_clipboard():
    password = password_var.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password to copy.")
    else:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

# Clear the input
def clear_input():
    password_var.set("")
    strength_label.config(text="Enter a password to check its strength.")
    strength_bar['value'] = 0
    suggestions_text.set("")

# GUI setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x300")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

password_var = tk.StringVar()
password_var.trace_add('write', update_strength)

tk.Label(root, text="Enter Password", font=("Arial", 12), bg="#f0f0f0").pack(pady=10)
password_entry = tk.Entry(root, textvariable=password_var, show="*", width=30, font=("Arial", 12))
password_entry.pack(pady=5)

# Strength bar and label
from tkinter import ttk
strength_bar = ttk.Progressbar(root, length=300, maximum=100)
strength_bar.pack(pady=10)

strength_label = tk.Label(root, text="Enter a password to check its strength.", font=("Arial", 12), bg="#f0f0f0")
strength_label.pack()

# Suggestions area
suggestions_text = tk.StringVar()
tk.Label(root, textvariable=suggestions_text, font=("Arial", 10), bg="#f0f0f0", fg="gray").pack(pady=5)

# Buttons
btn_frame = tk.Frame(root, bg="#f0f0f0")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Copy", command=copy_to_clipboard, bg="#eb455f", fg="white", width=10).pack(side="left", padx=10)
tk.Button(btn_frame, text="Clear", command=clear_input, bg="#083d77", fg="white", width=10).pack(side="left", padx=10)

root.mainloop()
