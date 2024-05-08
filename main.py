import tkinter as tk
from tkinter import messagebox
import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional


SECRET_KEY = "llavemagica" 
ALGORITHM = "HS256"

user_db = {}

def register_user(username: str, password: str) -> bool:
    if username in user_db:
        return False
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_db[username] = hashed_password
    return True

def login_user(username: str, password: str) -> Optional[str]:
    if username not in user_db:
        return None
    hashed_password = user_db[username]
    if bcrypt.checkpw(password.encode(), hashed_password):
        token = jwt.encode({
            "username": username,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }, SECRET_KEY, algorithm=ALGORITHM)
        return token
    return None

def verify_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


root = tk.Tk()
root.title("JWT Authentication")


tk.Label(root, text="Nombre de usuario:").pack()
entry_username = tk.Entry(root)
entry_username.pack()

tk.Label(root, text="Contraseña:").pack()
entry_password = tk.Entry(root, show="*")
entry_password.pack()


def gui_register():
    username = entry_username.get()
    password = entry_password.get()
    if register_user(username, password):
        message = "Usuario registrado exitosamente."
        messagebox.showinfo("Registro", message)
        print(message)
    else:
        message = "El usuario ya existe."
        messagebox.showerror("Registro", message)
        print(message)

def gui_login():
    username = entry_username.get()
    password = entry_password.get()
    token = login_user(username, password)
    if token:
        message = f"Inicio de sesión exitoso. Token: {token}"
        messagebox.showinfo("Login", message)
        print(message)
    else:
        message = "Nombre de usuario o contraseña incorrectos."
        messagebox.showerror("Login", message)
        print(message)


tk.Label(root, text="Token:").pack()
entry_token = tk.Entry(root)
entry_token.pack()

def gui_verify():
    token = entry_token.get()
    payload = verify_token(token)
    if payload:
        message = f"Token verificado exitosamente: {payload}"
        messagebox.showinfo("Verificación", message)
        print(message)
    else:
        message = "Token inválido o expirado."
        messagebox.showerror("Verificación", message)
        print(message)

# Buttons for actions
tk.Button(root, text="Registrar", command=gui_register).pack()
tk.Button(root, text="Iniciar Sesión", command=gui_login).pack()
tk.Button(root, text="Verificar Token", command=gui_verify).pack()

root.mainloop()
