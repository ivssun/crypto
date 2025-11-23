#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interfaz Gráfica para Demostración de Primitivas Criptográficas
Con Alice, Bob y Eve visualizados
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Demostración de Primitivas Criptográficas")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Variables
        self.alice_key_private = None
        self.alice_key_public = None
        self.bob_key_private = None
        self.bob_key_public = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Configura la interfaz gráfica"""
        
        # Frame superior con los personajes
        self.create_characters_frame()
        
        # Frame central con pestañas
        self.create_tabs_frame()
        
        # Frame inferior con log
        self.create_log_frame()
    
    def create_characters_frame(self):
        """Crea el frame con Alice, Bob y Eve"""
        char_frame = tk.Frame(self.root, bg='#34495e', height=200)
        char_frame.pack(fill=tk.X, padx=10, pady=10)
        char_frame.pack_propagate(False)
        
        # Alice (izquierda)
        alice_frame = tk.Frame(char_frame, bg='#e74c3c', relief=tk.RAISED, bd=3)
        alice_frame.place(relx=0.05, rely=0.5, anchor=tk.W, width=180, height=160)
        
        tk.Label(alice_frame, text="👩", font=("Arial", 50), bg='#e74c3c').pack(pady=5)
        tk.Label(alice_frame, text="ALICE", font=("Arial", 16, "bold"), 
                bg='#e74c3c', fg='white').pack()
        tk.Label(alice_frame, text="Emisor", font=("Arial", 10), 
                bg='#e74c3c', fg='white').pack()
        
        # Eve (centro - arriba)
        eve_frame = tk.Frame(char_frame, bg='#8e44ad', relief=tk.RAISED, bd=3)
        eve_frame.place(relx=0.5, rely=0.15, anchor=tk.N, width=180, height=160)
        
        tk.Label(eve_frame, text="🦹", font=("Arial", 50), bg='#8e44ad').pack(pady=5)
        tk.Label(eve_frame, text="EVE", font=("Arial", 16, "bold"), 
                bg='#8e44ad', fg='white').pack()
        tk.Label(eve_frame, text="Atacante", font=("Arial", 10), 
                bg='#8e44ad', fg='white').pack()
        
        # Bob (derecha)
        bob_frame = tk.Frame(char_frame, bg='#3498db', relief=tk.RAISED, bd=3)
        bob_frame.place(relx=0.95, rely=0.5, anchor=tk.E, width=180, height=160)
        
        tk.Label(bob_frame, text="👨", font=("Arial", 50), bg='#3498db').pack(pady=5)
        tk.Label(bob_frame, text="BOB", font=("Arial", 16, "bold"), 
                bg='#3498db', fg='white').pack()
        tk.Label(bob_frame, text="Receptor", font=("Arial", 10), 
                bg='#3498db', fg='white').pack()
        
        # Línea de comunicación
        canvas = tk.Canvas(char_frame, bg='#34495e', highlightthickness=0)
        canvas.place(relx=0.2, rely=0.5, width=720, height=80)
        
        # Línea Alice -> Bob
        canvas.create_line(10, 40, 710, 40, fill='#95a5a6', width=3, dash=(5, 5))
        canvas.create_text(360, 60, text="Canal de Comunicación", 
                          fill='white', font=("Arial", 10))
    
    def create_tabs_frame(self):
        """Crea el frame con pestañas de funcionalidades"""
        tab_frame = tk.Frame(self.root, bg='#2c3e50')
        tab_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Notebook (pestañas)
        self.notebook = ttk.Notebook(tab_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Estilo para las pestañas
        style = ttk.Style()
        style.configure('TNotebook', background='#2c3e50')
        style.configure('TNotebook.Tab', padding=[20, 10], font=('Arial', 10))
        
        # Crear pestañas
        self.create_hash_tab()
        self.create_symmetric_tab()
        self.create_asymmetric_tab()
        self.create_attacks_tab()
    
    def create_hash_tab(self):
        """Pestaña de funciones hash"""
        tab = tk.Frame(self.notebook, bg='white')
        self.notebook.add(tab, text="🔐 Hash & Primitivas")
        
        # Título
        tk.Label(tab, text="Funciones Hash y Primitivas sin Llave", 
                font=("Arial", 14, "bold"), bg='white').pack(pady=10)
        
        # Frame de entrada
        input_frame = tk.LabelFrame(tab, text="Entrada", font=("Arial", 11, "bold"), 
                                   bg='white', padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(input_frame, text="Mensaje:", bg='white').pack(anchor=tk.W)
        self.hash_input = tk.Entry(input_frame, font=("Arial", 11), width=60)
        self.hash_input.pack(fill=tk.X, pady=5)
        self.hash_input.insert(0, "Hola, este es un mensaje de prueba")
        
        # Botones
        btn_frame = tk.Frame(input_frame, bg='white')
        btn_frame.pack(pady=5)
        
        tk.Button(btn_frame, text="Calcular SHA-256", command=self.calculate_sha256,
                 bg='#27ae60', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Calcular SHA-3", command=self.calculate_sha3,
                 bg='#16a085', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Generar Token Aleatorio", command=self.generate_token,
                 bg='#f39c12', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Frame de salida
        output_frame = tk.LabelFrame(tab, text="Resultado", font=("Arial", 11, "bold"), 
                                    bg='white', padx=10, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        self.hash_output = scrolledtext.ScrolledText(output_frame, font=("Courier", 10), 
                                                     height=10, wrap=tk.WORD)
        self.hash_output.pack(fill=tk.BOTH, expand=True)
    
    def create_symmetric_tab(self):
        """Pestaña de cifrado simétrico"""
        tab = tk.Frame(self.notebook, bg='white')
        self.notebook.add(tab, text="🔒 Cifrado Simétrico")
        
        tk.Label(tab, text="Cifrado Simétrico (AES-256)", 
                font=("Arial", 14, "bold"), bg='white').pack(pady=10)
        
        # Entrada
        input_frame = tk.LabelFrame(tab, text="Alice envía mensaje", 
                                   font=("Arial", 11, "bold"), bg='white', 
                                   padx=10, pady=10)
        input_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(input_frame, text="Mensaje para Bob:", bg='white').pack(anchor=tk.W)
        self.sym_input = tk.Entry(input_frame, font=("Arial", 11), width=60)
        self.sym_input.pack(fill=tk.X, pady=5)
        self.sym_input.insert(0, "Este es un mensaje secreto para Bob")
        
        # Clave
        tk.Label(input_frame, text="Clave compartida (se generará automáticamente):", 
                bg='white').pack(anchor=tk.W, pady=(10, 0))
        self.sym_key_label = tk.Label(input_frame, text="No generada aún", 
                                      bg='white', fg='gray', font=("Courier", 9))
        self.sym_key_label.pack(anchor=tk.W)
        
        # Botones
        btn_frame = tk.Frame(input_frame, bg='white')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🔑 Generar Clave", command=self.generate_symmetric_key,
                 bg='#9b59b6', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🔒 Cifrar (Alice)", command=self.encrypt_symmetric,
                 bg='#e74c3c', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🔓 Descifrar (Bob)", command=self.decrypt_symmetric,
                 bg='#3498db', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Salida
        output_frame = tk.LabelFrame(tab, text="Resultado", font=("Arial", 11, "bold"), 
                                    bg='white', padx=10, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        self.sym_output = scrolledtext.ScrolledText(output_frame, font=("Courier", 10), 
                                                    height=10, wrap=tk.WORD)
        self.sym_output.pack(fill=tk.BOTH, expand=True)
        
        # Variables para cifrado simétrico
        self.symmetric_key = None
        self.symmetric_iv = None
        self.symmetric_ciphertext = None
    
    def create_asymmetric_tab(self):
        """Pestaña de cifrado asimétrico"""
        tab = tk.Frame(self.notebook, bg='white')
        self.notebook.add(tab, text="🔑 Cifrado Asimétrico")
        
        tk.Label(tab, text="Cifrado Asimétrico (RSA-2048)", 
                font=("Arial", 14, "bold"), bg='white').pack(pady=10)
        
        # Frame de claves
        key_frame = tk.LabelFrame(tab, text="Gestión de Claves", 
                                 font=("Arial", 11, "bold"), bg='white', 
                                 padx=10, pady=10)
        key_frame.pack(fill=tk.X, padx=20, pady=5)
        
        btn_frame = tk.Frame(key_frame, bg='white')
        btn_frame.pack(pady=5)
        
        tk.Button(btn_frame, text="👩 Generar Claves Alice", 
                 command=self.generate_alice_keys,
                 bg='#e74c3c', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="👨 Generar Claves Bob", 
                 command=self.generate_bob_keys,
                 bg='#3498db', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        self.key_status = tk.Label(key_frame, text="Estado: No hay claves generadas", 
                                   bg='white', fg='red', font=("Arial", 10))
        self.key_status.pack(pady=5)
        
        # Frame de mensaje
        msg_frame = tk.LabelFrame(tab, text="Alice envía mensaje a Bob", 
                                 font=("Arial", 11, "bold"), bg='white', 
                                 padx=10, pady=10)
        msg_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(msg_frame, text="Mensaje:", bg='white').pack(anchor=tk.W)
        self.asym_input = tk.Entry(msg_frame, font=("Arial", 11), width=60)
        self.asym_input.pack(fill=tk.X, pady=5)
        self.asym_input.insert(0, "Mensaje confidencial para Bob")
        
        btn_frame2 = tk.Frame(msg_frame, bg='white')
        btn_frame2.pack(pady=5)
        
        tk.Button(btn_frame2, text="🔒 Cifrar con clave pública de Bob", 
                 command=self.encrypt_asymmetric,
                 bg='#27ae60', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame2, text="🔓 Descifrar con clave privada de Bob", 
                 command=self.decrypt_asymmetric,
                 bg='#2980b9', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Salida
        output_frame = tk.LabelFrame(tab, text="Resultado", font=("Arial", 11, "bold"), 
                                    bg='white', padx=10, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        self.asym_output = scrolledtext.ScrolledText(output_frame, font=("Courier", 10), 
                                                     height=8, wrap=tk.WORD)
        self.asym_output.pack(fill=tk.BOTH, expand=True)
        
        self.asymmetric_ciphertext = None
    
    def create_attacks_tab(self):
        """Pestaña de ataques"""
        tab = tk.Frame(self.notebook, bg='white')
        self.notebook.add(tab, text="⚠️ Ataques")
        
        tk.Label(tab, text="Demostraciones de Vulnerabilidades", 
                font=("Arial", 14, "bold"), bg='white').pack(pady=10)
        
        # Frame de ataques
        attack_frame = tk.LabelFrame(tab, text="Eve intenta atacar", 
                                    font=("Arial", 11, "bold"), bg='white', 
                                    padx=10, pady=10)
        attack_frame.pack(fill=tk.X, padx=20, pady=5)
        
        btn_frame = tk.Frame(attack_frame, bg='white')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="💀 Fuerza Bruta (contraseña débil)", 
                 command=self.demo_brute_force,
                 bg='#c0392b', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🔍 Vulnerabilidad ECB", 
                 command=self.demo_ecb,
                 bg='#d35400', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🕵️ Man-in-the-Middle", 
                 command=self.demo_mitm,
                 bg='#8e44ad', fg='white', font=("Arial", 10, "bold"), 
                 padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Salida
        output_frame = tk.LabelFrame(tab, text="Resultado del Ataque", 
                                    font=("Arial", 11, "bold"), bg='white', 
                                    padx=10, pady=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        self.attack_output = scrolledtext.ScrolledText(output_frame, font=("Courier", 10), 
                                                       height=15, wrap=tk.WORD)
        self.attack_output.pack(fill=tk.BOTH, expand=True)
    
    def create_log_frame(self):
        """Crea el frame de log inferior"""
        log_frame = tk.LabelFrame(self.root, text="📋 Log de Actividades", 
                                 font=("Arial", 11, "bold"), bg='white', 
                                 padx=5, pady=5)
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, font=("Courier", 9), 
                                                  height=6, wrap=tk.WORD, bg='#ecf0f1')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        self.log("Sistema iniciado. Listo para demostraciones.")
    
    def log(self, message):
        """Añade un mensaje al log"""
        self.log_text.insert(tk.END, f"[LOG] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.update()
    
    # ===== FUNCIONES DE HASH =====
    
    def calculate_sha256(self):
        message = self.hash_input.get()
        hash_result = hashlib.sha256(message.encode()).hexdigest()
        
        self.hash_output.delete(1.0, tk.END)
        self.hash_output.insert(tk.END, f"Mensaje original:\n{message}\n\n")
        self.hash_output.insert(tk.END, f"SHA-256:\n{hash_result}\n\n")
        self.hash_output.insert(tk.END, f"Longitud: 256 bits (64 caracteres hexadecimales)\n")
        
        self.log(f"Alice calculó SHA-256 del mensaje")
    
    def calculate_sha3(self):
        message = self.hash_input.get()
        hash_result = hashlib.sha3_256(message.encode()).hexdigest()
        
        self.hash_output.delete(1.0, tk.END)
        self.hash_output.insert(tk.END, f"Mensaje original:\n{message}\n\n")
        self.hash_output.insert(tk.END, f"SHA-3-256:\n{hash_result}\n\n")
        self.hash_output.insert(tk.END, f"Longitud: 256 bits (64 caracteres hexadecimales)\n")
        
        self.log(f"Alice calculó SHA-3 del mensaje")
    
    def generate_token(self):
        token = secrets.token_hex(32)
        
        self.hash_output.delete(1.0, tk.END)
        self.hash_output.insert(tk.END, f"Token aleatorio criptográficamente seguro (CSPRNG):\n\n")
        self.hash_output.insert(tk.END, f"{token}\n\n")
        self.hash_output.insert(tk.END, f"Longitud: 256 bits (64 caracteres hexadecimales)\n")
        self.hash_output.insert(tk.END, f"Uso: sesiones, claves temporales, nonces\n")
        
        self.log(f"Se generó un token aleatorio seguro")
    
    # ===== FUNCIONES DE CIFRADO SIMÉTRICO =====
    
    def generate_symmetric_key(self):
        self.symmetric_key = secrets.token_bytes(32)  # AES-256
        self.symmetric_iv = secrets.token_bytes(16)
        
        self.sym_key_label.config(text=f"Clave: {self.symmetric_key.hex()[:32]}...", 
                                 fg='green')
        self.sym_output.delete(1.0, tk.END)
        self.sym_output.insert(tk.END, f"✓ Clave simétrica AES-256 generada\n\n")
        self.sym_output.insert(tk.END, f"Clave (hex): {self.symmetric_key.hex()}\n\n")
        self.sym_output.insert(tk.END, f"IV (hex): {self.symmetric_iv.hex()}\n\n")
        self.sym_output.insert(tk.END, f"Esta clave es compartida entre Alice y Bob de forma segura.\n")
        
        self.log("Alice y Bob comparten una clave simétrica AES-256")
    
    def encrypt_symmetric(self):
        if not self.symmetric_key:
            messagebox.showwarning("Advertencia", "Primero genera una clave simétrica")
            return
        
        message = self.sym_input.get()
        
        # Padding
        def pad(data):
            padding_length = 16 - (len(data) % 16)
            return data + (chr(padding_length) * padding_length)
        
        message_padded = pad(message).encode()
        
        # Cifrar con AES-CBC
        cipher = Cipher(algorithms.AES(self.symmetric_key), 
                       modes.CBC(self.symmetric_iv), 
                       backend=default_backend())
        encryptor = cipher.encryptor()
        self.symmetric_ciphertext = encryptor.update(message_padded) + encryptor.finalize()
        
        self.sym_output.delete(1.0, tk.END)
        self.sym_output.insert(tk.END, f"[ALICE] Cifrado el mensaje con AES-256-CBC\n\n")
        self.sym_output.insert(tk.END, f"Mensaje original:\n{message}\n\n")
        self.sym_output.insert(tk.END, f"Texto cifrado (hex):\n{self.symmetric_ciphertext.hex()}\n\n")
        self.sym_output.insert(tk.END, f"✓ El mensaje viaja por el canal de forma segura\n")
        self.sym_output.insert(tk.END, f"✓ Eve no puede leer el contenido sin la clave\n")
        
        self.log("Alice cifró un mensaje para Bob usando AES-256")
    
    def decrypt_symmetric(self):
        if not self.symmetric_ciphertext:
            messagebox.showwarning("Advertencia", "Primero cifra un mensaje")
            return
        
        # Descifrar
        cipher = Cipher(algorithms.AES(self.symmetric_key), 
                       modes.CBC(self.symmetric_iv), 
                       backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(self.symmetric_ciphertext) + decryptor.finalize()
        
        # Quitar padding
        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length].decode()
        
        self.sym_output.delete(1.0, tk.END)
        self.sym_output.insert(tk.END, f"[BOB] Descifrado el mensaje con AES-256-CBC\n\n")
        self.sym_output.insert(tk.END, f"Texto cifrado recibido (hex):\n{self.symmetric_ciphertext.hex()[:64]}...\n\n")
        self.sym_output.insert(tk.END, f"Mensaje descifrado:\n{decrypted}\n\n")
        self.sym_output.insert(tk.END, f"✓ Bob recuperó el mensaje original exitosamente\n")
        
        self.log("Bob descifró el mensaje de Alice correctamente")
    
    # ===== FUNCIONES DE CIFRADO ASIMÉTRICO =====
    
    def generate_alice_keys(self):
        self.alice_key_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.alice_key_public = self.alice_key_private.public_key()
        
        self.update_key_status()
        self.log("Alice generó su par de claves RSA-2048")
    
    def generate_bob_keys(self):
        self.bob_key_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.bob_key_public = self.bob_key_private.public_key()
        
        self.update_key_status()
        self.log("Bob generó su par de claves RSA-2048")
    
    def update_key_status(self):
        alice_status = "✓" if self.alice_key_public else "✗"
        bob_status = "✓" if self.bob_key_public else "✗"
        
        status_text = f"Alice: {alice_status}  |  Bob: {bob_status}"
        color = "green" if (self.alice_key_public and self.bob_key_public) else "orange"
        
        self.key_status.config(text=f"Estado de claves: {status_text}", fg=color)
    
    def encrypt_asymmetric(self):
        if not self.bob_key_public:
            messagebox.showwarning("Advertencia", "Bob debe generar sus claves primero")
            return
        
        message = self.asym_input.get().encode()
        
        # Cifrar con la clave pública de Bob
        self.asymmetric_ciphertext = self.bob_key_public.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.asym_output.delete(1.0, tk.END)
        self.asym_output.insert(tk.END, f"[ALICE] Cifró con la clave pública de Bob\n\n")
        self.asym_output.insert(tk.END, f"Mensaje original:\n{message.decode()}\n\n")
        self.asym_output.insert(tk.END, f"Texto cifrado (hex):\n{self.asymmetric_ciphertext.hex()[:128]}...\n\n")
        self.asym_output.insert(tk.END, f"✓ Solo Bob puede descifrar esto con su clave privada\n")
        self.asym_output.insert(tk.END, f"✓ Eve no puede descifrar sin la clave privada de Bob\n")
        
        self.log("Alice cifró un mensaje con la clave pública de Bob")
    
    def decrypt_asymmetric(self):
        if not self.asymmetric_ciphertext:
            messagebox.showwarning("Advertencia", "Primero cifra un mensaje")
            return
        
        if not self.bob_key_private:
            messagebox.showwarning("Advertencia", "Bob debe tener su clave privada")
            return
        
        # Descifrar con la clave privada de Bob
        decrypted = self.bob_key_private.decrypt(
            self.asymmetric_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        self.asym_output.delete(1.0, tk.END)
        self.asym_output.insert(tk.END, f"[BOB] Descifró con su clave privada\n\n")
        self.asym_output.insert(tk.END, f"Mensaje descifrado:\n{decrypted.decode()}\n\n")
        self.asym_output.insert(tk.END, f"✓ Bob recuperó el mensaje de Alice exitosamente\n")
        
        self.log("Bob descifró el mensaje usando su clave privada RSA")
    
    # ===== FUNCIONES DE ATAQUES =====
    
    def demo_brute_force(self):
        import time
        from itertools import product
        
        self.attack_output.delete(1.0, tk.END)
        self.attack_output.insert(tk.END, "[EVE] Iniciando ataque de fuerza bruta...\n\n")
        self.attack_output.update()
        
        # Contraseña débil (4 dígitos)
        password_real = "1234"
        hash_objetivo = hashlib.sha256(password_real.encode()).hexdigest()
        
        self.attack_output.insert(tk.END, f"Objetivo: descifrar hash\n")
        self.attack_output.insert(tk.END, f"Hash: {hash_objetivo[:32]}...\n\n")
        self.attack_output.insert(tk.END, "Probando todas las combinaciones de 4 dígitos...\n\n")
        self.attack_output.update()
        
        intentos = 0
        inicio = time.time()
        
        for combinacion in product('0123456789', repeat=4):
            intentos += 1
            candidato = ''.join(combinacion)
            hash_candidato = hashlib.sha256(candidato.encode()).hexdigest()
            
            if intentos % 500 == 0:
                self.attack_output.insert(tk.END, f"Probando: {candidato} ({intentos} intentos)\n")
                self.attack_output.see(tk.END)
                self.attack_output.update()
            
            if hash_candidato == hash_objetivo:
                fin = time.time()
                self.attack_output.insert(tk.END, f"\n✓ ¡CONTRASEÑA ENCONTRADA: {candidato}!\n")
                self.attack_output.insert(tk.END, f"✓ Tiempo: {fin - inicio:.2f} segundos\n")
                self.attack_output.insert(tk.END, f"✓ Intentos: {intentos}\n\n")
                self.attack_output.insert(tk.END, "⚠️ LECCIÓN: Usa contraseñas largas y complejas\n")
                self.attack_output.insert(tk.END, "⚠️ Una contraseña de 8 caracteres alfanuméricos\n")
                self.attack_output.insert(tk.END, "   requeriría 218 trillones de intentos\n")
                break
        
        self.log("Eve realizó un ataque de fuerza bruta exitoso")
    
    def demo_ecb(self):
        self.attack_output.delete(1.0, tk.END)
        self.attack_output.insert(tk.END, "[EVE] Analizando vulnerabilidad del modo ECB...\n\n")
        
        clave = secrets.token_bytes(16)
        mensaje = "HOLA" * 4  # Bloques repetidos
        mensaje_bytes = mensaje.encode()
        
        self.attack_output.insert(tk.END, f"Mensaje interceptado: {mensaje}\n")
        self.attack_output.insert(tk.END, f"Patrón: Mismo bloque repetido 4 veces\n\n")
        
        # Cifrar con ECB
        cipher = Cipher(algorithms.AES(clave), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        cifrado = encryptor.update(mensaje_bytes) + encryptor.finalize()
        
        self.attack_output.insert(tk.END, "Bloques cifrados interceptados:\n")
        for i in range(0, len(cifrado), 16):
            bloque = cifrado[i:i+16]
            self.attack_output.insert(tk.END, f"Bloque {i//16 + 1}: {bloque.hex()}\n")
        
        self.attack_output.insert(tk.END, "\n⚠️ ¡TODOS LOS BLOQUES SON IDÉNTICOS!\n")
        self.attack_output.insert(tk.END, "⚠️ Eve puede detectar patrones en el mensaje\n")
        self.attack_output.insert(tk.END, "⚠️ Solución: usar CBC, CTR o GCM con IV aleatorio\n")
        
        self.log("Eve detectó vulnerabilidad en el modo ECB")
    
    def demo_mitm(self):
        self.attack_output.delete(1.0, tk.END)
        self.attack_output.insert(tk.END, "[SIMULACIÓN] Ataque Man-in-the-Middle\n\n")
        self.attack_output.insert(tk.END, "="*60 + "\n\n")
        
        self.attack_output.insert(tk.END, "1. Alice envía: 'Transferir $100 a la cuenta 12345'\n")
        self.attack_output.insert(tk.END, "   [Alice] -----> [Canal] -----> [Bob]\n\n")
        self.root.update()
        time.sleep(1)
        
        self.attack_output.insert(tk.END, "2. [EVE] Intercepta el mensaje en el canal\n")
        self.attack_output.insert(tk.END, "   [Alice] -----> [EVE] -X- [Bob]\n\n")
        self.root.update()
        time.sleep(1)
        
        self.attack_output.insert(tk.END, "3. [EVE] Modifica el mensaje:\n")
        self.attack_output.insert(tk.END, "   'Transferir $10000 a la cuenta 99999' (cuenta de Eve)\n\n")
        self.root.update()
        time.sleep(1)
        
        self.attack_output.insert(tk.END, "4. [EVE] Envía el mensaje modificado a Bob\n")
        self.attack_output.insert(tk.END, "   [Eve] -----> [Bob]\n\n")
        self.root.update()
        time.sleep(1)
        
        self.attack_output.insert(tk.END, "5. Bob recibe: 'Transferir $10000 a la cuenta 99999'\n")
        self.attack_output.insert(tk.END, "   Bob cree que el mensaje es de Alice\n\n")
        self.attack_output.insert(tk.END, "="*60 + "\n\n")
        
        self.attack_output.insert(tk.END, "⚠️ CONSECUENCIA: Bob ejecuta una orden fraudulenta\n\n")
        self.attack_output.insert(tk.END, "✓ SOLUCIÓN 1: Usar firmas digitales\n")
        self.attack_output.insert(tk.END, "  Alice firma el mensaje con su clave privada\n")
        self.attack_output.insert(tk.END, "  Bob verifica con la clave pública de Alice\n\n")
        self.attack_output.insert(tk.END, "✓ SOLUCIÓN 2: Usar certificados (PKI)\n")
        self.attack_output.insert(tk.END, "  Verificar identidades antes de comunicar\n\n")
        self.attack_output.insert(tk.END, "✓ SOLUCIÓN 3: Usar canales cifrados (TLS/SSL)\n")
        self.attack_output.insert(tk.END, "  HTTPS, VPN, etc.\n")
        
        self.log("Eve realizó un ataque Man-in-the-Middle exitoso")

def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
