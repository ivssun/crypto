from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os
import secrets

# 1. CIFRADO POR BLOQUES (AES)
def demo_cifrado_bloques():
    print("\n=== DEMOSTRACIÓN: CIFRADO POR BLOQUES (AES) ===\n")
    
    mensaje = input("Mensaje a cifrar: ")
    
    # Padding para completar bloques de 16 bytes
    def pad(data):
        padding_length = 16 - (len(data) % 16)
        return data + (chr(padding_length) * padding_length)
    
    mensaje_padded = pad(mensaje).encode()
    
    # Generar clave de 256 bits
    clave = secrets.token_bytes(32)
    print(f"\nClave AES-256: {clave.hex()[:32]}...")
    
    # Modo ECB (NO SEGURO - solo para demostración)
    print("\n--- Modo ECB (Inseguro) ---")
    cipher_ecb = Cipher(algorithms.AES(clave), modes.ECB(), backend=default_backend())
    encryptor = cipher_ecb.encryptor()
    cifrado_ecb = encryptor.update(mensaje_padded) + encryptor.finalize()
    print(f"Cifrado ECB: {cifrado_ecb.hex()[:64]}...")
    print("⚠️ ECB es inseguro: bloques idénticos producen cifrado idéntico")
    
    # Modo CBC (SEGURO)
    print("\n--- Modo CBC (Seguro) ---")
    iv = secrets.token_bytes(16)
    print(f"Vector de inicialización (IV): {iv.hex()}")
    
    cipher_cbc = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
    encryptor = cipher_cbc.encryptor()
    cifrado_cbc = encryptor.update(mensaje_padded) + encryptor.finalize()
    print(f"Cifrado CBC: {cifrado_cbc.hex()[:64]}...")
    
    # Descifrado
    decryptor = cipher_cbc.decryptor()
    descifrado = decryptor.update(cifrado_cbc) + decryptor.finalize()
    
    # Quitar padding
    padding_length = descifrado[-1]
    mensaje_original = descifrado[:-padding_length].decode()
    print(f"\nMensaje descifrado: {mensaje_original}")

# 2. CIFRADO DE FLUJO (ChaCha20)
def demo_cifrado_flujo():
    print("\n=== DEMOSTRACIÓN: CIFRADO DE FLUJO (ChaCha20) ===\n")
    
    mensaje = input("Mensaje a cifrar: ").encode()
    
    # Clave de 256 bits y nonce de 128 bits
    clave = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)
    
    print(f"\nClave: {clave.hex()[:32]}...")
    print(f"Nonce: {nonce.hex()}")
    
    # Cifrado
    cipher = Cipher(algorithms.ChaCha20(clave, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(mensaje)
    
    print(f"\nMensaje cifrado: {cifrado.hex()}")
    
    # Descifrado (mismo proceso)
    decryptor = cipher.decryptor()
    descifrado = decryptor.update(cifrado)
    
    print(f"Mensaje descifrado: {descifrado.decode()}")

# 3. CÓDIGOS DE AUTENTICACIÓN DE MENSAJES (MAC)
def demo_mac():
    print("\n=== DEMOSTRACIÓN: MAC (HMAC-SHA256) ===\n")
    
    mensaje = input("Mensaje a autenticar: ").encode()
    clave = secrets.token_bytes(32)
    
    print(f"\nClave secreta compartida: {clave.hex()[:32]}...")
    
    # Generar HMAC
    h = hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h.update(mensaje)
    mac = h.finalize()
    
    print(f"MAC generado: {mac.hex()}")
    
    # Verificación
    print("\n[Receptor verifica la integridad]")
    h2 = hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h2.update(mensaje)
    
    try:
        h2.verify(mac)
        print("✓ Verificación exitosa - Mensaje íntegro y auténtico")
    except:
        print("✗ Verificación fallida - Mensaje alterado o clave incorrecta")
    
    # Demostrar alteración
    print("\n[Simulando alteración del mensaje]")
    mensaje_alterado = mensaje + b"X"
    h3 = hmac.HMAC(clave, hashes.SHA256(), backend=default_backend())
    h3.update(mensaje_alterado)
    
    try:
        h3.verify(mac)
        print("✓ Verificación exitosa")
    except:
        print("✗ Verificación fallida - Se detectó la alteración")

# 4. DERIVACIÓN DE CLAVES (KDF)
def demo_kdf():
    print("\n=== DEMOSTRACIÓN: KEY DERIVATION FUNCTION (PBKDF2) ===\n")
    
    password = input("Ingresa una contraseña: ").encode()
    
    # Salt aleatorio
    salt = secrets.token_bytes(16)
    print(f"\nSalt: {salt.hex()}")
    
    # Derivar clave con 100,000 iteraciones
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    
    clave_derivada = kdf.derive(password)
    print(f"Clave derivada (256 bits): {clave_derivada.hex()}")
    
    print("\n✓ Esta clave puede usarse para cifrado AES-256")
    print("✓ Las iteraciones hacen costoso el ataque por fuerza bruta")

def menu_simetrico():
    while True:
        print("\n" + "="*50)
        print("CIFRADO SIMÉTRICO")
        print("="*50)
        print("1. Cifrado por Bloques (AES)")
        print("2. Cifrado de Flujo (ChaCha20)")
        print("3. MAC (HMAC)")
        print("4. Derivación de Claves (KDF)")
        print("0. Volver")
        
        opcion = input("\nSelecciona una opción: ")
        
        if opcion == "1":
            demo_cifrado_bloques()
        elif opcion == "2":
            demo_cifrado_flujo()
        elif opcion == "3":
            demo_mac()
        elif opcion == "4":
            demo_kdf()
        elif opcion == "0":
            break
        
        input("\nPresiona Enter para continuar...")
