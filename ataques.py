import hashlib
import time
from itertools import product

# 1. ATAQUE DE FUERZA BRUTA
def demo_fuerza_bruta():
    print("\n=== DEMOSTRACIÓN: ATAQUE DE FUERZA BRUTA ===\n")
    
    print("Simulación: Intentar descifrar un hash de contraseña débil\n")
    
    # Contraseña débil (4 dígitos)
    password_real = "1234"
    hash_objetivo = hashlib.sha256(password_real.encode()).hexdigest()
    
    print(f"Hash objetivo: {hash_objetivo[:32]}...")
    print("\n[Atacante] Probando todas las combinaciones de 4 dígitos...\n")
    
    intentos = 0
    inicio = time.time()
    
    for combinacion in product('0123456789', repeat=4):
        intentos += 1
        candidato = ''.join(combinacion)
        hash_candidato = hashlib.sha256(candidato.encode()).hexdigest()
        
        if intentos % 1000 == 0:
            print(f"Probando: {candidato} ({intentos} intentos)", end='\r')
        
        if hash_candidato == hash_objetivo:
            fin = time.time()
            print(f"\n\n✓ ¡Contraseña encontrada: {candidato}!")
            print(f"✓ Tiempo: {fin - inicio:.2f} segundos")
            print(f"✓ Intentos: {intentos}")
            break
    
    print("\nLección: Usa contraseñas largas y complejas")
    print("Una contraseña de 8 caracteres alfanuméricos = 218 trillones de combinaciones")

# 2. VULNERABILIDAD DEL MODO ECB
def demo_ecb_vulnerability():
    print("\n=== DEMOSTRACIÓN: VULNERABILIDAD DEL MODO ECB ===\n")
    
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import secrets
    
    print("El modo ECB cifra cada bloque independientemente")
    print("Bloques idénticos producen cifrados idénticos\n")
    
    clave = secrets.token_bytes(16)
    
    # Mensaje con bloques repetidos
    mensaje = "HOLA" * 4  # 16 caracteres = 1 bloque repetido
    mensaje_bytes = mensaje.encode()
    
    print(f"Mensaje original: {mensaje}")
    print(f"Patrón: Mismo bloque repetido 4 veces\n")
    
    # Cifrar con ECB
    cipher = Cipher(algorithms.AES(clave), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    cifrado = encryptor.update(mensaje_bytes) + encryptor.finalize()
    
    # Mostrar bloques cifrados
    print("Bloques cifrados (hex):")
    for i in range(0, len(cifrado), 16):
        bloque = cifrado[i:i+16]
        print(f"Bloque {i//16 + 1}: {bloque.hex()}")
    
    print("\n!Todos los bloques cifrados son IDÉNTICOS!")
    print("Un atacante puede detectar patrones en el mensaje original")
    print("Solución: Usar modos CBC, CTR o GCM con IV aleatorio")

# 3. ATAQUE MAN-IN-THE-MIDDLE (Simulación)
def demo_mitm():
    print("\n=== DEMOSTRACIÓN: ATAQUE MAN-IN-THE-MIDDLE ===\n")
    
    print("Escenario: Alice y Bob intentan comunicarse")
    print("Eve intercepta y modifica los mensajes\n")
    
    print("[Alice] → 'Hola Bob, transferir $100' → [Red]")
    mensaje_alice = "Transferir $100"
    
    print("[Eve intercepta el mensaje]")
    time.sleep(1)
    
    print("[Eve modifica el mensaje]")
    mensaje_modificado = "Transferir $10000"
    time.sleep(1)
    
    print(f"[Eve] → '{mensaje_modificado}' → [Bob]")
    print(f"\n[Bob recibe]: '{mensaje_modificado}'")
    
    print("\nBob cree que el mensaje es de Alice")
    print("\n✓ Solución: Usar firmas digitales y certificados")
    print("✓ Con firma digital, Bob puede verificar la autenticidad")
    print("✓ Con PKI, Alice y Bob pueden verificar identidades")

# 4. ANÁLISIS DE VULNERABILIDADES
def analisis_vulnerabilidades():
    print("\n=== ANÁLISIS: ALGORITMOS VULNERABLES VS SEGUROS ===\n")
    
    print("ALGORITMOS VULNERABLES:")
    print("-" * 50)
    print("✗ DES (Data Encryption Standard)")
    print("  - Clave de solo 56 bits")
    print("  - Vulnerable a fuerza bruta en horas\n")
    
    print("✗ MD5 (Message Digest 5)")
    print("  - Colisiones encontradas en 2004")
    print("  - No usar para seguridad\n")
    
    print("✗ SHA-1")
    print("  - Colisiones prácticas desde 2017")
    print("  - Deprecado para certificados SSL\n")
    
    print("✗ RSA < 2048 bits")
    print("  - Vulnerable a factorización")
    print("  - RSA-1024 puede romperse con recursos suficientes\n")
    
    print("\nALGORITMOS SEGUROS (2025):")
    print("-" * 50)
    print("✓ AES-256")
    print("  - Estándar actual para cifrado simétrico")
    print("  - Sin vulnerabilidades prácticas conocidas\n")
    
    print("✓ SHA-256 / SHA-3")
    print("  - Seguros para hashing")
    print("  - Ampliamente utilizados en blockchain\n")
    
    print("✓ RSA-2048 o superior")
    print("  - Seguro hasta 2030+")
    print("  - RSA-4096 para mayor longevidad\n")
    
    print("✓ ChaCha20-Poly1305")
    print("  - Cifrado de flujo moderno")
    print("  - Usado en TLS 1.3\n")
    
    print("✓ Ed25519 (Curvas elípticas)")
    print("  - Firmas digitales rápidas y seguras")
    print("  - Claves más pequeñas que RSA\n")

def menu_ataques():
    while True:
        print("\n" + "="*50)
        print("ATAQUES Y VULNERABILIDADES")
        print("="*50)
        print("1. Ataque de Fuerza Bruta")
        print("2. Vulnerabilidad ECB")
        print("3. Man-in-the-Middle")
        print("4. Análisis de Vulnerabilidades")
        print("0. Volver")
        
        opcion = input("\nSelecciona una opción: ")
        
        if opcion == "1":
            demo_fuerza_bruta()
        elif opcion == "2":
            demo_ecb_vulnerability()
        elif opcion == "3":
            demo_mitm()
        elif opcion == "4":
            analisis_vulnerabilidades()
        elif opcion == "0":
            break
        
        input("\nPresiona Enter para continuar...")
