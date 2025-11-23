import hashlib
import secrets
import os

# 1. FUNCIONES HASH
def demo_hash():
    print("\n=== DEMOSTRACIÓN: FUNCIONES HASH ===\n")
    mensaje = input("Ingresa un mensaje: ")
    
    # SHA-256
    hash_sha256 = hashlib.sha256(mensaje.encode()).hexdigest()
    print(f"\nSHA-256: {hash_sha256}")
    
    # SHA-3
    hash_sha3 = hashlib.sha3_256(mensaje.encode()).hexdigest()
    print(f"SHA-3-256: {hash_sha3}")
    
    # Demostrar que un cambio mínimo cambia todo el hash
    mensaje_modificado = mensaje + "."
    hash_modificado = hashlib.sha256(mensaje_modificado.encode()).hexdigest()
    print(f"\nMensaje modificado (añadido '.'): {hash_modificado}")
    print("Observa cómo el hash cambió completamente con un solo carácter.")

# 2. GENERADOR DE NÚMEROS ALEATORIOS CRIPTOGRÁFICAMENTE SEGURO
def demo_csprng():
    print("\n=== DEMOSTRACIÓN: CSPRNG ===\n")
    
    # Generar bytes aleatorios seguros
    random_bytes = secrets.token_bytes(32)
    print(f"32 bytes aleatorios (hex): {random_bytes.hex()}")
    
    # Generar token para sesión
    token = secrets.token_urlsafe(32)
    print(f"\nToken de sesión seguro: {token}")
    
    # Comparación con random no seguro (NO usar para criptografía)
    import random
    random.seed(42)  # Semilla predecible
    print(f"\nRandom NO seguro (predecible): {random.randint(1000, 9999)}")
    print("NUNCA usar random.random() para criptografía")

# 3. PRUEBA DE CONOCIMIENTO CERO (Zero-Knowledge Proof)
def demo_zero_knowledge():
    print("\n=== DEMOSTRACIÓN: ZERO-KNOWLEDGE PROOF ===\n")
    print("Protocolo: Alice demuestra que conoce una contraseña sin revelarla")
    
    # Alice conoce la contraseña
    password = "secreto123"
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    print(f"\nHash almacenado del servidor: {password_hash[:32]}...")
    
    # Alice genera un desafío
    nonce = secrets.token_hex(16)
    print(f"Nonce aleatorio generado: {nonce}")
    
    # Alice crea la respuesta
    respuesta = hashlib.sha256((password + nonce).encode()).hexdigest()
    print(f"Respuesta de Alice: {respuesta[:32]}...")
    
    # Verificación
    print("\n[Servidor verifica sin conocer la contraseña]")
    verificacion = hashlib.sha256((password + nonce).encode()).hexdigest()
    
    if respuesta == verificacion:
        print("✓ Autenticación exitosa - Alice demostró que conoce la contraseña")
        print("✓ La contraseña nunca se transmitió por la red")
    else:
        print("✗ Autenticación fallida")

# 4. FUNCIONES DE COMPROMISO (Commitment)
def demo_commitment():
    print("\n=== DEMOSTRACIÓN: COMMITMENT SCHEME ===\n")
    print("Escenario: Alice hace un compromiso sobre un valor sin revelarlo\n")
    
    # Fase 1: Commitment
    valor_secreto = input("Alice, ingresa tu elección (cara/cruz): ")
    salt = secrets.token_hex(16)
    
    commitment = hashlib.sha256((valor_secreto + salt).encode()).hexdigest()
    print(f"\nCommitment publicado: {commitment}")
    print("(Este valor no revela la elección de Alice)\n")
    
    input("Bob hace su elección... [Enter para continuar]")
    
    # Fase 2: Reveal
    print(f"\n[Alice revela]")
    print(f"Valor: {valor_secreto}")
    print(f"Salt: {salt}")
    
    # Verificación
    verificacion = hashlib.sha256((valor_secreto + salt).encode()).hexdigest()
    if commitment == verificacion:
        print(f"\n✓ Verificación exitosa - Alice no hizo trampa")
    else:
        print(f"\n✗ Verificación fallida - Los valores no coinciden")

def menu_primitivas():
    while True:
        print("\n" + "="*50)
        print("PRIMITIVAS SIN USO DE LLAVES")
        print("="*50)
        print("1. Funciones Hash")
        print("2. CSPRNG (Generador Aleatorio Seguro)")
        print("3. Zero-Knowledge Proof")
        print("4. Commitment Scheme")
        print("0. Volver")
        
        opcion = input("\nSelecciona una opción: ")
        
        if opcion == "1":
            demo_hash()
        elif opcion == "2":
            demo_csprng()
        elif opcion == "3":
            demo_zero_knowledge()
        elif opcion == "4":
            demo_commitment()
        elif opcion == "0":
            break
        
        input("\nPresiona Enter para continuar...")
