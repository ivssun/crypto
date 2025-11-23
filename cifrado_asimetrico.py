from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

# 1. CIFRADO DE CLAVE PÚBLICA (RSA)
def demo_rsa():
    print("\n=== DEMOSTRACIÓN: CIFRADO RSA ===\n")
    
    print("[Bob genera su par de claves]")
    # Generar par de claves RSA
    clave_privada_bob = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica_bob = clave_privada_bob.public_key()
    
    print("✓ Par de claves RSA-2048 generado")
    
    # Alice cifra un mensaje con la clave pública de Bob
    mensaje = input("\n[Alice] Mensaje secreto para Bob: ").encode()
    
    cifrado = clave_publica_bob.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"\nMensaje cifrado (hex): {cifrado.hex()[:64]}...")
    print("✓ Solo Bob puede descifrar este mensaje con su clave privada")
    
    # Bob descifra con su clave privada
    print("\n[Bob descifra el mensaje]")
    descifrado = clave_privada_bob.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"Mensaje descifrado: {descifrado.decode()}")

# 2. FIRMAS DIGITALES
def demo_firmas():
    print("\n=== DEMOSTRACIÓN: FIRMAS DIGITALES ===\n")
    
    print("[Alice genera su par de claves]")
    clave_privada_alice = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica_alice = clave_privada_alice.public_key()
    
    # Alice firma un mensaje
    mensaje = input("\n[Alice] Mensaje a firmar: ").encode()
    
    firma = clave_privada_alice.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print(f"\nFirma digital: {firma.hex()[:64]}...")
    
    # Bob verifica la firma
    print("\n[Bob verifica la firma de Alice]")
    try:
        clave_publica_alice.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✓ Firma válida - El mensaje es auténtico y no ha sido alterado")
    except:
        print("✗ Firma inválida - El mensaje fue alterado o no es de Alice")
    
    # Demostrar alteración
    print("\n[Simulando alteración del mensaje]")
    mensaje_alterado = mensaje + b"X"
    try:
        clave_publica_alice.verify(
            firma,
            mensaje_alterado,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("✓ Firma válida")
    except:
        print("✗ Firma inválida - Se detectó la alteración del mensaje")

# 3. INTERCAMBIO DE CLAVES (Diffie-Hellman simplificado con RSA)
def demo_intercambio_claves():
    print("\n=== DEMOSTRACIÓN: INTERCAMBIO DE CLAVES ===\n")
    
    print("[Alice y Bob generan sus pares de claves]")
    
    # Alice genera su par
    clave_privada_alice = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica_alice = clave_privada_alice.public_key()
    
    # Bob genera su par
    clave_privada_bob = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica_bob = clave_privada_bob.public_key()
    
    print("✓ Alice y Bob intercambian sus claves públicas\n")
    
    # Alice genera una clave de sesión simétrica
    import secrets
    clave_sesion = secrets.token_bytes(32)
    print(f"[Alice] Clave de sesión AES-256: {clave_sesion.hex()[:32]}...")
    
    # Alice cifra la clave de sesión con la clave pública de Bob
    clave_cifrada = clave_publica_bob.encrypt(
        clave_sesion,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"\n[Alice envía a Bob] Clave cifrada: {clave_cifrada.hex()[:64]}...")
    
    # Bob descifra la clave de sesión
    clave_recibida = clave_privada_bob.decrypt(
        clave_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print(f"\n[Bob descifra] Clave de sesión: {clave_recibida.hex()[:32]}...")
    
    if clave_sesion == clave_recibida:
        print("\n✓ Intercambio exitoso - Ambos comparten la misma clave de sesión")
        print("✓ Ahora pueden usar cifrado simétrico (más rápido)")

# 4. INFRAESTRUCTURA DE CLAVE PÚBLICA (PKI) - Certificado simple
def demo_pki():
    print("\n=== DEMOSTRACIÓN: PKI - CERTIFICADO DIGITAL ===\n")
    
    print("[Autoridad Certificadora genera su par de claves]")
    # Clave de la CA
    clave_ca = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Clave del usuario (Alice)
    print("\n[Alice genera su par de claves]")
    clave_alice = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica_alice = clave_alice.public_key()
    
    # Crear certificado para Alice
    nombre_alice = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Veracruz"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Veracruz"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universidad"),
        x509.NameAttribute(NameOID.COMMON_NAME, "alice@universidad.edu"),
    ])
    
    certificado = x509.CertificateBuilder().subject_name(
        nombre_alice
    ).issuer_name(
        nombre_alice  # Auto-firmado para simplificar
    ).public_key(
        clave_publica_alice
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(clave_ca, hashes.SHA256(), default_backend())
    
    print("\n✓ Certificado digital generado para Alice")
    print(f"\nSubject: {certificado.subject}")
    print(f"Serial Number: {certificado.serial_number}")
    print(f"Válido desde: {certificado.not_valid_before}")
    print(f"Válido hasta: {certificado.not_valid_after}")
    
    # Exportar certificado
    cert_pem = certificado.public_bytes(serialization.Encoding.PEM)
    print(f"\nCertificado (PEM):\n{cert_pem.decode()[:200]}...")

def menu_asimetrico():
    while True:
        print("\n" + "="*50)
        print("CIFRADO ASIMÉTRICO")
        print("="*50)
        print("1. Cifrado de Clave Pública (RSA)")
        print("2. Firmas Digitales")
        print("3. Intercambio de Claves")
        print("4. PKI - Certificados Digitales")
        print("0. Volver")
        
        opcion = input("\nSelecciona una opción: ")
        
        if opcion == "1":
            demo_rsa()
        elif opcion == "2":
            demo_firmas()
        elif opcion == "3":
            demo_intercambio_claves()
        elif opcion == "4":
            demo_pki()
        elif opcion == "0":
            break
        
        input("\nPresiona Enter para continuar...")
