#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demostración de Primitivas Criptográficas
Proyecto de Ciberseguridad
Comunicación Alice, Bob y Eve
"""

import os
import sys
from primitivas_sin_llave import menu_primitivas
from cifrado_simetrico import menu_simetrico
from cifrado_asimetrico import menu_asimetrico
from ataques import menu_ataques

def limpiar_pantalla():
    """Limpia la pantalla según el sistema operativo"""
    os.system('clear' if os.name == 'posix' else 'cls')

def mostrar_banner():
    """Muestra el banner principal con Alice, Bob y Eve"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        DEMOSTRACIÓN DE PRIMITIVAS CRIPTOGRÁFICAS                ║
║                                                                  ║
║                         Eve (Atacante)                           ║
║                              🦹                                  ║
║                              |                                   ║
║     Alice  ~~~~~~~~~~~~~~~~ Canal ~~~~~~~~~~~~~~~~  Bob          ║
║       👩     <---- Comunicación Segura ---->     👨             ║
║                                                                  ║
║              Proyecto de Ciberseguridad 2025                     ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def mostrar_info():
    """Muestra información sobre el proyecto"""
    print("\n" + "="*70)
    print("SOBRE ESTE PROYECTO")
    print("="*70)
    print("""
Este programa demuestra el funcionamiento de primitivas criptográficas
mediante la simulación de comunicación entre tres actores:

- Alice: Usuario legítimo que envía mensajes
- Bob: Usuario legítimo que recibe mensajes  
- Eve: Atacante que intenta interceptar o descifrar comunicaciones

El programa está dividido en cuatro módulos principales:

1. Primitivas sin uso de llaves
   - Funciones hash criptográficas
   - Generadores de números aleatorios seguros (CSPRNG)
   - Pruebas de conocimiento cero
   - Esquemas de compromiso (commitment)

2. Cifrado simétrico
   - Cifrado por bloques (AES)
   - Cifrado de flujo (ChaCha20)
   - Códigos de autenticación de mensajes (MAC)
   - Derivación de claves (KDF)

3. Cifrado asimétrico
   - Cifrado de clave pública (RSA)
   - Firmas digitales
   - Intercambio de claves
   - Infraestructura de clave pública (PKI)

4. Ataques y vulnerabilidades
   - Ataques de fuerza bruta
   - Vulnerabilidades de algoritmos
   - Ataques man-in-the-middle
   - Análisis de seguridad

Librerías utilizadas:
- cryptography: Primitivas criptográficas modernas
- pycryptodome: Algoritmos adicionales
- hashlib: Funciones hash (biblioteca estándar)
- secrets: Generación segura de aleatorios (biblioteca estándar)
""")
    print("="*70)

def verificar_dependencias():
    """Verifica que las librerías necesarias estén instaladas"""
    try:
        import cryptography
        import Crypto
        return True
    except ImportError:
        print("\n⚠️  ERROR: Faltan dependencias requeridas")
        print("\nPor favor, instala las librerías necesarias:")
        print("  pip install cryptography pycryptodome")
        print("\nO usa el archivo requirements.txt:")
        print("  pip install -r requirements.txt")
        return False

def menu_principal():
    """Menú principal del programa"""
    
    # Verificar dependencias al inicio
    if not verificar_dependencias():
        sys.exit(1)
    
    while True:
        limpiar_pantalla()
        mostrar_banner()
        
        print("\n" + "="*70)
        print("MENÚ PRINCIPAL")
        print("="*70)
        print("1. Primitivas sin uso de llaves")
        print("2. Cifrado simétrico")
        print("3. Cifrado asimétrico")
        print("4. Ataques y vulnerabilidades")
        print("5. Información del proyecto")
        print("0. Salir")
        print("="*70)
        
        opcion = input("\nSelecciona una opción: ")
        
        if opcion == "1":
            limpiar_pantalla()
            menu_primitivas()
        elif opcion == "2":
            limpiar_pantalla()
            menu_simetrico()
        elif opcion == "3":
            limpiar_pantalla()
            menu_asimetrico()
        elif opcion == "4":
            limpiar_pantalla()
            menu_ataques()
        elif opcion == "5":
            limpiar_pantalla()
            mostrar_info()
            input("\nPresiona Enter para volver al menú...")
        elif opcion == "0":
            print("\n¡Hasta luego! 👋")
            sys.exit(0)
        else:
            print("\n⚠️  Opción inválida. Intenta de nuevo.")
            input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print("\n\nPrograma interrumpido por el usuario. ¡Hasta luego! 👋")
        sys.exit(0)
    except Exception as e:
        print(f"\n⚠️  Error inesperado: {e}")
        print("Por favor, reporta este error al desarrollador.")
        sys.exit(1)
