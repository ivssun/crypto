import os
import binascii

class Usuario:
    def __init__(self, nombre):
        self.nombre = nombre
        self.clave_publica = None
        self.clave_privada = None
        self.mensajes = []
    
    def recibir_mensaje(self, mensaje):
        self.mensajes.append(mensaje)
        print(f"[{self.nombre}] Mensaje recibido: {mensaje[:50]}...")

def mostrar_hex(datos, etiqueta="Datos"):
    if isinstance(datos, str):
        datos = datos.encode()
    print(f"{etiqueta}: {binascii.hexlify(datos).decode()[:64]}...")

def pausa():
    input("\nPresiona Enter para continuar...")
