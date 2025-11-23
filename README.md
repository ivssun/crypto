# CIBERSEGURIDAD - OLIMPIA MOCTEZUMA

# Demostración de Primitivas Criptográficas

Proyecto educativo que demuestra el funcionamiento de primitivas criptográficas
mediante la simulación de comunicación entre Alice, Bob y Eve.

## Requisitos

- Python 3.7 o superior
- Linux, macOS o Windows
- Librerías: cryptography, pycryptodome

## Instalación

### En Linux/macOS:
```bash
# Clonar o descargar el proyecto
cd proyecto_crypto

# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar
python3 main.py
```

### En Windows:
```cmd
# Navegar al proyecto
cd proyecto_crypto

# Crear entorno virtual (recomendado)
python -m venv venv
venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar
python main.py
```

## Estructura del Proyecto

El proyecto está organizado en los siguientes módulos:

- **`main.py`**: Punto de entrada principal. Permite seleccionar entre el modo Gráfico (GUI) y el modo Consola (Terminal).
- **`gui_crypto.py`**: Implementación de la interfaz gráfica de usuario utilizando `tkinter`. Contiene las visualizaciones de Alice, Bob y Eve.
- **`primitivas_sin_llave.py`**: Módulo con demostraciones de funciones Hash (SHA-256, SHA-3), generadores aleatorios (CSPRNG) y pruebas de conocimiento cero.
- **`cifrado_simetrico.py`**: Contiene la lógica para cifrado AES (modos CBC y ECB), ChaCha20, HMAC y derivación de claves (PBKDF2).
- **`cifrado_asimetrico.py`**: Implementa funciones para RSA, firmas digitales, intercambio de claves y generación de certificados simulados.
- **`ataques.py`**: Scripts que simulan vulnerabilidades y ataques, incluyendo fuerza bruta, debilidades del modo ECB y Man-in-the-Middle.
- **`utils.py`**: Funciones auxiliares y utilidades compartidas (formateo hexadecimal, clases de usuario, etc.).
- **`requirements.txt`**: Archivo de dependencias necesarias para instalar las librerías externas (`cryptography`, `pycryptodome`).
