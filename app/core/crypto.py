"""
Módulo Criptográfico para Cifrado en Reposo de Datos Biométricos (app/core/crypto.py).
Implementa Cifrado Autenticado con Datos Asociados (AEAD) mediante AES-256-GCM
(Galois/Counter Mode) bajo la biblioteca estándar de ciberseguridad 'cryptography'.

Requerimiento de Tesis:
- RNF-01 (Seguridad de Datos): Cifrado en reposo para vectores y plantillas biométricas.
- CP-S10 (Protección contra Tampering / Sabotaje Interno):
  Si un atacante o administrador malicioso altera 1 solo bit del vector cifrado en
  la columna 'vector_encrypted' (BYTEA) de PostgreSQL, el tag de autenticación
  GCM rechaza el descifrado arrojando 'InvalidTag', evitando la inyección de vectores corruptos.
"""

import json
import os
from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings


def encrypt_vector(vector: List[float]) -> bytes:
    """
    Cifra un vector de características biomecánicas (dinámica de tecleo) usando AES-256-GCM.

    ¿Cómo funciona el proceso de cifrado paso a paso?
    --------------------------------------------------
    1. Validación de Entrada:
       Verifica que el parámetro sea una lista de números flotantes válidos.
    2. Serialización del Vector Numérico:
       El vector de 31 floats (ej. [0.085, 0.120, ...]) se serializa a una cadena
       JSON canónica y se codifica como un arreglo de bytes en UTF-8.
    3. Generación del Nonce (Number used Once) de 12 bytes (96 bits):
       Se genera mediante `os.urandom(12)`, fuente criptográfica del kernel del SO.
       12 bytes es la longitud óptima recomendada por NIST SP 800-38D para AES-GCM;
       evita colisiones y garantiza que dos vectores idénticos cifrados con la misma
       llave produzcan criptogramas completamente diferentes (indistinguibilidad semántica).
    4. Cifrado Autenticado AEAD (AESGCM):
       Utiliza la llave maestra de 256 bits (32 bytes). AES-GCM realiza dos funciones
       simultáneas:
       a) Cifra el contenido en modo Counter (CTR).
       b) Calcula un Tag de Autenticación de 16 bytes (128 bits) utilizando el
          multiplicador universal en el campo de Galois GHASH.
    5. Empaquetado Binario:
       Se concatenan el Nonce (12 bytes) al inicio del Criptograma resultante
       (que incluye el Authentication Tag de 16 bytes al final):
       [ Nonce (12 bytes) | Criptograma Cifrado | Tag de Autenticación (16 bytes) ]
       Este formato se almacena directamente en la base de datos (PostgreSQL BYTEA).

    Args:
        vector (List[float]): Lista de números flotantes (tiempos H, DD, UD en segundos).

    Returns:
        bytes: Arreglo binario con el nonce prepuesto y el criptograma autenticado.
    """
    if not isinstance(vector, list) or not all(isinstance(x, (int, float)) for x in vector):
        raise ValueError("Vector must be a list of numeric values (floats).")

    # Paso 1: Serializar el vector flotante a bytes JSON en UTF-8
    data_bytes = json.dumps(vector).encode("utf-8")

    # Paso 2: Generar Nonce criptográfico aleatorio único de 12 bytes (NIST standard)
    nonce = os.urandom(12)

    # Paso 3: Inicializar el cifrador AES-256-GCM con la clave de 32 bytes (256 bits)
    aesgcm = AESGCM(settings.AES_KEY_BYTES)

    # Paso 4: Cifrar los datos (el resultado incluye los datos cifrados + el tag de 16 bytes)
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)

    # Paso 5: Retornar Nonce (12 bytes) + Criptograma (con Tag de 16 bytes)
    return nonce + ciphertext


def decrypt_vector(encrypted_data: bytes) -> List[float]:
    """
    Descifra un vector biométrico cifrado con AES-256-GCM y valida su autenticidad e integridad.

    ¿Cómo protege contra Tampering / Sabotaje en el Caso de Prueba CP-S10?
    ----------------------------------------------------------------------
    1. Verificación de Longitud Mínima:
       El binario debe tener al menos 28 bytes (12 bytes del nonce + 16 bytes del tag
       de autenticación mínimo para un payload vacío).
    2. Separación de Componentes:
       Se extraen los primeros 12 bytes correspondientes al Nonce público, y el resto
       corresponde al criptograma junto con el Authentication Tag.
    3. Verificación Criptográfica de Integridad (Detección de Manipulación):
       Al invocar `aesgcm.decrypt(nonce, ciphertext, None)`, el algoritmo recalcula
       internamente el código de autenticación GHASH. Si un atacante modificó aunque sea
       UN SOLO BIT en la base de datos (simulado en el test CP-S10):
       - El hash calculado NO coincide con el tag de autenticación de 16 bytes.
       - La biblioteca `cryptography` levanta inmediatamente una excepción `InvalidTag`.
       - La operación de reautenticación es denegada antes de procesar cualquier dato.
    4. Deserialización Segura:
       Si el tag es válido, los bytes descifrados se decodifican de UTF-8 y se
       reconstruye la lista de floats original en memoria RAM.

    Args:
        encrypted_data (bytes): Arreglo binario [Nonce 12B | Ciphertext + Tag 16B].

    Returns:
        List[float]: Vector original de 31 características biomecánicas descifrado.

    Raises:
        ValueError: Si los datos no son bytes o la longitud es inferior a 28 bytes.
        cryptography.exceptions.InvalidTag: Si el vector fue manipulado o corrompido (CP-S10).
    """
    if not isinstance(encrypted_data, (bytes, bytearray)):
        raise ValueError("Encrypted data must be bytes or bytearray.")

    # 12 bytes del nonce + 16 bytes mínimos del authentication tag = mínimo 28 bytes
    if len(encrypted_data) < 28:
        raise ValueError("Invalid encrypted data length: minimum 28 bytes required.")

    # Extraer el Nonce de 12 bytes del prefijo
    nonce = encrypted_data[:12]
    # Extraer el Criptograma con el Tag de autenticación de 16 bytes al final
    ciphertext = encrypted_data[12:]

    # Inicializar la primitiva criptográfica con la llave maestra simétrica
    aesgcm = AESGCM(settings.AES_KEY_BYTES)

    # Validar el Authentication Tag y descifrar; arroja InvalidTag si hubo modificación de bits
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    # Deserializar la lista JSON de números flotantes de vuelta a memoria
    parsed = json.loads(decrypted_bytes.decode("utf-8"))
    return [float(x) for x in parsed]

