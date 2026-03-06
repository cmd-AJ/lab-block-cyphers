

#Para la instalación de las librerias de Crypto utilizar pip install pycryptodome 
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def encrypt_3des_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto para 3DES"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> len(ciphertext) % 8
        0  # Debe ser múltiplo de 8 (tamaño de bloque de DES)
    """

    key = DES3.adjust_key_parity(key)
    # Para verificar que la llave tiene la misma longitud se debe de verificar los bits de paridad.  

    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    # No se utiliza el padding manual que se creo si no que se utilizara el padding de la libreria de Crypto.Util
    padded_plaintext = pad(plaintext, DES3.block_size)  

    ciphertext = cipher.encrypt(padded_plaintext)

    return ciphertext


def decrypt_3des_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """    
    Example:
        >>> key = generate_3des_key(2)
        >>> iv = generate_iv(8)
        >>> plaintext = b"Mensaje secreto"
        >>> ciphertext = encrypt_3des_cbc(plaintext, key, iv)
        >>> decrypted = decrypt_3des_cbc(ciphertext, key, iv)
        >>> decrypted == plaintext
        True
    """
    # TODO: Implementar
    # 1. Validar longitud de clave y IV
    # 2. Crear cipher: DES3.new(key, DES3.MODE_CBC, iv=iv)
    # 3. Descifrar
    # 4. Eliminar padding usando unpad() de Crypto.Util.Padding
    # 5. Retornar

    # 1. Solo verificar si la llave esta en 16 o 24 bytes de longitud
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be either 16 or 24 bytes long")

    # Tambien nos piden validar IV lo cual tiene que ser valido si y solo si tiene 8 bytes.
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes long for 3DES")

    # Para verificar que la llave tiene la misma longitud se debe de verificar los bits de paridad como se realiza con el de encriptar 
    key = DES3.adjust_key_parity(key)

    # 2. Creación del cypher
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)

    # 3. Con el mensaje que realizamos anteriormente utilizamos la desencripción por parte de la libreria  Crypto.Cypher
    padded_plaintext = cipher.decrypt(ciphertext)

    # 4. En caso de que hay padding quitamos esto para poder observar el mensaje lastimosamente no utilizamos los padding creados por mi :(
    plaintext = unpad(padded_plaintext, DES3.block_size)


    return plaintext


