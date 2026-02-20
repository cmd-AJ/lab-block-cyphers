"""
Generador de claves criptográficamente seguras.
"""
import secrets


def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    
    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.

    """
    llave_des = secrets.token_bytes(8)


    return llave_des


def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.   

    """

    if key_option == 1:
        # 2-key 3DES → 16 bytes
        return secrets.token_bytes(16)

    elif key_option == 2:
        # 3-key 3DES → 24 bytes
        return secrets.token_bytes(24)
    
    else:
        raise ValueError("debe de ser o 1 que se marca para el de 16 bytes y la otra opción como 24 bytes")



def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    
    """
    # TODO: Implementar
    # Convertir bits a bytes: key_size // 8

    # entonces tiene que er 128, 192 y 256 bits

    if key_size not in (128,192,256):
        raise ValueError("El keysize tiene que ser 128, 192 y 256")

    llaves_en_bits = key_size // 8

    return secrets.token_bytes(llaves_en_bits)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.

    """
    
    # TODO: Implementarlo

    # El bloque tiene un tamaño de la clave generada del DES / 3DES -> 8 bytes
    # Pero en el otro caso para AES es de 16 bytes


    # Se usa la libraria de secrets para generar IV aleatoriamente. 
    return secrets.token_bytes(block_size)

    # Tomar nota no reutilizar el mismo IV

