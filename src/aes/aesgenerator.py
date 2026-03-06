from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import struct

BLOCK_SIZE = 16
KEY_SIZE = 32



def encrypt_image(input_path: str, output_path: str, key: bytes, mode: str):
    """
    Encrypt an image using AES-256 ECB or CBC.

    Output MUST be saved as .bmp so pixel bytes are stored raw
    (no re-compression that would corrupt the ciphertext).

    ECB result: structural outlines visible   ← expected, shows ECB weakness
    CBC result: looks like random colour noise ← expected, secure
    """
    if len(key) != KEY_SIZE:
        raise ValueError("Key must be 32 bytes (AES-256)")

    if not output_path.lower().endswith(".bmp"):
        raise ValueError(
            "Output must be a .bmp file.\n"
            "PNG and JPEG re-compress pixel data which corrupts the ciphertext."
        )

    img = Image.open(input_path).convert("RGB")
    img_array = np.array(img)
    original_shape = img_array.shape

    pixel_bytes = img_array.tobytes()
    padded_pixels = pad(pixel_bytes, BLOCK_SIZE)

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        iv = None
    elif mode == "CBC":
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        print(f"CBC IV: {iv.hex()}")
    else:
        raise ValueError("Mode must be 'ECB' or 'CBC'")

    encrypted_pixels = cipher.encrypt(padded_pixels)

    # Trim back to original pixel byte length for reshaping
    encrypted_pixels = encrypted_pixels[:len(pixel_bytes)]

    encrypted_array = np.frombuffer(encrypted_pixels, dtype=np.uint8).reshape(original_shape)
    Image.fromarray(encrypted_array).save(output_path)  # .bmp → raw, no compression

    print(f"{mode} encrypted image saved → {output_path}")
    return iv  # return IV so caller can use it for decryption


def decrypt_image(input_path: str, output_path: str, key: bytes, mode: str, iv: bytes = None):
    """
    Decrypt an AES-256 encrypted BMP image.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("Key must be 32 bytes (AES-256)")

    img = Image.open(input_path).convert("RGB")
    img_array = np.array(img)
    original_shape = img_array.shape

    pixel_bytes = img_array.tobytes()
    padded_pixels = pad(pixel_bytes, BLOCK_SIZE)  # re-pad to match encrypt side

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV required for CBC decryption")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Mode must be 'ECB' or 'CBC'")

    decrypted_pixels = cipher.decrypt(padded_pixels)
    decrypted_pixels = decrypted_pixels[:len(pixel_bytes)]

    decrypted_array = np.frombuffer(decrypted_pixels, dtype=np.uint8).reshape(original_shape)
    Image.fromarray(decrypted_array).save(output_path)
    print(f"{mode} decrypted image saved → {output_path}")


def encrypt_text(plaintext: str, key: bytes, mode: str):
    """
    Encrypt text using AES-256 ECB or CBC.
    Returns (ciphertext, iv).  iv is None for ECB.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("Key must be 32 bytes (AES-256)")

    padded = pad(plaintext.encode("utf-8"), BLOCK_SIZE)

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(padded), None

    elif mode == "CBC":
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(padded), iv

    raise ValueError("Mode must be 'ECB' or 'CBC'")


def decrypt_text(ciphertext: bytes, key: bytes, mode: str, iv: bytes = None) -> str:
    """
    Decrypt AES-256 ECB or CBC ciphertext back to a string.
    """
    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("IV required for CBC decryption")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Mode must be 'ECB' or 'CBC'")

    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE).decode("utf-8")


if __name__ == "__main__":
    key = get_random_bytes(32)

    encrypt_image("input.png", "encrypted_ecb.bmp", key, "ECB")
    iv = encrypt_image("input.png", "encrypted_cbc.bmp", key, "CBC")

    decrypt_image("encrypted_ecb.bmp", "decrypted_ecb.bmp", key, "ECB")
    decrypt_image("encrypted_cbc.bmp", "decrypted_cbc.bmp", key, "CBC", iv=iv)

    msg = "Hello! This is a secret message. Hello! This is a secret message."
    print("\n── TEXT DEMO ──")
    print("Original :", msg)

    ct_ecb, _      = encrypt_text(msg, key, "ECB")
    ct_cbc, iv_cbc = encrypt_text(msg, key, "CBC")

    print("ECB cipher (hex):", ct_ecb.hex())
    print("CBC cipher (hex):", ct_cbc.hex())


    print("ECB decrypted:", decrypt_text(ct_ecb, key, "ECB"))
    print("CBC decrypted:", decrypt_text(ct_cbc, key, "CBC", iv=iv_cbc))