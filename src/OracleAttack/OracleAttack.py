"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           PADDING ORACLE ATTACK — Demostración Completa                     ║
║                                                                              ║
║  Secciones:                                                                  ║
║    1. Servidor vulnerable (oráculo de padding)                               ║
║    2. El ataque byte a byte explicado paso a paso                            ║
║    3. Ataque completo: descifrar ciphertext sin la clave                     ║
║    4. Estadísticas del ataque                                                ║
║    5. Contramedidas                                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

CONCEPTO FUNDAMENTAL:
─────────────────────
  Un Padding Oracle Attack explota un servidor que revela si el padding
  de un mensaje descifrado es válido o no.

  Con solo esa respuesta binaria (padding OK / padding INVÁLIDO) un atacante
  puede descifrar CUALQUIER ciphertext bloque a bloque, sin conocer la clave.

  Fue demostrado por Serge Vaudenay en 2002 y explotado masivamente en
  ataques reales: POODLE (SSL 3.0), BEAST, Lucky13, ASP.NET padding oracle.

PKCS#7 PADDING (recordatorio):
───────────────────────────────
  Si faltan N bytes para completar un bloque de 16, se agregan N bytes
  con valor N.

  Ejemplos:
    "HOLA"  (4 bytes)  → "HOLA" + b'\\x0c' * 12
    "ABCDEFGHIJKLMNO"  (15 bytes) → ... + b'\\x01'
    bloque completo    (16 bytes) → + b'\\x10' * 16  (bloque extra de padding)

  Padding INVÁLIDO (lanza excepción):
    ...\\x03\\x03\\x04   ← último byte debería ser \\x03, no \\x04
"""

import os
import time
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

BLOCK  = 16
SEP    = "═" * 70


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 1 — EL SERVIDOR VULNERABLE (el "Oráculo")
# ══════════════════════════════════════════════════════════════════════════════

class ServidorVulnerable:
    """
    Simula un servidor web vulnerable que:
      1. Cifra cookies/tokens en AES-CBC (función legítima)
      2. Al recibir datos cifrados, REVELA si el padding es válido
         → esto es el error fatal que crea el oráculo

    En la vida real el "oráculo" puede ser:
      - Un mensaje de error HTTP diferente (400 vs 500)
      - Una diferencia en el tiempo de respuesta
      - Un campo de error en una respuesta JSON
    """

    def __init__(self):
        self.clave      = os.urandom(32)    # AES-256 secreta (el atacante NO la conoce)
        self.consultas  = 0                 # contador de llamadas al oráculo

    # ── Operaciones legítimas del servidor ───────────────────────────────────

    def cifrar_token(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """El servidor cifra datos del usuario y se los devuelve como cookie."""
        iv     = os.urandom(BLOCK)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()

        c = Cipher(algorithms.AES(self.clave), modes.CBC(iv),
                   backend=default_backend())
        e = c.encryptor()
        ct = e.update(padded) + e.finalize()
        return ct, iv

    def descifrar_interno(self, ciphertext: bytes, iv: bytes) -> bytes:
        """Descifrado interno del servidor (no expuesto directamente)."""
        c = Cipher(algorithms.AES(self.clave), modes.CBC(iv),
                   backend=default_backend())
        d = c.decryptor()
        return d.update(ciphertext) + d.finalize()

    # ── La vulnerabilidad: el oráculo ─────────────────────────────────────────

    def verificar_padding(self, ciphertext: bytes, iv: bytes) -> bool:
        """
        ★ ESTA ES LA FUNCIÓN VULNERABLE ★

        El servidor intenta descifrar y verifica el padding.
        Devuelve True/False según si el padding es válido.

        Esto parece inofensivo, pero permite al atacante descifrar
        cualquier mensaje sin conocer la clave.
        """
        self.consultas += 1
        try:
            raw = self.descifrar_interno(ciphertext, iv)
            # Verificar padding PKCS#7 manualmente
            pad_byte = raw[-1]
            if pad_byte == 0 or pad_byte > BLOCK:
                return False
            padding = raw[-pad_byte:]
            return all(b == pad_byte for b in padding)
        except Exception:
            return False


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 2 — LA MATEMÁTICA DEL ATAQUE
# ══════════════════════════════════════════════════════════════════════════════

def explicar_matematica():
    print(SEP)
    print("  SECCIÓN 2 — Matemática del ataque (un solo byte)")
    print(SEP)
    print("""
  CBC DESCIFRADO — fórmula:
  ─────────────────────────
    P[i] = AES_Dec( C[i] )  XOR  C[i-1]

  Donde:
    P[i]   = bloque de plaintext i
    C[i]   = bloque de ciphertext i
    C[i-1] = bloque de ciphertext anterior (o IV para el primer bloque)

  ┌─────────────────────────────────────────────────────────────────┐
  │  ATAQUE AL ÚLTIMO BYTE DEL BLOQUE                               │
  │                                                                 │
  │  Meta: descubrir P[i][15]  (último byte del bloque i)           │
  │                                                                 │
  │  1. Tomamos C[i-1] (bloque anterior, conocido)                  │
  │  2. Construimos C'[i-1] = C[i-1] con el último byte modificado: │
  │       C'[i-1][15] = X  (probamos X = 0..255)                    │
  │                                                                 │
  │  3. Enviamos (C'[i-1], C[i]) al oráculo                         │
  │  4. El oráculo descifra:                                        │
  │       P'[i][15] = AES_Dec(C[i])[15]  XOR  X                    │
  │                                                                 │
  │  5. Cuando el oráculo dice "padding OK" con padding=\\x01:       │
  │       P'[i][15] = \\x01                                         │
  │       → AES_Dec(C[i])[15]  XOR  X  = \\x01                     │
  │       → AES_Dec(C[i])[15]          = X  XOR  \\x01             │
  │                                                                 │
  │  6. El byte real del plaintext es:                              │
  │       P[i][15] = AES_Dec(C[i])[15]  XOR  C[i-1][15]           │
  │               = (X XOR \\x01)        XOR  C[i-1][15]           │
  │                                                                 │
  │  → Hemos descubierto P[i][15] con máximo 256 consultas.         │
  │  → Repetimos para cada byte, de derecha a izquierda.            │
  └─────────────────────────────────────────────────────────────────┘

  Para el byte en posición j (de atrás hacia adelante, j=1..16):
    • Padding objetivo = \\x0j  (valor del padding que queremos forzar)
    • Ya conocemos los últimos j-1 bytes intermedios → ajustamos C'
    • Probamos el byte j hasta que el oráculo confirme padding válido
    • Despejamos el byte intermedio y luego el byte real de plaintext
""")


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 3 — EL ATAQUE COMPLETO
# ══════════════════════════════════════════════════════════════════════════════

def ataque_padding_oracle(servidor: ServidorVulnerable,
                          ciphertext: bytes,
                          iv: bytes,
                          verbose: bool = True) -> bytes:
    """
    Descifra `ciphertext` byte a byte usando solo el oráculo de padding.
    No usa la clave en ningún momento.

    Algoritmo:
      Para cada bloque i (de izquierda a derecha):
        Para cada byte j (de derecha a izquierda, j = 15..0):
          1. Construir bloque modificado C' con bytes ya conocidos ajustados
          2. Probar valores 0..255 para el byte j de C'
          3. Cuando el oráculo dice OK → calcular byte intermedio
          4. Byte real = byte_intermedio XOR bloque_anterior[j]
    """

    bloques_ct = [ciphertext[i:i+BLOCK] for i in range(0, len(ciphertext), BLOCK)]
    bloques_prev = [iv] + bloques_ct[:-1]   # IV + bloques C[0..n-2]

    plaintext_total = bytearray()
    inicio_total    = time.perf_counter()

    for num_bloque, (bloque_ct, bloque_prev) in enumerate(
            zip(bloques_ct, bloques_prev)):

        if verbose:
            print(f"\n  {'─'*68}")
            print(f"  Atacando bloque {num_bloque + 1}/{len(bloques_ct)}")
            print(f"  {'─'*68}")

        # bytes_intermedios[j] = AES_Dec(C[i])[j]  (sin XOR con bloque anterior)
        bytes_intermedios = bytearray(BLOCK)
        plaintext_bloque  = bytearray(BLOCK)

        for pos in range(BLOCK - 1, -1, -1):
            # padding_objetivo: valor de padding que queremos forzar
            # Si pos=15 → queremos \\x01
            # Si pos=14 → queremos \\x02 \\x02
            # ...
            padding_objetivo = BLOCK - pos   # 1, 2, 3, ..., 16

            # Construir IV modificado: ajustar bytes ya conocidos a la derecha
            iv_mod = bytearray(bloque_prev)
            for k in range(pos + 1, BLOCK):
                # Para que los bytes ya descifrados produzcan padding_objetivo
                iv_mod[k] = bytes_intermedios[k] ^ padding_objetivo

            # Probar todos los valores posibles para el byte en `pos`
            encontrado = False
            for intento in range(256):
                iv_mod[pos] = intento
                if servidor.verificar_padding(bytes(bloque_ct), bytes(iv_mod)):
                    # Verificación extra: asegurarse de que es \\x01 y no \\x02\\x02
                    # cambiando el byte anterior si existe
                    if pos > 0:
                        iv_mod2    = bytearray(iv_mod)
                        iv_mod2[pos - 1] ^= 1
                        if not servidor.verificar_padding(bytes(bloque_ct), bytes(iv_mod2)):
                            continue   # falso positivo, seguir buscando
                    # Byte intermedio: iv_mod[pos] XOR padding_objetivo
                    byte_intermedio       = intento ^ padding_objetivo
                    bytes_intermedios[pos] = byte_intermedio
                    # Byte real de plaintext
                    byte_real             = byte_intermedio ^ bloque_prev[pos]
                    plaintext_bloque[pos] = byte_real
                    encontrado            = True

                    if verbose:
                        car = chr(byte_real) if 32 <= byte_real < 127 else f"\\x{byte_real:02x}"
                        print(f"    pos[{pos:02d}]  intento=0x{intento:02x}  "
                              f"intermedio=0x{byte_intermedio:02x}  "
                              f"plaintext=0x{byte_real:02x} '{car}'")
                    break

            if not encontrado:
                if verbose:
                    print(f"    pos[{pos:02d}]  !! No encontrado (error)")
                plaintext_bloque[pos] = 0

        plaintext_total.extend(plaintext_bloque)

    # Quitar padding PKCS#7
    pad_byte = plaintext_total[-1]
    if 1 <= pad_byte <= BLOCK:
        plaintext_sin_pad = plaintext_total[:-pad_byte]
    else:
        plaintext_sin_pad = plaintext_total

    if verbose:
        elapsed = time.perf_counter() - inicio_total
        print(f"\n  {'─'*68}")
        print(f"  Ataque completado en {elapsed:.2f}s")
        print(f"  Consultas al oráculo: {servidor.consultas}")
        print(f"  Promedio por byte: {servidor.consultas / len(ciphertext):.1f} consultas")

    return bytes(plaintext_sin_pad)


# ══════════════════════════════════════════════════════════════════════════════
#  DEMO PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def demo_completa():
    print()
    print(SEP)
    print("  PADDING ORACLE ATTACK — Demostración Completa")
    print(SEP)

    # ── Setup ─────────────────────────────────────────────────────────────────
    servidor = ServidorVulnerable()

    # Mensaje secreto que el servidor cifró (el atacante ve el ciphertext pero no el plaintext)
    mensaje_secreto = b"usuario=admin;rol=superusuario;exp=9999999999"

    print(f"\n  [Servidor] Cifrando token secreto...")
    print(f"  [Servidor] Plaintext  : {mensaje_secreto}")
    ct, iv = servidor.cifrar_token(mensaje_secreto)
    print(f"  [Servidor] Ciphertext : {ct.hex()}")
    print(f"  [Servidor] IV         : {iv.hex()}")
    print(f"  [Servidor] Bloques    : {len(ct) // BLOCK}")
    print(f"\n  [Atacante] Solo conoce el ciphertext y el IV.")
    print(f"  [Atacante] NO conoce la clave.")
    print(f"  [Atacante] Iniciando ataque...\n")

    # ── Explicación matemática ─────────────────────────────────────────────────
    explicar_matematica()

    # ── El ataque ─────────────────────────────────────────────────────────────
    print(SEP)
    print("  SECCIÓN 3 — Ataque byte a byte")
    print(SEP)

    servidor.consultas = 0   # reset contador
    resultado = ataque_padding_oracle(servidor, ct, iv, verbose=True)

    # ── Verificación ──────────────────────────────────────────────────────────
    print()
    print(SEP)
    print("  SECCIÓN 4 — Resultados y estadísticas")
    print(SEP)
    exito = resultado == mensaje_secreto
    print(f"\n  Plaintext original : {mensaje_secreto}")
    print(f"  Plaintext atacado  : {resultado}")
    print(f"  Ataque exitoso     : {'SÍ ✓' if exito else 'NO ✗'}")
    print(f"\n  Estadísticas:")
    print(f"  ┌─ Bytes a descifrar       : {len(ct)}")
    print(f"  │  Consultas al oráculo    : {servidor.consultas}")
    print(f"  │  Consultas por byte      : {servidor.consultas / len(ct):.1f}  (máx teórico: 256)")
    print(f"  │  Bloques CBC             : {len(ct) // BLOCK}")
    print(f"  └─ Complejidad             : O(256 × n_bytes) vs O(2^256) fuerza bruta")

    print(f"""
  Comparativa de complejidad:
  ┌──────────────────────────────────┬─────────────────────────────┐
  │  Método                          │  Consultas / operaciones    │
  ├──────────────────────────────────┼─────────────────────────────┤
  │  Fuerza bruta AES-256            │  2^256  ≈ 10^77             │
  │  Padding Oracle (este ataque)    │  256 × {len(ct)} = {256*len(ct):<8} (real: {servidor.consultas})│
  └──────────────────────────────────┴─────────────────────────────┘
""")

    # ── Contramedidas ─────────────────────────────────────────────────────────
    print(SEP)
    print("  SECCIÓN 5 — Contramedidas")
    print(SEP)
    print("""
  El ataque funciona porque el servidor revela información sobre el padding.
  Para eliminarlo completamente:

  ┌─────────────────────────────────────────────────────────────────────┐
  │  CONTRAMEDIDA 1 (RECOMENDADA): Usar AES-GCM en lugar de AES-CBC     │
  │                                                                     │
  │  GCM = Galois/Counter Mode                                          │
  │  • Autenticado: incluye un tag HMAC que verifica integridad         │
  │  • Si el tag no coincide → rechazar SIN descifrar                   │
  │  • El atacante nunca llega a ver errores de padding                 │
  │  • Es el estándar moderno (TLS 1.3, JWT, etc.)                      │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  CONTRAMEDIDA 2: Encrypt-then-MAC (si se debe usar CBC)             │
  │                                                                     │
  │  1. Cifrar con AES-CBC                                              │
  │  2. Calcular HMAC-SHA256 del ciphertext                             │
  │  3. Verificar el HMAC ANTES de intentar descifrar                   │
  │  → Si HMAC falla, rechazar sin revelar nada sobre el padding        │
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  CONTRAMEDIDA 3: Respuestas indistinguibles (parche mínimo)         │
  │                                                                     │
  │  • Devolver SIEMPRE el mismo mensaje de error                       │
  │  • Mismo tiempo de respuesta (comparación en tiempo constante)      │
  │  • Nunca revelar si el error fue "padding" vs "autenticación"        │
  │  ⚠ Esto mitiga pero NO elimina el ataque — usar GCM es mejor        │
  └─────────────────────────────────────────────────────────────────────┘
""")

    demo_aes_gcm_seguro(mensaje_secreto)


def demo_aes_gcm_seguro(mensaje: bytes):
    """Muestra la contramedida correcta: AES-GCM."""
    print(SEP)
    print("  BONUS — Implementación segura con AES-GCM")
    print(SEP)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    clave_gcm = os.urandom(32)
    nonce_gcm = os.urandom(12)   # GCM usa nonce de 12 bytes
    aesgcm    = AESGCM(clave_gcm)

    # Cifrar
    ct_gcm = aesgcm.encrypt(nonce_gcm, mensaje, None)
    print(f"\n  [GCM] Ciphertext  : {ct_gcm.hex()}")
    print(f"  [GCM] Nonce       : {nonce_gcm.hex()}")
    print(f"  [GCM] Tag incluido: últimos 16 bytes = {ct_gcm[-16:].hex()}")

    # Intentar atacar con un byte modificado
    ct_tampered = bytearray(ct_gcm)
    ct_tampered[0] ^= 0xFF   # modificar un byte
    try:
        aesgcm.decrypt(nonce_gcm, bytes(ct_tampered), None)
        print("  [GCM] Ataque: ¡descifró! (esto NO debería pasar)")
    except Exception:
        print("  [GCM] Ataque bloqueado: tag inválido → mensaje rechazado ✓")
        print("  [GCM] El atacante no recibe ninguna información sobre el contenido.")

    # Descifrado legítimo
    pt_gcm = aesgcm.decrypt(nonce_gcm, ct_gcm, None)
    print(f"  [GCM] Descifrado  : {pt_gcm}")
    print(f"  [GCM] Correcto    : {'✓' if pt_gcm == mensaje else '✗'}")
    print(f"""
  ¿Por qué GCM es inmune al Padding Oracle?
  ┌─ GCM no usa padding → no hay bytes de padding que explotar.
  │  GCM verifica el tag de autenticación ANTES de descifrar.
  │  Un ciphertext modificado produce tag inválido → rechazo inmediato.
  └─ El atacante no puede distinguir entre "padding malo" y "tag malo".
""")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    demo_completa()