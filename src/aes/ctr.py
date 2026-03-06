# Prompt utilizado Claude:
# Como se que es CTR y como se puede implementar, 

"""
╔══════════════════════════════════════════════════════════════════════╗
║        AES-256 – MODOS ECB, CBC y CTR: Implementación completa      ║
║                                                                      ║
║  Secciones:                                                          ║
║    1. Implementación completa CTR (cifrado / descifrado)             ║
║    2. Demostración: CTR no requiere padding                          ║
║    3. Benchmark rendimiento: 10 MB  →  CBC vs CTR                   ║
║    4. Análisis de paralelización                                     ║
║    5. Tabla comparativa final ECB / CBC / CTR                        ║
╚══════════════════════════════════════════════════════════════════════╝

Dependencia: pip install cryptography
"""

import os
import struct
import time
import threading
import statistics
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding


# ══════════════════════════════════════════════════════════════════════════════
#  UTILIDADES COMPARTIDAS
# ══════════════════════════════════════════════════════════════════════════════

BLOCK_SIZE = 16   # AES siempre trabaja con bloques de 128 bits = 16 bytes
KEY_SIZE   = 32   # AES-256 → clave de 256 bits = 32 bytes

SEPARADOR  = "═" * 68


def _pkcs7_pad(data: bytes) -> bytes:
    """Aplica padding PKCS#7 para que el mensaje sea múltiplo de 16 bytes."""
    padder = sym_padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    """Elimina el padding PKCS#7."""
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def _aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """
    Cifra un único bloque de 16 bytes con AES-ECB (primitiva interna).
    Esto es lo que CTR usa para generar cada bloque de keystream.
    """
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    e = c.encryptor()
    return e.update(block) + e.finalize()


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 1 – IMPLEMENTACIÓN COMPLETA: MODO CTR
# ══════════════════════════════════════════════════════════════════════════════
#
#  Cómo funciona CTR (Counter Mode):
#  ─────────────────────────────────
#  CTR convierte AES (cifrado de bloque) en un cifrado de flujo (stream cipher).
#
#  Para cada bloque i:
#    bloque_contador_i = nonce (8 bytes) ‖ contador_i (8 bytes, big-endian)
#    keystream_i       = AES_Cifrar( bloque_contador_i )
#    ciphertext_i      = plaintext_i  XOR  keystream_i
#
#  Propiedades clave:
#    • Cifrar == Descifrar  (XOR es su propia inversa)
#    • No necesita padding  (el último bloque puede ser parcial)
#    • Cada bloque es independiente  → paralelizable
#    • NUNCA reutilizar (clave, nonce)  → rompe la seguridad completamente

class AES_CTR:
    """
    AES-256 modo CTR implementado manualmente para mostrar cada paso.

    Uso:
        ctr = AES_CTR(key)
        ciphertext, nonce = ctr.cifrar(plaintext)
        plaintext         = ctr.descifrar(ciphertext, nonce)
    """

    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise ValueError(f"La clave debe ser {KEY_SIZE} bytes (AES-256)")
        self.key = key

    # ── Paso 1: construir el bloque contador ─────────────────────────────────
    def _bloque_contador(self, nonce: bytes, contador: int) -> bytes:
        """
        Empaqueta  nonce (8 bytes) + contador (8 bytes big-endian) = 16 bytes.
        
        Ejemplo para contador=3:
            nonce     = b'\\xAB\\xCD...' (8 bytes aleatorios)
            contador  = 0x0000000000000003
            resultado = nonce + b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x03'
        """
        return nonce + struct.pack(">Q", contador)

    # ── Paso 2: generar keystream y XOR ──────────────────────────────────────
    def cifrar(self, plaintext: bytes, nonce: bytes = None) -> tuple[bytes, bytes]:
        """
        Cifra plaintext de CUALQUIER longitud.  No agrega padding.
        Devuelve (ciphertext, nonce).
        """
        if nonce is None:
            nonce = os.urandom(8)       # 8 bytes nonce + 8 bytes contador = 16 bytes
        if len(nonce) != 8:
            raise ValueError("El nonce debe ser 8 bytes")

        ciphertext = bytearray()
        num_bloques = (len(plaintext) + BLOCK_SIZE - 1) // BLOCK_SIZE

        for i in range(num_bloques):
            # Construir bloque contador único para este índice
            bloque_ctr = self._bloque_contador(nonce, i)

            # Cifrar el bloque contador → genera 16 bytes de keystream pseudoaleatorio
            keystream = _aes_encrypt_block(self.key, bloque_ctr)

            # Extraer el trozo de plaintext correspondiente (puede ser < 16 en el último)
            trozo_pt = plaintext[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]

            # XOR byte a byte (si el trozo es menor que 16, zip se trunca correctamente)
            trozo_ct = bytes(p ^ k for p, k in zip(trozo_pt, keystream))
            ciphertext.extend(trozo_ct)

        return bytes(ciphertext), nonce

    def descifrar(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """
        Descifrar = exactamente la misma operación que cifrar.
        XOR(XOR(p, k), k) == p
        """
        plaintext, _ = self.cifrar(ciphertext, nonce)
        return plaintext

    # ── Variante paralela con hilos ───────────────────────────────────────────
    def cifrar_paralelo(self, plaintext: bytes, nonce: bytes = None,
                        num_hilos: int = 4) -> tuple[bytes, bytes]:
        """
        CTR paralelo: divide el plaintext en N partes, cada hilo
        cifra su parte de forma independiente (cada uno conoce su
        valor de contador inicial sin necesitar el resultado del hilo anterior).
        """
        if nonce is None:
            nonce = os.urandom(8)

        n        = len(plaintext)
        tam_chunk = (n + num_hilos - 1) // num_hilos
        chunks   = [plaintext[i * tam_chunk : (i + 1) * tam_chunk]
                    for i in range(num_hilos)]

        # Cada hilo i empieza en el contador (i * tam_chunk) // BLOCK_SIZE
        offsets_contador = [i * tam_chunk // BLOCK_SIZE for i in range(num_hilos)]

        resultados = [None] * num_hilos

        def worker(idx, datos, contador_inicio):
            buf = bytearray()
            for j in range(0, len(datos), BLOCK_SIZE):
                ctr_bloque = self._bloque_contador(nonce, contador_inicio + j // BLOCK_SIZE)
                keystream  = _aes_encrypt_block(self.key, ctr_bloque)
                trozo      = datos[j : j + BLOCK_SIZE]
                buf.extend(p ^ k for p, k in zip(trozo, keystream))
            resultados[idx] = bytes(buf)

        hilos = [threading.Thread(target=worker,
                                  args=(i, chunks[i], offsets_contador[i]))
                 for i in range(num_hilos)]
        for h in hilos: h.start()
        for h in hilos: h.join()

        return b"".join(r for r in resultados if r), nonce


# ══════════════════════════════════════════════════════════════════════════════
#  IMPLEMENTACIONES CBC y ECB (usando la librería nativa para benchmark justo)
# ══════════════════════════════════════════════════════════════════════════════

class AES_CBC:
    """AES-256 CBC usando la librería cryptography (con hardware AES-NI)."""

    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise ValueError("La clave debe ser 32 bytes (AES-256)")
        self.key = key

    def cifrar(self, plaintext: bytes) -> tuple[bytes, bytes]:
        iv     = os.urandom(BLOCK_SIZE)
        padded = _pkcs7_pad(plaintext)
        c      = Cipher(algorithms.AES(self.key), modes.CBC(iv),
                        backend=default_backend())
        e      = c.encryptor()
        return e.update(padded) + e.finalize(), iv

    def descifrar(self, ciphertext: bytes, iv: bytes) -> bytes:
        c = Cipher(algorithms.AES(self.key), modes.CBC(iv),
                   backend=default_backend())
        d = c.decryptor()
        return _pkcs7_unpad(d.update(ciphertext) + d.finalize())


class AES_ECB:
    """AES-256 ECB usando la librería cryptography."""

    def __init__(self, key: bytes):
        if len(key) != KEY_SIZE:
            raise ValueError("La clave debe ser 32 bytes (AES-256)")
        self.key = key

    def cifrar(self, plaintext: bytes) -> bytes:
        padded = _pkcs7_pad(plaintext)
        c      = Cipher(algorithms.AES(self.key), modes.ECB(),
                        backend=default_backend())
        e      = c.encryptor()
        return e.update(padded) + e.finalize()

    def descifrar(self, ciphertext: bytes) -> bytes:
        c = Cipher(algorithms.AES(self.key), modes.ECB(),
                   backend=default_backend())
        d = c.decryptor()
        return _pkcs7_unpad(d.update(ciphertext) + d.finalize())


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 2 – DEMO: CTR NO REQUIERE PADDING
# ══════════════════════════════════════════════════════════════════════════════

def demo_sin_padding():
    print(SEPARADOR)
    print("  SECCIÓN 2 – CTR no requiere padding")
    print(SEPARADOR)

    key = os.urandom(KEY_SIZE)
    ctr = AES_CTR(key)
    cbc = AES_CBC(key)

    casos = [
        (b"A" * 16,         "16 bytes  (bloque exacto)"),
        (b"B" * 17,         "17 bytes  (1 byte sobre bloque)"),
        (b"C" * 33,         "33 bytes  (2 bloques + 1 byte)"),
        (b"Hola Mundo!!!",  "13 bytes  (no múltiplo de 16)"),
        (b"X",              " 1 byte   (mínimo)"),
    ]

    print(f"\n  {'Descripción':<34} {'Entrada':>8}  {'CTR salida':>10}  "
          f"{'CBC salida':>10}  {'CTR == entrada?':>15}")
    print(f"  {'─'*34} {'─'*8}  {'─'*10}  {'─'*10}  {'─'*15}")

    for pt, desc in casos:
        ct_ctr, nonce = ctr.cifrar(pt)
        ct_cbc, _     = cbc.cifrar(pt)
        igual         = "✓ Sí" if len(ct_ctr) == len(pt) else "✗ No"
        print(f"  {desc:<34} {len(pt):>8}  {len(ct_ctr):>10}  {len(ct_cbc):>10}  {igual:>15}")

    # Verificar round-trip con longitud impar
    pt_impar = b"Cifrado sin padding: 31 bytes!!"
    assert len(pt_impar) == 31
    ct, nonce = ctr.cifrar(pt_impar)
    rt        = ctr.descifrar(ct, nonce)
    print(f"\n  Round-trip 31 bytes:  {'OK ✓' if rt == pt_impar else 'FALLO ✗'}")
    print(f"  Original  → {pt_impar}")
    print(f"  Descifrado→ {rt}")

    print("\n  Conclusión:")
    print("  ┌─ CTR genera un keystream del mismo tamaño que el plaintext.")
    print("  │  No hay bloques sobrantes, no hay padding que agregar.")
    print("  └─ CBC debe rellenar hasta el siguiente múltiplo de 16 (PKCS#7).")


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 3 – BENCHMARK: 10 MB  →  CBC vs CTR
# ══════════════════════════════════════════════════════════════════════════════

def benchmark_10mb():
    print("\n" + SEPARADOR)
    print("  SECCIÓN 3 – Benchmark rendimiento: archivo de 10 MB")
    print(SEPARADOR)

    key  = os.urandom(KEY_SIZE)
    data = os.urandom(10 * 1024 * 1024)   # 10 MB de datos aleatorios
    RUNS = 5

    # Usamos la librería nativa (con AES-NI de hardware) para CBC y CTR
    # para obtener tiempos reales de producción.
    cbc = AES_CBC(key)

    # CTR nativo (hardware-accelerated) para benchmark justo
    def _cifrar_ctr_nativo(d):
        nonce = os.urandom(BLOCK_SIZE)
        c = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        e = c.encryptor()
        return e.update(d) + e.finalize()

    def medir(fn, etiqueta):
        tiempos = []
        for _ in range(RUNS):
            t0 = time.perf_counter()
            fn()
            tiempos.append(time.perf_counter() - t0)
        avg = statistics.mean(tiempos)
        mb_s = 10 / avg
        med  = statistics.median(tiempos)
        print(f"  {etiqueta:<38}  {avg*1000:7.1f} ms  "
              f"(mediana {med*1000:.1f} ms)  {mb_s:6.0f} MB/s")
        return avg

    print(f"\n  Cifrado de 10 MB  –  {RUNS} ejecuciones\n")
    print(f"  {'Modo':<38}  {'Promedio':>10}   {'Mediana':>13}   {'Velocidad':>9}")
    print(f"  {'─'*38}  {'─'*10}   {'─'*13}   {'─'*9}")

    t_cbc = medir(lambda: cbc.cifrar(data),           "CBC  (serial  + PKCS#7 padding)")
    t_ctr = medir(lambda: _cifrar_ctr_nativo(data),   "CTR  (serial  sin padding)     ")

    ratio = t_cbc / t_ctr
    print(f"\n  → CTR es {ratio:.1f}x más rápido que CBC en este sistema.")
    print()
    print("  ¿Por qué CTR es más rápido?")
    print("  ┌─ 1. Sin overhead de padding (no calcula ni agrega bytes extra).")
    print("  │  2. Sin dependencia entre bloques → el pipeline del CPU no se detiene.")
    print("  │  3. El keystream puede pre-computarse antes de tener el plaintext.")
    print("  └─ 4. Mejor aprovechamiento de AES-NI (instrucciones hardware).")


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 4 – ANÁLISIS DE PARALELIZACIÓN
# ══════════════════════════════════════════════════════════════════════════════

def analisis_paralelizacion():
    print("\n" + SEPARADOR)
    print("  SECCIÓN 4 – Análisis de paralelización")
    print(SEPARADOR)

    print("""
  ┌──────────────────────────────────────────────────────────────┐
  │  CBC – CIFRADO  (dependencia en cadena → NO paralelizable)   │
  │                                                              │
  │  IV ──┐                                                      │
  │       ▼                                                      │
  │  P1 ─XOR─► AES ──► C1 ──┐                                   │
  │                           ▼                                  │
  │                    P2 ─XOR─► AES ──► C2 ──┐                 │
  │                                             ▼                │
  │                                    P3 ─XOR─► AES ──► C3     │
  │                                                              │
  │  Regla:  C[i] = AES( P[i] XOR C[i-1] )                      │
  │  Para cifrar P[i] NECESITAS C[i-1] → espera obligatoria.     │
  │  → Bloques 100% secuenciales. Un solo núcleo de CPU.         │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  CBC – DESCIFRADO  (parcialmente paralelizable)              │
  │                                                              │
  │  C1 ──► AES_Dec ──XOR── P1    (necesita IV, conocido)       │
  │  C2 ──► AES_Dec ──XOR── P2    (necesita C1, conocido)       │
  │  C3 ──► AES_Dec ──XOR── P3    (necesita C2, conocido)       │
  │                                                              │
  │  Regla:  P[i] = AES_Dec( C[i] ) XOR C[i-1]                  │
  │  Como todos los C[i] ya existen → sí se puede paralelizar.   │
  └──────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────┐
  │  CTR – CIFRADO/DESCIFRADO  (100% paralelizable)              │
  │                                                              │
  │  Hilo 1:  AES(nonce‖0) ─XOR─ P1 ──► C1  ┐                  │
  │  Hilo 2:  AES(nonce‖1) ─XOR─ P2 ──► C2  │ Todos al mismo   │
  │  Hilo 3:  AES(nonce‖2) ─XOR─ P3 ──► C3  │ tiempo           │
  │  Hilo 4:  AES(nonce‖3) ─XOR─ P4 ──► C4  ┘                  │
  │                                                              │
  │  Regla:  C[i] = AES( nonce ‖ i )  XOR  P[i]                 │
  │  Solo necesita el nonce (público) y el índice i.             │
  │  Ningún bloque depende del resultado de otro bloque.         │
  │  → Escala perfectamente con más núcleos / GPUs.              │
  └──────────────────────────────────────────────────────────────┘
""")

    # Prueba empírica: descifrar bloque 7 sin descifrar los bloques 0-6
    print("  Prueba empírica: acceso aleatorio a un bloque específico")
    print("  " + "─" * 50)
    key   = os.urandom(KEY_SIZE)
    ctr   = AES_CTR(key)
    data  = os.urandom(BLOCK_SIZE * 12)   # 12 bloques

    ct, nonce = ctr.cifrar(data)

    # Descifrar SOLO el bloque 7 directamente, sin tocar bloques 0-6
    bloque_objetivo = 7
    ctr_bloque  = ctr._bloque_contador(nonce, bloque_objetivo)
    keystream   = _aes_encrypt_block(key, ctr_bloque)
    ct_bloque7  = ct[bloque_objetivo * BLOCK_SIZE : (bloque_objetivo + 1) * BLOCK_SIZE]
    pt_bloque7  = bytes(c ^ k for c, k in zip(ct_bloque7, keystream))
    esperado    = data[bloque_objetivo * BLOCK_SIZE : (bloque_objetivo + 1) * BLOCK_SIZE]

    ok = pt_bloque7 == esperado
    print(f"  Descifrar bloque #7 directamente (sin bloques 0-6): {'OK ✓' if ok else 'FALLO ✗'}")
    print(f"  Bytes correctos: {sum(a==b for a,b in zip(pt_bloque7, esperado))}/16")
    print()
    print("  Implicación práctica:")
    print("  ┌─ Streaming de video cifrado: puedes saltar al minuto 45")
    print("  │  sin descifrar los 45 minutos anteriores.")
    print("  │  Con CBC esto es imposible; con CTR es trivial.")
    print("  └─ Recuperación de errores: un bit corrupto en CTR afecta")
    print("     solo 1 bloque. En CBC se propaga al siguiente bloque también.")


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIÓN 5 – TABLA COMPARATIVA FINAL
# ══════════════════════════════════════════════════════════════════════════════

def tabla_comparativa():
    print("\n" + SEPARADOR)
    print("  SECCIÓN 5 – Tabla comparativa: ECB vs CBC vs CTR")
    print(SEPARADOR)

    filas = [
        ("Propiedad",                  "ECB",           "CBC",             "CTR"),
        ("─" * 30,                     "─" * 12,        "─" * 14,          "─" * 14),
        ("Tipo de cifrado",            "Bloque",        "Bloque",          "Flujo (stream)"),
        ("Padding requerido",          "Sí (PKCS#7)",   "Sí (PKCS#7)",     "No ✓"),
        ("IV / Nonce",                 "No",            "Sí (IV 16B)",     "Sí (nonce 8B)"),
        ("Cifrado paralelizable",      "Sí",            "No ✗",            "Sí ✓"),
        ("Descifrado paralelizable",   "Sí",            "Sí (parcial)",    "Sí ✓"),
        ("Acceso aleatorio",           "Sí",            "No ✗",            "Sí ✓"),
        ("Patrones visibles",          "SÍ ✗✗✗",        "No ✓",            "No ✓"),
        ("Propagación de errores",     "1 bloque",      "2 bloques",       "1 bloque ✓"),
        ("Cifrado == Descifrado",      "No",            "No",              "Sí ✓"),
        ("Rendimiento relativo",       "1×",            "1×",              "~3× más rápido"),
        ("¿Usar en producción?",       "NUNCA ✗",       "Con cuidado ⚠",   "Sí (+ MAC) ✓"),
    ]

    for fila in filas:
        print(f"  {fila[0]:<30}  {fila[1]:<14}  {fila[2]:<16}  {fila[3]}")

    print()
    print("  Notas de seguridad:")
    print("  ┌─ ECB  → Nunca usar. Bloques iguales producen ciphertext igual.")
    print("  │         Revela patrones del mensaje original (ver 'ECB penguin').")
    print("  │")
    print("  │  CBC  → Seguro con IV aleatorio no predecible. Vulnerable a")
    print("  │         ataques de padding oracle si no se autentica el mensaje.")
    print("  │")
    print("  └─ CTR  → Seguro si el nonce es único por (clave, mensaje).")
    print("            Reutilizar nonce con la misma clave es catastrófico:")
    print("            C1 XOR C2 = P1 XOR P2  (el keystream se cancela).")
    print("            Siempre combinar con un MAC → usar AES-GCM en producción.")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN – ejecuta todas las secciones
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print(SEPARADOR)
    print("  AES-256 — ECB / CBC / CTR  — Análisis completo")
    print(SEPARADOR)

    # ── Sección 2: padding ────────────────────────────────────────────────────
    demo_sin_padding()

    # ── Sección 3: benchmark 10 MB ────────────────────────────────────────────
    benchmark_10mb()

    # ── Sección 4: paralelización ─────────────────────────────────────────────
    analisis_paralelizacion()

    # ── Sección 5: tabla final ────────────────────────────────────────────────
    tabla_comparativa()

    # ── Round-trip final de verificación ─────────────────────────────────────
    print("\n" + SEPARADOR)
    print("  Verificación round-trip de los tres modos")
    print(SEPARADOR)

    key = os.urandom(KEY_SIZE)
    msg = b"Mensaje de prueba con longitud no multiplo de 16: 53 bytes!!"
    assert len(msg) % 16 != 0   # confirmar que no es múltiplo de 16

    ctr = AES_CTR(key)
    cbc = AES_CBC(key)
    ecb = AES_ECB(key)

    ct_ctr, nonce = ctr.cifrar(msg)
    ct_cbc, iv    = cbc.cifrar(msg)
    ct_ecb        = ecb.cifrar(msg)

    rt_ctr = ctr.descifrar(ct_ctr, nonce)
    rt_cbc = cbc.descifrar(ct_cbc, iv)
    rt_ecb = ecb.descifrar(ct_ecb)

    print(f"\n  Mensaje original  ({len(msg)} bytes): {msg}")
    print(f"  CTR round-trip:  {'OK ✓' if rt_ctr == msg else 'FALLO ✗'}  "
          f"(ciphertext {len(ct_ctr)} bytes, sin padding)")
    print(f"  CBC round-trip:  {'OK ✓' if rt_cbc == msg else 'FALLO ✗'}  "
          f"(ciphertext {len(ct_cbc)} bytes, con padding → múltiplo de 16)")
    print(f"  ECB round-trip:  {'OK ✓' if rt_ecb == msg else 'FALLO ✗'}  "
          f"(ciphertext {len(ct_ecb)} bytes, con padding → múltiplo de 16)")
    print()