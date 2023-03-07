# RC4 en Python
import fileinput as fp

def KSA(key):
    """A partir de una clave dada genera una subclave de 256 bytes."""
    length = len(key)
    s = list(range(256))
    j = 0
    for i in range(0, 256):
        j = (j + s[i] + key[i % length]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def PRGA(s):
    """A partir de la permutación S de 256 bytes genera un stream pseudoaleatorio."""
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i] # Intercambia valores entre S[i] y S[j]
        K = s[(s[i] + s[j]) % 256]
        yield K # Generador a la salida conforme se necesiten bits para cifrar.

def RC4 (clave, textoplano):
    """Realiza el cifrado con RC4 de un mensaje en claro."""
    s = KSA(clave)
    flujoclave = PRGA(s)
    cifrado = bytes([p ^ next(flujoclave) for p in textoplano])
    return cifrado.hex().upper()

#Recuperando las entradas en una lista.
inputs = []

for entrada in fp.input():
    inputs.append(entrada.strip())

print(inputs)



# Transformamos todos a un flujo de bits hexadecimal. 
key1 = entrada[0].encode('utf-8')
print(key1)
key1 = bytes.fromhex(key1.hex().upper())
text1 = entrada[1].encode('utf-8')
text1 = bytes.fromhex(text1.hex().upper())

print(RC4(key1, text1))