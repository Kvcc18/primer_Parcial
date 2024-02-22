
#Karla Vianey De la Cruz Cicler

import Crypto.Util.number
import hashlib

bits = 1024

#Primos de Alice
pA = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("primo de alice: ", pA, "\n")
qA = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("primo de alice: ", qA, "\n")

#Primos de Bob
pB = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("primo de Bob: ", pB, "\n")
qB = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
print("primo de bob: ", qB, "\n")

e = 65537

#primera parte de la llave pública de Alice
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
print("phiA: ", phiA, "\n")

#primera parte de la llave pública de Bob
nB = pB * qB
phiB = (pB - 1) * (qB - 1)
print("phiB: ", phiB, "\n")

#Calcular llave privada de Alice
dA = Crypto.Util.number.inverse(e, phiA)

#Calcular llave privada de bob
dB = Crypto.Util.number.inverse(e, phiB)

#Mensaje de 1050 caracteres
msg = "They say the sun a na shine for all But in some people world It never shine at all These roads of flames are catching a fire, ahh Showed you I loved you, and you called me a liar Oh, no, no, no, no, no Baby, tell me where you gone, gone, gone I've been fiendin' for your love so long We can praise Jah in the moonlight Baby, if you with me better do right And I've been gone too long And I'm hoping that you sing my songs (sing my songs) I've been on this road for way too long I've been hoping that we all get along These roads of flames are catching a fire, ahh Showed you I loved you, you called me a liar Give Jah the thanks and praises I've been on my own all along But we ain't never left alone, 'lone, 'lone And if I'm telling you the feeling is wrong Relax a little, friend, this won't take too long And when you're feeling alone You can call my phone Is there a better way to go? Teach them something before they lose their soul Oh, no, no, no freedom is the road Oh, no, no, no coming in from the cold Tell them not to sell it, it's worth more than gold And guiltiness."
print("Mensaje original: ", msg, "\n")
print("Longitud del mensaje en bytes: ", len(msg.encode('utf-8')))

#Convertir el mensaje a número
m = int.from_bytes(msg.encode('utf-8'), byteorder = 'big')
print("Mensaje convertido en entero: ", m, "\n")

#Dividir el mensaje en partes de 128 caracteres
mensajes_cifrados = []
for i in range(0, len(msg), 128):
    m_parte = msg[i:i+128]
    m = int.from_bytes(m_parte.encode('utf-8'), byteorder='big') 
    c = pow(m, e, nB)
    print(c, "\n")
    des = pow(c, dB, nB)
    print("Mensaje descifrado: ", des, "\n")
    m_parte_bytes = int.to_bytes(des, 128, byteorder='big') 
    m_parte_bytes = m_parte_bytes.lstrip(b'\x00')
    print(m_parte_bytes, "\n")
    
#Convertimos el mensaje de número a texto
msg_final = int.to_bytes(des, len(msg), byteorder = 'big').decode('utf-8')
print("Mensaje final: ", msg_final, "\n")

#Generar hash del mensaje
hash_object = hashlib.sha256(msg.encode())
hex_dig = hash_object.hexdigest()
print("Hash del mensaje: ", hex_dig, "\n")

#Convertir Hash a numero
m_int = int(hex_dig, 16)
print("Hash convertido en entero: ", m_int, "\n")

#ciframos hash con la clave privada de Alice
signature = pow(m_int, dA, nA)
print("Firma: ", signature, "\n")

#Bob recibe los mensajes y los descifra
decrypted = pow(signature, e, nA)
print("Mensaje descifrado: ", decrypted, "\n")

#Verificamos si el hash descifrado coincide con el hash original del mensaje
orginal_hash = hashlib.sha256(msg.encode()).hexdigest()
print("Hash original del mensaje: ", orginal_hash, "\n")

# Comparar hashes
if decrypted == m_int:
    print("El mensaje se descifró correctamente")
else:
    print("Error al descifrar el mensaje")

