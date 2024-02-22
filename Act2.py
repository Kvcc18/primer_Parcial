import Crypto.Util.number
import hashlib

bits = 1024
archivo_contrato = "NDA.pdf"
e = 65537

#Mensaje 
msg = "firmada por Alice"
print("Mensaje original: ", msg, "\n")
print("Longitud del mensaje en bytes: ", len(msg.encode('utf-8')))

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

#primera parte de la llave pública de Alice
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
print("Llave publica de Alice: ", phiA, "\n")

#primera parte de la llave pública de Bob
nB = pB * qB
phiB = (pB - 1) * (qB - 1)
print("phiB: ", phiB, "\n")

#Calcular llave privada Alice
dA = Crypto.Util.number.inverse(e, phiA)

#Calcular llave privada de bob
dB = Crypto.Util.number.inverse(e, phiB)

#Hash del contrato
hash_contrato = hashlib.sha256(open(archivo_contrato, "rb").read())
hex_dig = hash_contrato.hexdigest()
print("Hash del Contrato: ", hex_dig, "\n")

#Convertir hash a numero
m = int(hex_dig, 16)
print("Hash convertido a entero: ", m, "\n")

#Cifrando hash con la clave privada de Alice
signature = pow(m, dA, nA)
print("Firma: ", signature, "\n")

#Decifrar firma
decrypted_signature = pow(signature, e, nA)
print("firma descifrada: ", decrypted_signature, "\n")

from PyPDF2 import PdfWriter, PdfReader, PageObject
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# Abrir el archivo PDF original
reader = PdfReader(archivo_contrato)

# Crear un nuevo escritor de PDF
writer = PdfWriter()

# Agregar las páginas del PDF original al nuevo escritor
for page in reader.pages:
    writer.add_page(page)

# Guardar el nuevo PDF firmado
with open("NDA.pdf", "wb") as f:
    writer.write(f)
    c = canvas.Canvas("NDA_firma.pdf", pagesize=letter)
    c.drawString(50,50, str(decrypted_signature))
    c.save()

# Comparar el hash del documento con el resultado de la verificación
if decrypted_signature == m:
    print("La firma es válida.")
else:
    print("La firma es inválida.")

