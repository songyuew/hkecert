from datetime import datetime
import pwinput
import base64
from beautifultable import BeautifulTable
import inquirer
import OpenSSL
import warnings
from termcolor import colored
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

class internalError(Exception):
    pass

warnings.filterwarnings("ignore", category=DeprecationWarning) 

mainSel = [
  inquirer.List('main',
                message="Please select an option",
                choices=['Sign', 'Verify', 'Encrypt', 'Decrypt', 'Certificate', 'P12 PK', 'Exit'],
            ),
]

def writeSignature(sigStd, sigHex):
    sigFileNameStd = datetime.now().strftime("%d%m%y_%H%M%S") + "_std"
    sigFileNameHex = datetime.now().strftime("%d%m%y_%H%M%S") + "_hex"
    with open(f"{sigFileNameStd}.sig", 'wb') as f:
        f.write(sigStd)
    with open(f"{sigFileNameHex}.sig", 'w') as f:
        f.write(sigHex)

def writeCipher(cipher):
    encFileName = datetime.now().strftime("%d%m%y_%H%M%S")
    with open(f"{encFileName}.enc", 'wb') as f:
        f.write(cipher)

def sign(data,p12Path):
    print(f"Hex encoded message: 0x{data.hex()}")

    pk = loadP12(p12Path)[0]
    sigRaw = OpenSSL.crypto.sign(pk,data,"sha256")
    sigStd = base64.b64encode(sigRaw)
    sigHex = "0x" + sigRaw.hex()
    writeSignature(sigStd, sigHex)
    print(colored("Message successfully signed","green"))


def verify(data,sig_file,certPath):
    try:
        with open(sig_file, 'rb') as f:
            signature = base64.b64decode(f.read())

        cert = loadCert(certPath)

        OpenSSL.crypto.verify(cert, signature, data, 'sha256')
        print(colored("Signature verified OK","green"))
    except FileNotFoundError:
        print(colored("Signature file not found","red"))
        raise internalError
    except OpenSSL.crypto.Error:
        print(colored("Signature verification failed","red"))
        raise internalError

def loadP12(p12Path):
    pwd = pwinput.pwinput(prompt = 'Password: ').encode()
    try:
        with open(p12Path, "rb") as f:
            p12 = OpenSSL.crypto.load_pkcs12(f.read(), passphrase=pwd)
            pk = p12.get_privatekey()
            cert = p12.get_certificate()
    except FileNotFoundError:
        print(colored("P12 file not found","red"))
        raise internalError
    except KeyboardInterrupt:
        print(colored("User cancelled","red"))
        raise internalError
    except OpenSSL.crypto.Error:
        print(colored("Incorrect password or/and path","red"))
        raise internalError
    return [pk,cert]
        
def loadCert(certPath):
    try:
        with open(certPath, "rb") as f:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, f.read())
        
        return cert
    except FileNotFoundError:
        print(colored("Certificate file not found","red"))
        raise internalError
    except KeyboardInterrupt:
        print(colored("User cancelled","red"))
        raise internalError
    except OpenSSL.crypto.Error:
        print(colored("Unable to load certificate","red"))
        raise internalError

def X509ToDict(X509):
    dataList = "".join("/{:s}={:s}".format(name.decode(), value.decode()) for name, value in X509.get_components())[1:].split("/")
    dataDict = dict()
    for i in dataList:
        pair = i.split("=")
        dataDict[pair[0]] = pair[1]
    return dataDict

def groupHex(hexStr):
    temp = []
    for i in range(0,len(hexStr),2):
        if i != len(hexStr) - 1:
            temp.append(hexStr[i]+hexStr[i+1])
        else:
            temp.append(hexStr[i])
    return " ".join(temp)

def viewCert(certPath):
    cert = loadCert(certPath)
    issuerData = X509ToDict(cert.get_issuer())
    subjectData = X509ToDict(cert.get_subject())
    pubKey = cert.get_pubkey().to_cryptography_key()

    certInfo = BeautifulTable(maxwidth=100)
    certInfo.set_style(BeautifulTable.STYLE_RST)
    certInfo.rows.append([colored("Issued To","yellow"),""])
    certInfo.rows.append(["Common Name (CN)",subjectData.get("CN","N/A")])
    certInfo.rows.append(["Email (emailAddress)",subjectData.get("emailAddress","N/A")])
    certInfo.rows.append(["Organization (O)",subjectData.get("O","N/A")])
    certInfo.rows.append(["Organization Unit (OU)",subjectData.get("OU","N/A")])
    certInfo.rows.append(["Country/Region (C)",subjectData.get("C","N/A")])

    certInfo.rows.append([colored("Issued By","yellow"),""])
    certInfo.rows.append(["Common Name (CN)",issuerData.get("CN","N/A")])
    certInfo.rows.append(["Organization (O)",issuerData.get("O","N/A")])
    certInfo.rows.append(["Organization Unit (OU)",issuerData.get("OU","N/A")])
    certInfo.rows.append(["Country/Region (C)",issuerData.get("C","N/A")])
    
    certInfo.rows.append([colored("Certificate","yellow"),""])
    certInfo.rows.append(["Issued On",str(datetime.strptime(cert.get_notBefore().decode()[0:-1],'%Y%m%d%H%M%S'))])
    certInfo.rows.append(["Expires On",str(datetime.strptime(cert.get_notAfter().decode()[0:-1],'%Y%m%d%H%M%S'))])
    certInfo.rows.append(["Serial Number",groupHex(hex(cert.get_serial_number())[2:])])
    certInfo.rows.append(["Signature Algorithm",cert.get_signature_algorithm().decode()])

    print(certInfo)
    viewPK(pubKey)

def viewPK(pubKey):
    print(colored("Public Key","yellow"))
    print(colored("RSA Modulus (m)", "magenta"))
    print(hex(pubKey.public_numbers().n))
    print(colored("RSA Exponent (e)", "magenta"))
    print(hex(pubKey.public_numbers().e))
    print(colored("PEM Format", "magenta"))
    print(pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    )

def encrypt(msg,certPath):
    cert = loadCert(certPath)
    publicKeyCrypto = cert.get_pubkey().to_cryptography_key()
    ciphertext = base64.b64encode(publicKeyCrypto.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    writeCipher(ciphertext)
    print(colored("Message successfully encrypted","green"))

def pkFromP12(p12Path):
    pubKey = loadP12(p12Path)[1].get_pubkey().to_cryptography_key()
    viewPK(pubKey)

def decrypt(enc_file,p12Path):
    pk = loadP12(p12Path)[0].to_cryptography_key()
    try:
        with open(enc_file, 'rb') as f:
            cipher = base64.b64decode(f.read())
        plaintext = pk.decrypt(
            cipher,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(colored("Message successfully decrypted","green"))
        print("--------------------PLAINTEXT BEGIN--------------------")
        print(plaintext.decode())
        print("---------------------PLAINTEXT END---------------------")
    except FileNotFoundError:
        print(colored("Cipher file not found","red"))
        raise internalError
    except (OpenSSL.crypto.Error,ValueError):
        print(colored("Message decryption failed","red"))
        raise internalError

def main():
    try:
        print("Hong Kong Post e-Cert Utilities")
        while True:
            try:
                op = inquirer.prompt(mainSel)["main"]
                print(op)

                if op == "Sign":
                    msg = input("Message to sign: ").encode()
                    p12Path = input("P12 file path: ")
                    sign(msg,p12Path)
                    
                elif op == "Verify":
                    msg = input("Message to verify: ").encode()
                    sigFile = input("Signature path: ")
                    certPath = input("Sender's certificate path: ")
                    verify(msg,sigFile,certPath)

                elif op == "Encrypt":
                    msg = input("Message to encrypt: ").encode()
                    certPath = input("Certificate path: ")
                    encrypt(msg,certPath)

                elif op == "Decrypt":
                    encFile = input("Cipher file path: ")
                    p12Path = input("P12 file path: ")
                    decrypt(encFile,p12Path)

                elif op == "Certificate":
                    certPath = input("Certificate path: ")
                    viewCert(certPath)

                elif op == "P12 PK":
                    p12Path = input("P12 file path: ")
                    pkFromP12(p12Path)
                  
                elif op == "Exit":
                    print("Programme closed")
                    break
            except internalError:
                pass
            except KeyboardInterrupt:
                print()
                print(colored("To exit, press Ctrl+C again","yellow"))
                pass
    except TypeError:
        print()
        print("Programme closed")

main()
