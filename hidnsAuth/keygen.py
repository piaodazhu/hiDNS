from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
# from getpass import getpass

def keygen(outputpath='./', type='secp256r1'):
    if type == 'rsa':
        key = generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
    elif type == 'ed25519':
        key = Ed25519PrivateKey.generate()
    elif type == 'secp256r1':
        key = ec.generate_private_key(ec.SECP256R1())
    elif type == 'secp384r1':
        key = ec.generate_private_key(ec.SECP384R1())
    else:
        return
    # passwd1 = getpass("please input private key access password:")
    # passwd2 = getpass("please input private key access password again:")
    # if passwd1 != passwd2:
    #     return -1
    # Write our key to disk for safe keeping
    with open(outputpath + '/' + "private.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            # encryption_algorithm=serialization.BestAvailableEncryption(passwd2.encode()),
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(outputpath + '/' + "public.key", "wb") as f:
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

if __name__ == "__main__":
    outputpath = './'
    keygen(outputpath)