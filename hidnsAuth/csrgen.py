from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ed25519,ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
# from getpass import getpass

def csrgen(pkpath = './private.key', outputpath = './', hashalgo=None):
    # Generate a CSR
    if hashalgo == 'sha1':
        _hashalgo = hashes.SHA1()
    elif hashalgo == 'sha224':
        _hashalgo = hashes.SHA224()
    elif hashalgo == 'sha256':
        _hashalgo = hashes.SHA256()
    elif hashalgo == 'sha384':
        _hashalgo = hashes.SHA384()
    else:
        _hashalgo = None
    
    with open(pkpath, 'rb') as f:
        pkraw = f.read()
    
    # passwd1 = getpass("please input private key access password:")
    # passwd2 = getpass("please input private key access password again:")
    # if passwd1 != passwd2:
    #     print('exit. bye~')
    #     return -1
    # key = load_pem_private_key(pkraw, password=passwd1.encode())
    key = load_pem_private_key(pkraw, password=None)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        _hashalgo = None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if _hashalgo != None:
            _hashalgo = ec.ECDSA(_hashalgo)
        else:
            if isinstance(key.curve, ec.SECP256R1):
                _hashalgo = hashes.SHA256()
            elif isinstance(key.curve, ec.SECP384R1):
                _hashalgo = hashes.SHA384()
            else:
                print("unsupport private key type: ", key.curve.name)

    prefix = input('your prefix [IMPORTANT]: ')
    country_name = input('2 character country code: ')
    state_or_province_name = input('state or province name: ')
    locality_name = input('locality name: ')
    organization_name = input('organization name: ')
    email_address = input('email address: ')

    confirm = input('is above all right? y or n: ')
    if confirm != 'y' and confirm != 'yes':
        print('exit. bye~')
        return -2

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
        x509.NameAttribute(NameOID.COMMON_NAME, prefix),
    ])).sign(key, _hashalgo)
    # Write our CSR out to disk.
    
    with open(outputpath + '/' + "csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    
    print("CSR create succeed:")
    print(csr.subject)

if __name__ == "__main__":
    pkpath = './private.key'
    outputpath = './'
    csrgen(pkpath, outputpath)