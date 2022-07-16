from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
# from getpass import getpass

def certsign(pkpath='./private.key', csrpath='./csr.pem', outputpath='./', hashalgo=None):

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
    # private_key = load_pem_private_key(pkraw, password=passwd1.encode())
    private_key = load_pem_private_key(pkraw, password=None)
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        _hashalgo = None

    with open(csrpath, 'rb') as f:
        pem_req_data = f.read()
        
    csr = x509.load_pem_x509_csr(pem_req_data)
    if not csr.is_signature_valid:
        print("invalid CSR.")
        return -3

    print("The certificate signing request subject information is below:")
    print(csr.subject)

    confirm = input('Are you sure to issue a certificate? y or n: ')
    if confirm != 'y' and confirm != 'yes':
        print('exit. bye~')
        return -2

    one_day = datetime.timedelta(1, 0, 0)

    prefix = input('issuer prefix [IMPORTANT]: ')
    organization_name = input('organization name: ')
    email_address = input('email address: ')

    confirm = input('is above all right? y or n: ')
    if confirm != 'y' and confirm != 'yes':
        print('exit. bye~')
        return -2

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name(csr.subject))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
        x509.NameAttribute(NameOID.COMMON_NAME, prefix),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(csr.public_key())
    # builder = builder.add_extension(
    #     csr.extensions[0],
    #     critical=False
    # )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=10), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=_hashalgo,
    )

    with open(outputpath + '/' + "cert.pem", 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
        # .replace(b'\r\n', b'').replace(b'\n', b''))
    print("certificate signing succeed:")
    print(certificate.issuer)
    print(certificate.subject)

if __name__ == "__main__":
    pkpath = './private.key'
    csrpath = './csr.pem'
    outputpath = './'
    certsign(pkpath, csrpath, outputpath)