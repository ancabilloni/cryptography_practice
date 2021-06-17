
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime


def create_private_key(key_name):
    # Generate our key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, )
    print(key)

    # Write our key to disk for safe keeping
    with open(key_name, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            ) )
    print("Create private key {}.".format(key_name))
    return key


def load_private_key(private_key_file, password=None):
    with open(private_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
        )
    return private_key

def load_public_key(public_key):
    # public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(pem)

def deserialization_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

def create_certificate_signing_request(private_key, country: str, state: str, city: str, company: str):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"{}".format(country)),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"{}".format(state)),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"{}".format(city)),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{}".format(company)),
            x509.NameAttribute(NameOID.COMMON_NAME, u""),
        ])).sign(private_key, hashes.SHA256())
    with open("./csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    return csr

def load_csr(csr_file):
    with open(csr_file, "rb") as csr_f:
        csr = x509.load_pem_x509_csr(csr_f.read())
    print(csr.subject)
    print(load_public_key(csr.public_key()))

def load_certificate(cert_file):
    with open(cert_file, "rb") as cert_f:
        cert = x509.load_pem_x509_certificate(cert_f.read())
    print(cert.subject)
    print(cert.serial_number)
    print(load_public_key(cert.public_key()))

def create_self_signed_certificate(load_key_file, country, state, city, company):
    if not load_key_file:
        key = create_private_key("ca_private_key.pem")
    else:
        key = load_private_key("ca_private_key.pem")
    
    subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"{}".format(country)),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"{}".format(state)),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"{}".format(city)),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"{}".format(company)),
            x509.NameAttribute(NameOID.COMMON_NAME, u""),
        ])

    cert = x509.CertificateBuilder().subject_name(
        subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(key, hashes.SHA256())

    with open("./ca_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Create CA certificate")


def sign_certificate_request(csr_cert, ca_cert, private_ca_key):
    cert = x509.CertificateBuilder().subject_name(
        csr_cert.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr_cert.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.utcnow() + timedelta(days=10)
    # Sign our certificate with our private key
    ).sign(private_ca_key, hashes.SHA256())

    with open("./signed_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Signed certificate")


def verify_signature():
    public_key.verify(signature,
                    message,
                    padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256())
        


fn = "./myca_private.key"
cert_file = "./ca_certificate.pem"
csr_file = "./csr.pem"
privKey = load_private_key(fn)
load_public_key(privKey.public_key())

# # Create root self-signed certificate
# create_self_signed_certificate(False, "US", "OHIO", "COLUMBUS", "SEA LTD")

# Load certificate
load_certificate(cert_file)

# deserialized_privKey = deserialization_private_key(privKey)
# csr = create_certificate_signing_request(privKey, "US", "OHIO", "COLUMBUS", "SEALTD")
# load_csr(csr_file)


