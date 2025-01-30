#generate RSA keys for software signing
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidKey
import logging

# configure logging
logging.basicConfig(filename='keys.log', level=logging.DEBUG)

try:
    # generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    print("Private key generated")
    logging.info("Private key generated")

    # generate public key
    public_key = private_key.public_key()
    print("Public key generated")  
    logging.info("Public key generated")        

except InvalidKey as e:  
    print("Invalid RSA key error: ", e)
    logging.error("Invalid RSA key error: ", e)

try:
    # serialize private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # serialize public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # write private key to file 
    with open('private_key.pem', 'wb') as f:
        f.write(private_key_pem)
        print("Private key written to file private_key.pem")
        logging.info("Private key written to file private_key.pem") 
    
    # write public key to file  
    with open('public_key.pem', 'wb') as f:
        f.write(public_key_pem)
        print("Public key written to file public_key.pem")
        logging.info("Public key written to file public_key.pem")

except:
    print("Unexpected error")
    logging.error("Unexpected error")

