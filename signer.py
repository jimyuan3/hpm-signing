import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def importPrivateKey(privateKeyFile, passphrase=None):
    if passphrase:
        password = passphrase.encode()
    else:
        password = None

    with open(privateKeyFile, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )
    return private_key

# local RSA signature generation using private key from local file
class RSASigner:
    hashes = {
        'sha256': hashes.SHA256(),
        'sha512': hashes.SHA512(),
        'md5': hashes.MD5()
    }
    def __init__(self, keypath, passphrase=None, hash_algorithm='sha256'):
        self.private_key_file = importPrivateKey(keypath, passphrase)
        self.hash_algorithm = self.hashes[hash_algorithm]

    def sign(self, data):
        private_key = self.private_key_file

        # sign data
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            self.hash_algorithm
        )

        return signature
    
    def dosha(self, data, hash_algorithm):
        hasher = hashes.Hash(self.hash_algorithm, default_backend())
        hasher.update(data)
        return hasher.finalize()

    def verify(self, data, signature):
        public_key = self.private_key_file.public_key()
        public_key.verify(
            signature,
            data,
            padding=padding.PKCS1v15(),
            algorithm=self.hash_algorithm
        )
    
    def get_public_key(self):
        return self.private_key_file.public_key()
    
    def get_public_key_pem(self):
        return self.private_key_file.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_public_key_der(self):
        return self.private_key_file.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )