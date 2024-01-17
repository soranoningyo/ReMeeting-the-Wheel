from random import randint
from Crypto.Util.number import getPrime, long_to_bytes as l2b
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import FLAG
from hashlib import sha256

class RSAGen:
    def __init__(self, bits):
        self.bits = bits
    
    def keygen(self):
        p = getPrime(self.bits//2)
        q = getPrime(self.bits//2)
        self.n = p*q
        self.e = 0x10001
        phi = (p-1)*(q-1)
        self.d = pow(self.e, -1, phi)
        return (self.n, self.e), (p, q, phi, self.d)

    def encrypt(self, m):
        return pow(m, self.e, self.n)
    
    def decrypt(self, c):
        return pow(c, self.d, self.n)

class AESGen:
    def __init__(self, size):
        key1 = randint(1 << size, 1 << (size+1))
        key2 = randint(1 << size, 1 << (size+1))
        self.k = key1 * key2
        assert 40 <= self.k.bit_length() <= 42
        self.KEY = sha256(str(self.k).encode()).digest()

    def encrypt(self, m):
        cipher = AES.new(self.KEY, AES.MODE_ECB)
        enc_secret = cipher.encrypt(pad(m, 16))
        return enc_secret

def main():
    rsa = RSAGen(1024)
    aes = AESGen(20)
    pubkey, _ = rsa.keygen()
    enc_aes_key = l2b(rsa.encrypt(aes.k))
    enc_secret = aes.encrypt(FLAG)

    with open('output.txt', 'w') as f:
        f.write("Bob :: Hi Alice, here is my public key:\n")
        f.write(f"({pubkey[0]}, {pubkey[1]})\n")
        f.write("Alice :: Hi Bob, here is my encrypted AES key, don't forget to sha256-hash it!\n")
        f.write(f"Encrypted AES Key = {enc_aes_key.hex()}\n")
        f.write("Bob :: Got it, here is the encrypted secret you requested:\n")
        f.write(f"Encrypted Secret = {enc_secret.hex()}")


if __name__ == '__main__':
    main()