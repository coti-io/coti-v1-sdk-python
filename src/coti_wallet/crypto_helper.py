from Crypto.Hash import keccak
import ecdsa
import binascii


def PadCRC(crc):
    crc1 = crc[2:]
    while len(crc1) < 8:
        crc1 = '0' + crc1
    return crc1


def PrivateKeyFromSeed(seed):
    keccakHash = keccak.new(digest_bits=256)
    keccakHash.update(seed)
    return keccakHash.hexdigest()


def PublicKeyFromPrivateKey(key):
    signinKey = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
    publicKey = signinKey.get_verifying_key()
    return binascii.hexlify(publicKey.to_string()).decode('utf-8'), PadCRC(hex(binascii.crc32(bytes(publicKey.to_string()))))


def HashAndSign(key, msg):
    keccakHash = keccak.new(digest_bits=256)
    keccakHash.update(msg)
    digest = keccakHash.digest()
    signinKey = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
    sig = signinKey.sign_digest(digest)
    signHEX = binascii.hexlify(sig).decode('utf-8')
    return (signHEX[:64], signHEX[64:]), binascii.hexlify(digest).decode('utf-8')


def SignDigest(key, digest):
    signinKey = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
    sig = signinKey.sign_digest(digest)
    signHEX = binascii.hexlify(sig).decode('utf-8')
    return signHEX[:64], signHEX[64:]


def HashKeccak256(msg):
    keccakHash = keccak.new(digest_bits=256)
    keccakHash.update(msg)
    digest = keccakHash.digest()
    return binascii.hexlify(digest).decode('utf-8')


def HashKeccak224(msg):
    keccakHash = keccak.new(digest_bits=224)
    keccakHash.update(msg)
    digest = keccakHash.digest()
    return binascii.hexlify(digest).decode('utf-8')


def VerifyWithPrivateKey(key, msg, sign):
    keccakHash = keccak.new(digest_bits=256)
    keccakHash.update(msg)
    digest = keccakHash.digest()
    signinKey = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
    verifyingKey = signinKey.get_verifying_key()
    return verifyingKey.verify_digest(sign, digest)


def VerifyWithPublicKey(key, msg, sign):
    keccakHash = keccak.new(digest_bits=256)
    keccakHash.update(msg)
    digest = keccakHash.digest()
    verifyingKey = ecdsa.VerifyingKey.from_string(key, curve=ecdsa.SECP256k1)
    return verifyingKey.verify_digest(sign, digest)


def VerifyHashWithPublicKey(key, digest, sign):
    verifyingKey = ecdsa.VerifyingKey.from_string(key, curve=ecdsa.SECP256k1)
    return verifyingKey.verify_digest(sign, digest)


def KeyAndAddressFromSeed(seed, index):
    priv = PrivateKeyFromSeed(seed)
    userpk, _ = PublicKeyFromPrivateKey(bytearray.fromhex(priv))
    address_private = HashKeccak256(seed + index.to_bytes(4, byteorder='big'))
    address_publicKey, crc = PublicKeyFromPrivateKey(bytearray.fromhex(address_private))
    return userpk, address_publicKey, address_publicKey + crc, address_private


def KeyAndAddressFromSeed2(seed, index):
    priv = PrivateKeyFromSeed(seed)
    userpk, _ = PublicKeyFromPrivateKey(bytearray.fromhex(priv))
    keyForAddress = HashKeccak256(seed + index.to_bytes(4, byteorder='big'))
    publicKey, crc = PublicKeyFromPrivateKey(bytearray.fromhex(keyForAddress))
    return publicKey, crc


def KeyForIndexFromSeed(seed, address):
    index = 0
    publicKey = ""
    while address != publicKey:
        keyForAddress = HashKeccak256(seed + index.to_bytes(4, byteorder='big'))
        publicKey, _ = PublicKeyFromPrivateKey(bytearray.fromhex(keyForAddress))
        index += 1
        if index > 1000:
            return
    return keyForAddress, index
