import nacl.public as public
import nacl.encoding
import nacl.exceptions

SIGNATURE_ENC = nacl.encoding.Base64Encoder
KEY_ENC = nacl.encoding.HexEncoder
STORE_ENC = nacl.encoding.HexEncoder


class CryptoCore(object):
    def __init__(self):
        """Load or initialize crypto keys."""
        try:
            with open("key", "rb") as keys_file:
                keys = keys_file.read()
        except IOError:
            keys = None
        if keys:
            self.pkey = public.PrivateKey(keys, STORE_ENC)
        else:
            kp = public.PrivateKey.generate()
            with open("key", "wb") as keys_file:
                keys_file.write(kp.encode(STORE_ENC))
            self.pkey = kp

    @property
    def public_key(self):
        return self.pkey.public_key.encode(KEY_ENC).decode("utf8").upper()

    def dsrep_decode_name(self, client, nonce, pl):
        box = public.Box(self.pkey, public.PublicKey(client))
        by = box.decrypt(pl, nonce)
        return by

    def dsrec_encrypt_key(self, client, nonce, msg):
        box = public.Box(self.pkey, public.PublicKey(client))
        by = box.encrypt(msg, nonce)
        return by[24:]
