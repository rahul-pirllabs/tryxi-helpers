from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

from aes_enc_dec.helpers.salt_helpers import generate_secret_key


def aes256_cbc_encrypt(data: str, password: str, iterations: int) -> str:
    """Encrypts data using AES-256-CBC algorithm.

    Args:
        data(str): plaintext to be encrypted.
        password(str): password to be used for encryption
        iterations(int): number of iterations to be used in PBKDF2 key derivation function.

    Returns:
        str: encrypted data

    Raises:
        ValueError: if there is an error in generating the secret key
    """
    # Create IV
    iv = AES.get_random_bytes(16)
    # Create salt
    salt = AES.get_random_bytes(16)
    # Generate the secret key
    try:
        secret_key = generate_secret_key(
            salt=salt, iterations=iterations, password=password
        )
    except ValueError as error:
        raise error

    # Create cipher obj
    cipher = AES.new(key=secret_key, mode=AES.MODE_CBC, iv=iv)
    # Encrypt data
    data_byte_str = data.encode("utf-8")
    pad_data = pad(data_byte_str, AES.block_size)
    enc_data = cipher.encrypt(pad_data)
    # Convert values to hex
    enc_data_hex = binascii.hexlify(enc_data)
    salt_hex = binascii.hexlify(salt)
    iv_hex = binascii.hexlify(iv)
    # convert from hex to string
    enc_data_str = str(enc_data_hex, "utf-8")
    enc_salt_str = str(salt_hex, "utf-8")
    enc_iv_str = str(iv_hex, "utf-8")

    return {"enc_data": enc_data_str, "salt": enc_salt_str, "iv": enc_iv_str}


def aes256_cbc_decrypt(data: str, password: str, iterations: int) -> str:
    """Decrypts data using AES-256-CBC algorithm.

    Args:
        data(str): encrypted data.
        password(str): password to be used for decryption
        iterations(int): number of iterations to be used in PBKDF2 key derivation function.

    Returns:
        str: decrypted data

    Raises:
        ValueError: if there is an error in generating the secret key
    """
    # Convert values from string to hex
    enc_data_hex = binascii.unhexlify(data["enc_data"])
    salt_hex = binascii.unhexlify(data["salt"])
    iv_hex = binascii.unhexlify(data["iv"])
    # Generate the secret key
    try:
        secret_key = generate_secret_key(
            salt=salt_hex, iterations=iterations, password=password
        )
    except ValueError as error:
        raise error

    # Create cipher obj
    cipher = AES.new(key=secret_key, mode=AES.MODE_CBC, iv=iv_hex)
    # Decrypt data
    dec_data = cipher.decrypt(enc_data_hex)
    # Unpad data
    unpad_data = unpad(dec_data, AES.block_size)
    # Convert from bytes to string
    dec_data_str = str(unpad_data, "utf-8")

    return dec_data_str
