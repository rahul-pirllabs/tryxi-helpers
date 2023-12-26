from aes_enc_dec.aes_enc_dec import aes256_cbc_encrypt, aes256_cbc_decrypt


def test_aes256_cbc_encrypt_decrypt():
    """Test AES-256-CBC encryption and decryption."""
    # Test data
    data = "test data"
    password = "password"
    iterations = 10000
    # Encrypt data
    enc_data = aes256_cbc_encrypt(
        data=data, password=password, iterations=iterations
    )
    # Decrypt data
    dec_data = aes256_cbc_decrypt(
        data=enc_data, password=password, iterations=iterations
    )
    # Assert
    assert data == dec_data
