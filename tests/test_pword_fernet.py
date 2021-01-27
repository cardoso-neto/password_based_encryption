
from password_based_encryption import PWordFernet


def test_encrypted_msg_can_be_decrypted_with_the_same_key():
    message = 'The brown fox jumps over the crazy lake'
    password = 'xablau'
    pword_fernet = PWordFernet(password)
    cipher_text = pword_fernet.encrypt(message)
    round_trip = pword_fernet.decrypt(cipher_text)
    assert round_trip == message

def test_encrypted_msg_can_be_decrypted_by_a_different_instance():
    message = 'The brown fox jumps over the crazy lake.'
    password = 'xablau'
    cipher_text = PWordFernet(password).encrypt(message)
    round_trip = PWordFernet(password).decrypt(cipher_text)
    assert round_trip == message
