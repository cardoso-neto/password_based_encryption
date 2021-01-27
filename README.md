# Password-based Encryption
> Fernet encrypt strings using a key generated based on a string password.

Fernet (AES CBC with random IV + HMAC SHA256 and PKCS7 padding) with password.

Key derived with PBKDF2HMAC: salted 100k times hashed (SHA3_256) password.


## Installing

`pip install git+https://github.com/cardoso-neto/password_based_encryption.git@master`

## Using

```python
message = "The fox jumps over the lazy dog."
password = "2 strong & SECURE pa$$word"
cipher_text = PWordFernet(password).encrypt(message)
# 'nj2kr4YdCHpKwcjMNCNThAABhqCAAAAAAGAQwUnbQsLKbHg1vL_CQBjjn5WNKQC_a0rs9YVd7K0HiWlfE_9yvlDB56meX-x_5FDY4GTEjySniE9X9yl54hX-mSV4Pv1R-22U-tSn8rf72fGquwGhVjgeL90AdlDwodm_Fjo='
message = PWordFernet(password).decrypt(cipher_text)
# 'The fox jumps over the lazy dog.'
```

## Testing/Contributing

`git clone git@github.com:cardoso-neto/password_based_encryption.git`

`pip install -r requirements-test.txt`

`pip install -e .`

`pytest -v`
