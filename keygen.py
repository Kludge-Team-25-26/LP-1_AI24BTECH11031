from Crypto.PublicKey import RSA

key = RSA.generate(4096)

pub_key = key.public_key()

with open('public.pem', 'w') as f:
    f.write(pub_key.export_key().decode("UTF-8"))

with open('private.pem', 'w') as f:
    f.write(key.export_key().decode("UTF-8"))
