def cau_md5(text):
    from base64 import b64encode
    from hashlib import md5

    return md5(b64encode(text.encode('utf-8'))).hexdigest()

while True:
	print(cau_md5(input("text: ")))
