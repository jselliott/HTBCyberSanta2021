# Crypto :: Missing Reindeer

*Not only elves took control of Santa's Christmas factory but they kidnapped Rudolf as well. Our cyber spies managed to capture an email related to Santa's favorite reindeer. Can you help them decrypt the message?*

### Challenge Files: [crypto_missing_reindeer.zip](crypto_missing_reindeer.zip)

For this challenge, you are provided with an email file which contains an RSA encrypted email as well as a public key. However, if we check the public key we find that the public exponent of the key is only 3, which is a big no-no.

The reason why this is a problem is because of the way that RSA uses modular arithmetic to encrypt messages:

If C = M<sup>E</sup> % N and M<sup>E</sup> is less than N (because we have a small exponent of 3) then the process of decrypting the message becomes very simple because it is not affected by the modulus.

This means that is the value of the ciphertext is less than the public key modulus N, then the plain text is simply the cube root of the ciphertext.

To calculate this, we can use a euclidean algorithm to perform a sort of binary search to quickly find the cube root:

```python

import base64
from Crypto.Util.number import bytes_to_long,long_to_bytes

def find_invpow(x,n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** n < x:
        high *= 2
    low = high//2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

flag = bytes_to_long(base64.b64decode("Ci95oTkIL85VWrJLVhns1O2vyBeCd0weKp9o3dSY7hQl7CyiIB/D3HaXQ619k0+4FxkVEksPL6j3wLp8HMJAPxeA321RZexR9qwswQv2S6xQ3QFJi6sgvxkN0YnXtLKRYHQ3te1Nzo53gDnbvuR6zWV8fdlOcBoHtKXlVlsqODku2GvkTQ/06x8zOAWgQCKj78V2mkPiSSXf2/qfDp+FEalbOJlILsZMe3NdgjvohpJHN3O5hLfBPdod2v6iSeNxl7eVcpNtwjkhjzUx35SScJDzKuvAv+6DupMrVSLUfcWyvYUyd/l4v01w+8wvPH9l"))

print(long_to_bytes(find_invpow(flag,3)))
```

This reveals the message content:

```
We are in Antarctica, near the independence mountains.
HTB{w34k_3xp0n3n7_ffc896}
```