import random
import math

# Standard Key Size 1024->4096 Bits long
# Primes Generated 1024->2048 Bits
# Modulus Size from 2048-4096 Bits


def runRSA():
    # Establish a Range to choose a Random Prime
    lower = 0
    upper = 1000

    # Text to Encrypt
    Text = "Hello, Welcome to RSA Encryption!"
    print("Text to Encrypt: ", '\n', Text, '\n')

    print("Cipher Text = m^e mod n")
    print("Plaintext = (CipherText^d) mod n", '\n')

    publicKey = 0
    privateKey = 0
    n = 0
    prime_num = []

    # Appends all Prime Numbers Between the Range to an array.
    def gen_prime(lower, upper):
        for num in range(lower, upper + 1):
            if num > 1:
                for i in range(2, num):
                    if (num % i) == 0:
                        break
                else:
                    prime_num.append(num)

    # Picks a random prime number from the Array
    def pick_random_prime():
        # Generating Random Iterator to select from Prime Array
        i = random.randint(0, len(prime_num) - 1)

        prime = prime_num[i]
        # Deletes the Prime number that is chosen so subsequent call ensures the same
        # Number will not be chosen
        prime_num.remove(prime)
        return prime

    # Sets the Public and Private keys for both users.
    def set_keys():
        global privateKey, publicKey, n
        # Initializing d and e > 1 or the operations would be the same
        e = 2
        d = 2
        print("Selecting Two Primes Numbers: ")
        # Assigns P and Q to be 2 Random Primes
        p = pick_random_prime()
        q = pick_random_prime()
        print("Prime 1 (p): ", p)
        print("Prime 2 (q): ", q, '\n')
        n = p * q
        print("N (p*q): ", n)
        phi = (p - 1) * (q - 1)
        print("ϕ(n): ", phi, '\n')
        while True:
            # Finds the GCD of e and phi where it == 1
            if math.gcd(e, phi) == 1:
                break
            # Increments e until the GCD is found
            e += 1

        while True:
            # Finds a d where d*e%phi == 1
            if (d * e) % phi == 1:
                break
            d += 1

        # Final Value of e will be the Public Key
        publicKey = e
        # Final Value of d will be the Public Key
        privateKey = d
        print("PublicKey = 1 < e < ϕ(n)")
        print("Public Key:", publicKey, ",", n, '\n')
        print("Private Key = (d*e) % ϕ(n) == 1")
        print("Private Key:", privateKey, ",", n, '\n')

    # String to ASCII conversion
    def string2ASCII(text):
        ASCII = []
        for letters in text:
            ASCII.append(ord(letters))
        return ASCII

    # ASCII to String Convertion
    def ASCII2string(encoded):
        string = ""
        for num in encoded:
            string += (chr(num))
        return string

    # Encrypts the string message into an array of encrypted values.
    def encrypt(message):
        global publicKey, n
        final = []
        for letter in message:
            e = publicKey
            encryptText = 1
            while e > 0:
                encryptText *= letter
                encryptText %= n
                e -= 1
            final.append(encryptText)
        return final
    # Decrypts an array of encrypted values and returns an array of ASCII Characters
    def decrypt(message):
        global privateKey, n
        final = []
        for letter in message:
            d = privateKey
            decryptText = 1
            while d > 0:
                decryptText *= letter
                decryptText %= n
                d -= 1
            final.append(decryptText)
            string = ASCII2string(final)
        return string

    gen_prime(lower, upper)
    set_keys()

    asciiText = string2ASCII(Text)
    print("Plaintext Represented as an Array of ASCII: ")
    print(asciiText, '\n')
    encrypted = encrypt(asciiText)
    print("Encrypted ASCII Text Represented as an Array of encrypted integers: ")
    print(encrypted, '\n')
    decrypted = decrypt(encrypted)
    print("Final Decrypted Text: ")
    print(decrypted)


runRSA()
