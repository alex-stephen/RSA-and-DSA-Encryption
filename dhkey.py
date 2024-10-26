import random
import math

# Diffie–Hellman Key Exchange.

def runDH():
    lower = 0
    upper = 1000
    primeSet = []
    Alex = 0
    Jevon = 0

    #Base integer G for Key Gen Calculation
    G = 0
    #Prime number P used as modulo variable.
    #   Traditionally 2048 Bits for security.
    P = 0

    def gen_prime(lower, upper):
        for num in range(lower, upper + 1):
           if num > 1:
               for i in range(2, num):
                   if (num % i) == 0:
                       break
               else:
                   primeSet.append(num)

    def gcd(a, b):
        while b!=0:
            a, b = b , a % b
        return a

    def primitiveRoot(p):
        primitive_roots = []
        initial_set = set(num for num in range (1, p) if gcd(num, p) == 1)

        for g in range(1, p):
            root_set = set(pow(g, power) % p for power in range (1, p))
            if initial_set == root_set:
                primitive_roots.append(g)
        return primitive_roots

    def pick_random_prime():
        #Generating Random Iterator to select from Prime Array
        i = random.randint(0, len(primeSet) - 1)
        prime = primeSet[i]
        primeSet.remove(prime)
        return prime

    def assign_private_key():
        global Alex, Jevon, G
        print("---Generate Private Keys for Users---")
        Alex = random.randint(2, 500)
        print("Alex Private Key (a): ", Alex)
        Jevon = random.randint(2, 500)
        print("Jevon Private Key (b): ", Jevon, '\n')

    def gen_public():
        global Alex, Jevon, G, P
        primitive = []
        print("---Calculate Public Keys---")
        print("Public_Key = G^a mod P")
        print(' '*21 + "G^b mod P", '\n')
        # Picks Random Prime P
        P = pick_random_prime()
        # Generates an Array of Primitive Roots of P
        primitive = primitiveRoot(P)
        # Generating Random Iterator to select from Primitive Array
        j = random.randint(0, len(primitive) - 1)
        # Assigns G to a Random Primitive Root of P
        G = primitive[j]
        print("Prime Number P: ", '\n', "P: ", P)
        print("Random Primitive Root of (P) G: " , '\n', "G: ", G, '\n')
        print("Public_Key = ", G, "^", Alex, " mod ", P)
        x = pow(G, Alex) % P
        print("Alex Public Key: ", x, '\n')
        print("Public_Key = ", G, "^", Jevon, " mod ", P)
        y = pow(G, Jevon) % P
        print("Jevon Public Key: ", y, '\n')

        return x, y

    def compute_secret(pub_alex, pub_jevon):
        global Alex, Jevon, P
        print("---Compute Secret Key---")
        print("   Public Key Exchange")
        print("Public_Alex <--> Public_Jevon")
        print("Secret_Key = P_J^a mod P")
        print(' '*21 + "P_A^b mod P", '\n')
        print("Secret_Key = ", pub_jevon, "^", Alex, " mod ", P)
        print("Secret_Key = ", pub_alex, "^", Jevon, " mod ", P, '\n')
        # Swapping the Public Keys to generate the Secret Key
        secret_alex = pow(pub_jevon, Alex) % P
        secret_jevon = pow(pub_alex, Jevon) % P

        if (secret_jevon == secret_alex):
            print("Shared Secret Key: ", secret_alex)
            return secret_alex
        else:
            return -1



    assign_private_key()
    gen_prime(lower, upper)
    public_alex, public_jevon = gen_public()
    secret = compute_secret(public_alex, public_jevon)

runDH()