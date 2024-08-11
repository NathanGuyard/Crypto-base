from math import gcd
from cryptoy.utils import (
    draw_random_prime,
    int_to_str,
    modular_inverse,
    pow_mod,
    str_to_int,
)

def keygen() -> dict:
    e = 65537
    # 1. Tire aléatoirement un nombre premier p avec la fonction draw_random_prime
    p = draw_random_prime()
    
    # 2. Tire aléatoirement un nombre premier q avec la fonction draw_random_prime
    q = draw_random_prime()
    
    # 3. Calcul de d, l'inverse de e modulo (p - 1) * (q - 1), avec la fonction modular_inverse
    phi = (p - 1) * (q - 1)
    d = modular_inverse(e, phi)
    
    # 4. Renvoit un dictionnaire { "public_key": (e, p * q), "private_key": d}
    N = p * q
    return {"public_key": (e, N), "private_key": d}

def encrypt(msg: str, public_key: tuple) -> int:
    e, N = public_key
    
    # 1. Convertir le message en nombre entier avec la fonction str_to_int
    msg_int = str_to_int(msg)
    
    # 2. Verifiez que ce nombre est < public_key[1], sinon lancer une exception
    if msg_int >= N:
        raise ValueError("Le message est trop long pour être chiffré avec cette clé publique.")
    
    # 3. Chiffrez le nombre entier avec pow_mod et les paramètres de la clef publique (e, N)
    encrypted_msg = pow_mod(msg_int, e, N)
    return encrypted_msg

def decrypt(msg: int, key: dict) -> str:
    e, N = key["public_key"]
    d = key["private_key"]
    
    # 1. Utilisez pow_mod avec les paramètres de la clef
    decrypted_msg_int = pow_mod(msg, d, N)
    
    # 2. Convertir l'entier calculé en str avec la fonction int_to_str
    decrypted_msg = int_to_str(decrypted_msg_int)
    return decrypted_msg
