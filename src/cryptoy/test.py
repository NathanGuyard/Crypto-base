from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    # A implémenter, en sortie on doit avoir une liste result tel que result[i] == (a * i + b) % n
    s = []
    for i in range(n):
        s.append((a*i+b)%n)
    return s


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    # A implémenter, pour cela on appelle perm = compute_permutation(a, b, n) et on calcule la permutation inverse
    # result qui est telle que: perm[i] == j implique result[j] == i
    perm = compute_permutation(a, b, n)
    inv_perm = [0]*n
    for i in range(n):
        inv_perm[perm[i]] = i
    # print(result)
    return inv_perm 


def encrypt(msg: str, a: int, b: int) -> str:
    # A implémenter, en utilisant compute_permutation, str_to_unicodes et unicodes_to_str
    perm = compute_permutation(a, b, 0x110000)
    uni = str_to_unicodes(msg)
    s = [perm[i] for i in uni]
    # print(s)
    return unicodes_to_str(s)



def encrypt_optimized(msg: str, a: int, b: int) -> str:
    # A implémenter, sans utiliser compute_permutation
    s = []
    for m in msg:
        s.append(chr((a*ord(m)+b)%0x110000))
    return "".join(s)


def decrypt(msg: str, a: int, b: int) -> str:
    # A implémenter, en utilisant compute_inverse_permutation, str_to_unicodes et unicodes_to_str
    perm = compute_inverse_permutation(a, b, 0x110000)
    uni = str_to_unicodes(msg)
    s = [perm[i] for i in uni]
    return unicodes_to_str(s)


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    # A implémenter, sans utiliser compute_inverse_permutation
    # On suppose que a_inverse a été précalculé en utilisant compute_affine_key_inverse, et passé
    # a la fonction
    s = []
    for m in msg:
        s.append(chr((a_inverse*(ord(m)-b))%0x110000))
    return "".join(s)


def compute_affine_keys(n: int) -> list[int]:
    # A implémenter, doit calculer l'ensemble des nombre a entre 1 et n tel que gcd(a, n) == 1
    # c'est à dire les nombres premiers avec n
    affine_keys = []
    for i in range(1, n):
        if gcd(i, n) == 1:
            affine_keys.append(i)
    return affine_keys


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    # Trouver a_1 dans affine_keys tel que a * a_1 % N == 1 et le renvoyer
    # Placer le code ici (une boucle)
    for i in affine_keys:
        if (a*i)%n == 1:
            return i

    # Si a_1 n'existe pas, alors a n'a pas d'inverse, on lance une erreur:
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg et b == 58
    for a in range(1, 0x110000):
        if "bombe" in decrypt(s, a, 58):
            print(decrypt(s, a, 58))
            return decrypt(s, a, 58), (a, 58)

    # Placer le code ici

    raise RuntimeError("Failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg
   
    for a in range(1, 0x110000):
        try:
            a_inverse = compute_affine_key_inverse(a, compute_affine_keys(0x110000), 0x110000)
        except RuntimeError:
            continue
        for b in range(1, 10000):
            if "bombe" in decrypt_optimized(s, a_inverse, b):
                return decrypt_optimized(s, a_inverse, b), (a, b)
    # for a in range(1, 0x110000):
    #def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    #     if "bombe" in decrypt_optimized(s, a, 58):
    #         return decrypt_optimized(s, a, 58), (a, 58)
    # Placer le code ici

    raise RuntimeError("Failed to attack")