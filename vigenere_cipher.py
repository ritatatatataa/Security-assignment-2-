#!/usr/bin/env python3
"""
Vigenere Cipher with Multi-Round Row/Column Permutation
---------------------------------------------------------
Pipeline (encryption order):
    plaintext -> [Round 1: Vigenere substitution]
              -> [Round 2: Column permutation]
              -> [Round 3: Row permutation]
              -> ciphertext

Decryption simply runs the exact same three steps in reverse:
    ciphertext -> [undo Round 3: row permutation]
               -> [undo Round 2: column permutation]
               -> [undo Round 1: Vigenere substitution]
               -> plaintext

Every round is independently reversible, and each round's key determines
a permutation/shift, so the whole pipeline is fully symmetric: feeding the
printed ciphertext and the same three keys back into "Decrypt" always
reproduces the original plaintext exactly.

Only letters A-Z are processed (spaces/punctuation are stripped and the
text is upper-cased) -- this is standard for classical ciphers, since the
Vigenere alphabet itself only spans 26 symbols. This is documented in the
README together with worked examples.
"""

import math

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PAD_CHAR = "X"
LEN_HEADER_WIDTH = 6   # e.g. "000042" -> up to 999,999 characters


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def clean_text(s):
    """Upper-case and keep only A-Z letters."""
    return "".join(ch for ch in s.upper() if ch in ALPHA)


def clean_key(s):
    k = clean_text(s)
    if not k:
        raise ValueError("Key must contain at least one letter (A-Z).")
    return k


def keyword_order(key):
    """
    Turns a keyword into a column/row read-order, the classic columnar-
    transposition way: letters are ranked alphabetically (ties broken by
    original position), giving a permutation of range(len(key)).

    Example: key = "ZEBRA"
        index : 0 1 2 3 4
        letter: Z E B R A
        sorted alphabetically -> A(4) B(2) E(1) R(3) Z(0)
        order = [4, 2, 1, 3, 0]
    """
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def pad_to_multiple(text, block):
    remainder = len(text) % block
    if remainder == 0:
        return text
    return text + PAD_CHAR * (block - remainder)


# --------------------------------------------------------------------------
# Round 1 : Vigenere substitution
# --------------------------------------------------------------------------
def vigenere_encrypt(text, key):
    out = []
    for i, ch in enumerate(text):
        shift = ALPHA.index(key[i % len(key)])
        out.append(ALPHA[(ALPHA.index(ch) + shift) % 26])
    return "".join(out)


def vigenere_decrypt(text, key):
    out = []
    for i, ch in enumerate(text):
        shift = ALPHA.index(key[i % len(key)])
        out.append(ALPHA[(ALPHA.index(ch) - shift) % 26])
    return "".join(out)


# --------------------------------------------------------------------------
# Round 2 : Column permutation (columnar transposition)
# --------------------------------------------------------------------------
def column_permute_encrypt(text, key):
    ncols = len(key)
    text = pad_to_multiple(text, ncols)
    nrows = len(text) // ncols

    rows = [text[r * ncols:(r + 1) * ncols] for r in range(nrows)]
    order = keyword_order(key)

    # read the grid column by column, in the permuted column order
    out = []
    for c in order:
        for r in range(nrows):
            out.append(rows[r][c])
    return "".join(out)


def column_permute_decrypt(text, key):
    ncols = len(key)
    nrows = len(text) // ncols
    order = keyword_order(key)

    grid = [[None] * ncols for _ in range(nrows)]
    pos = 0
    for c in order:
        for r in range(nrows):
            grid[r][c] = text[pos]
            pos += 1

    return "".join("".join(row) for row in grid)


# --------------------------------------------------------------------------
# Round 3 : Row permutation (block transposition)
# --------------------------------------------------------------------------
def row_permute_encrypt(text, key):
    nrows = len(key)
    ncols = math.ceil(len(text) / nrows)
    text = pad_to_multiple(text, ncols) if len(text) % ncols else text
    # ensure exact nrows*ncols length
    text = text + PAD_CHAR * (nrows * ncols - len(text))

    rows = [text[r * ncols:(r + 1) * ncols] for r in range(nrows)]
    order = keyword_order(key)

    return "".join(rows[r] for r in order)


def row_permute_decrypt(text, key):
    nrows = len(key)
    ncols = len(text) // nrows
    order = keyword_order(key)

    chunks = [text[i * ncols:(i + 1) * ncols] for i in range(nrows)]
    rows_original = [None] * nrows
    for i, original_row_index in enumerate(order):
        rows_original[original_row_index] = chunks[i]

    return "".join(rows_original)


# --------------------------------------------------------------------------
# Full pipeline
# --------------------------------------------------------------------------
def encrypt(plaintext, vig_key, col_key, row_key, show_steps=True):
    clean = clean_text(plaintext)
    if not clean:
        raise ValueError("Plaintext must contain at least one letter (A-Z).")

    original_len = len(clean)

    step1 = vigenere_encrypt(clean, vig_key)
    step2 = column_permute_encrypt(step1, col_key)
    step3 = row_permute_encrypt(step2, row_key)

    ciphertext = f"{original_len:0{LEN_HEADER_WIDTH}d}" + step3

    if show_steps:
        print(f"  Cleaned plaintext (letters only) : {clean}")
        print(f"  Round 1 - Vigenere substitution   : {step1}")
        print(f"  Round 2 - Column permutation      : {step2}")
        print(f"  Round 3 - Row permutation         : {step3}")
        print(f"  Length header ({LEN_HEADER_WIDTH} digits)            : {original_len:0{LEN_HEADER_WIDTH}d}")
        print(f"  FINAL CIPHERTEXT (copy this)      : {ciphertext}")

    return ciphertext


def decrypt(ciphertext, vig_key, col_key, row_key, show_steps=True):
    ciphertext = ciphertext.strip()
    if len(ciphertext) <= LEN_HEADER_WIDTH or not ciphertext[:LEN_HEADER_WIDTH].isdigit():
        raise ValueError(
            "Ciphertext must start with the 6-digit length header produced "
            "by Encrypt (e.g. 000012ABCDEF...)."
        )

    original_len = int(ciphertext[:LEN_HEADER_WIDTH])
    body = ciphertext[LEN_HEADER_WIDTH:]

    step3_undone = row_permute_decrypt(body, row_key)
    step2_undone = column_permute_decrypt(step3_undone, col_key)
    step1_undone = vigenere_decrypt(step2_undone, vig_key)

    plaintext = step1_undone[:original_len]   # strip padding

    if show_steps:
        print(f"  Length header read                : {original_len}")
        print(f"  Undo Round 3 - row permutation     : {step3_undone}")
        print(f"  Undo Round 2 - column permutation  : {step2_undone}")
        print(f"  Undo Round 1 - Vigenere            : {step1_undone}")
        print(f"  RECOVERED PLAINTEXT (padding stripped): {plaintext}")

    return plaintext


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
MENU = """
==================== VIGENERE CIPHER (MULTI-ROUND) ====================
  1) Encrypt
  2) Decrypt
  3) Run built-in self-test (round-trip check)
  0) Exit
=========================================================================
"""


def ask_keys():
    vig_key = clean_key(input("  Vigenere Secret Key           : "))
    col_key = clean_key(input("  Column Permutation Key        : "))
    row_key = clean_key(input("  Row Permutation Key            : "))
    return vig_key, col_key, row_key


def line():
    print("=" * 73)


def self_test():
    cases = [
        ("ATTACKATDAWN", "LEMON", "KEY", "PERMUTE"),
        ("The quick brown fox jumps", "SECRET", "CIPHER", "ORDER"),
        ("HELLOWORLD", "ZEBRA", "ABC", "AB"),
    ]
    line()
    print("SELF-TEST: encrypting then decrypting each case and comparing")
    line()
    all_ok = True
    for plaintext, vk, ck, rk in cases:
        expected = clean_text(plaintext)
        cipher = encrypt(plaintext, vk, ck, rk, show_steps=False)
        recovered = decrypt(cipher, vk, ck, rk, show_steps=False)
        ok = recovered == expected
        all_ok &= ok
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] '{plaintext}' (keys: {vk}/{ck}/{rk})")
        print(f"           ciphertext : {cipher}")
        print(f"           recovered  : {recovered}")
    line()
    print("ALL TESTS PASSED" if all_ok else "SOME TESTS FAILED")
    line()


def main():
    while True:
        print(MENU)
        choice = input("Choice: ").strip()

        if choice == "1":
            plaintext = input("  Plaintext to encrypt           : ")
            vig_key, col_key, row_key = ask_keys()
            print()
            line()
            print("ENCRYPTION")
            line()
            try:
                encrypt(plaintext, vig_key, col_key, row_key)
            except ValueError as e:
                print(f"  Error: {e}")
            line()
            print()

        elif choice == "2":
            ciphertext = input("  Ciphertext to decrypt           : ")
            vig_key, col_key, row_key = ask_keys()
            print()
            line()
            print("DECRYPTION")
            line()
            try:
                decrypt(ciphertext, vig_key, col_key, row_key)
            except ValueError as e:
                print(f"  Error: {e}")
            line()
            print()

        elif choice == "3":
            self_test()
            print()

        elif choice == "0":
            print("\nBye.\n")
            break

        else:
            print("\n  Invalid choice.\n")


if __name__ == "__main__":
    main()
