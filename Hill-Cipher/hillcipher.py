import numpy as np
import math

def text_to_numbers(text):
    """Mengubah teks ke daftar angka (A=0, B=1, ..., Z=25)."""
    return [ord(char) - ord('A') for char in text.upper() if char.isalpha()]

def numbers_to_text(numbers):
    """Mengubah daftar angka kembali ke karakter huruf."""
    return "".join([chr(int(num) % 26 + ord('A')) for num in numbers])

def matrix_mod_inverse(matrix, modulus=26):
    """Mencari invers matriks modulo 26 (khusus 2x2)."""
    # Hitung determinan 2x2 secara manual agar presisi integer terjaga
    det = int(matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0])
    det_element = det % modulus
    
    try:
        det_inv = pow(det_element, -1, modulus)
    except ValueError:
        raise ValueError(f"Determinan {det_element} tidak punya invers mod {modulus}!")

    if matrix.shape == (2, 2):
        adjugate = np.array([
            [matrix[1, 1], -matrix[0, 1]],
            [-matrix[1, 0], matrix[0, 0]]
        ])
    else:
        det_float = int(np.round(np.linalg.det(matrix)))
        adjugate = np.round(np.linalg.inv(matrix) * det_float).astype(int)
        
    return (det_inv * adjugate) % modulus

def encrypt(plaintext, key_matrix):
    """Enkripsi Hill Cipher."""
    n = len(key_matrix)
    numbers = text_to_numbers(plaintext)
    
    while len(numbers) % n != 0:
        numbers.append(ord('X') - ord('A'))
        
    vectors = np.array(numbers).reshape(-1, n)
    ciphertext_numbers = []
    
    for v in vectors:
        c_vector = np.dot(v, key_matrix) % 26
        ciphertext_numbers.extend(c_vector)
        
    return numbers_to_text(ciphertext_numbers)

def decrypt(ciphertext, key_matrix):
    """Dekripsi Hill Cipher."""
    n = len(key_matrix)
    numbers = text_to_numbers(ciphertext)
    vectors = np.array(numbers).reshape(-1, n)
    
    inverse_key = matrix_mod_inverse(key_matrix, 26)
    plaintext_numbers = []
    
    for v in vectors:
        p_vector = np.dot(v, inverse_key) % 26
        plaintext_numbers.extend(p_vector)
        
    return numbers_to_text(plaintext_numbers)

def find_key(plaintext, ciphertext):
    """Mencari kunci Hill Cipher (Known-Plaintext Attack)."""
    p_nums = text_to_numbers(plaintext)
    c_nums = text_to_numbers(ciphertext)
    n = len(p_nums)

    if n < 4:
        raise ValueError("Teks terlalu pendek, minimal butuh 4 huruf!")

    for i in range(0, n - 1):
        for j in range(i + 1, n - 1):
            P = np.array([
                p_nums[i:i+2],
                p_nums[j:j+2]
            ])
            C = np.array([
                c_nums[i:i+2],
                c_nums[j:j+2]
            ])

            det = int(P[0, 0] * P[1, 1] - P[0, 1] * P[1, 0]) % 26

            if math.gcd(det, 26) == 1:
                P_inv = matrix_mod_inverse(P, 26)
                K = np.dot(P_inv, C) % 26
                return np.round(K).astype(int)

    raise ValueError("Tidak ditemukan blok matriks Plaintext yang invertible mod 26 pada teks ini!")

if __name__ == "__main__":
    key = np.array([
        [9, 18],
        [1, 5]
    ])
    
    message = "SUNDAY"
    print(f"Original Message : {message}")
    
    cipher_text = encrypt(message, key)
    print(f"Encrypted Cipher : {cipher_text}")
    
    decrypted_text = decrypt(cipher_text, key)
    print(f"Decrypted Text   : {decrypted_text}")
    
    found_key = find_key(message, cipher_text)
    print("\nMatriks Kunci Ditemukan:")
    print(found_key)