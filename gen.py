import sys
import hashlib
import random


def gen_hashes(in_file, encoding, hash_func, count, out_file):
    """Вычисляет хеши из входного файла, записывает в выходной"""
    maintained_encodings = ["UTF-8", "UTF-16"]
        
    maintained_h_funcs = {
        'MD4': 'md4',
        'MD5': 'md5',
        'SHA-1': 'sha1',
        'SHA-256': 'sha256',
        'SHA-512': 'sha512',
    }

    if encoding not in maintained_encodings:
        print(f"Unsupported encoding:{encoding}")
        return

    if count <= 0:
        print("The amount of hash_values should be positive!")
        return

    if hash_func not in maintained_h_funcs:
        print(f"Unsupported hash function: {hash_func}")
        print(f"Available hash functions are: md4, md5, sha-1, sha-256, sha-512")
        return

    try:
        with open(in_file, 'r', encoding=encoding) as f:
            passw = f.read().splitlines()
    except Exception as err:
        print(f"Error occured while reading from input file: {err}")
        return

    hashes = []
    hash_func = getattr(hashlib, maintained_h_funcs[hash_func])     # определяем хеш-функцию

    for password in passw:
        hash_value = hash_func(password.encode(encoding)).hexdigest()   # вычисляем хеш для каждого пароля
        hashes.append(hash_value)

    while len(hashes) < count:                  # дополняем файл случайными хешами
        length = random.randint(1, 10) 
        random_password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=length))
        random_hash = hash_func(random_password.encode(encoding)).hexdigest()
        hashes.append(random_hash)

    try:
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(hashes))
    except Exception as err:
        print(f"Error occured while writing to output file: {err}")


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python gen.py <input_file> <encoding> <hash_function> <count> <output_file>")
        sys.exit(1)

    in_file = sys.argv[1]       # считываем переданные аргументы
    encoding = sys.argv[2]
    hash_func = sys.argv[3]
    count = int(sys.argv[4])
    out_file = sys.argv[5]

    gen_hashes(in_file, encoding, hash_func, count, out_file)
