import sys
import time
import hashlib
from multiprocessing import Pool, cpu_count


def compute_hash(password, encoding, hash_function):
    hash_func = getattr(hashlib, hash_function.lower())    

    return hash_func(password.encode(encoding)).hexdigest()

def process_part(chunk, hash_list, encoding, hash_function):
    matches = []

    for password in chunk:
        password = password.strip()  # убираем пробельные символы по краям
        hash_value = compute_hash(password, encoding, hash_function)
        if any(hash_value.strip().lower() == h.strip().lower() for h in hash_list):
            matches.append(f"{password}:{hash_value}")
    return matches

def split_list(data, num_chunks):
    avg = len(data) // num_chunks
    return [data[i * avg:(i + 1) * avg] for i in range(num_chunks)]

def crack_passwords(wordlist_file, encoding, hash_func, hashlist_file):
    maintained_encodings = ["UTF-8", "UTF-16"]
    maintained_h_funcs = ['md4','md5','sha1','sha256','sha512']
    # Загрузка словаря паролей
    try:
        with open(wordlist_file, 'r', encoding=encoding) as f:
            passwords = f.readlines()
    except Exception as err:
        print(f"Error occured while reading file with passwords: {err}")

    # Загрузка хешей
    try:
        with open(hashlist_file, 'r', encoding='utf-8') as f:
            hash_list = set(f.read().splitlines())
    except Exception as err:
        print(f"Error occured while reading file with hashes: {err}")

    if encoding not in maintained_encodings:
        print(f"Unsupported encoding:{encoding}")
        return
    if hash_func not in maintained_h_funcs:
        print(f"Unsupported hash function: {hash_func}")
        print(f"Available hash functions are: md4, md5, sha1, sha256, sha512")
        return
    # Печать хешей для проверки
    #print("Loaded hashes:")
    #for h in hash_list:
    #   print(h)

    # Распараллеливание вычислений
    num_cores = cpu_count()
    parts = split_list(passwords, num_cores)

    start_time = time.time()

    with Pool(processes=num_cores) as pool:
        results = pool.starmap(process_part, [(part, hash_list, encoding, hash_func) for part in parts])

    end_time = time.time()

    # Объединяем результаты из всех процессов
    matches = [item for sublist in results for item in sublist]

    # Вывод результатов
    if matches:
        for match in matches:
            print(match)
    else:
        print("No matches found.")

    print(f"\nSpeed: {len(passwords) / (end_time - start_time):.2f} candidates/second")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python crack.py <wordlist_file> <encoding> <hash_function> <hashlist_file>")
        sys.exit(1)

    wordlist_file = sys.argv[1]
    encoding = sys.argv[2]
    hash_function = sys.argv[3]
    hashlist_file = sys.argv[4]

    crack_passwords(wordlist_file, encoding, hash_function, hashlist_file)
