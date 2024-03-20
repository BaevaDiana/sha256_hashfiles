import os
import json
import tkinter as tk
from tkinter import filedialog

def calculate_sha256(data):
    """Вычисляет SHA-256 хеш."""
    # Инициализация начальных значений хеша
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # Определение констант K
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    # Предварительная обработка данных
    bit_len = len(data) * 8
    data += b'\x80'
    while len(data) % 64 != 56:
        data += b'\x00'
    data += bit_len.to_bytes(8, 'big')

    # Разбивка данных на блоки
    blocks = [data[i:i+64] for i in range(0, len(data), 64)]

    # Цикл хеширования для каждого блока
    for block in blocks:
        words = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 64, 4)]

        # Расширение 16-ти 32-битных слов до 64-ти 32-битных слов
        for i in range(16, 64):
            s0 = (rotate_right(words[i-15], 7) ^
                  rotate_right(words[i-15], 18) ^
                  (words[i-15] >> 3))
            s1 = (rotate_right(words[i-2], 17) ^
                  rotate_right(words[i-2], 19) ^
                  (words[i-2] >> 10))
            words.append((words[i-16] + s0 + words[i-7] + s1) & 0xFFFFFFFF)

        # Инициализация рабочих переменных
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Основной цикл
        for i in range(64):
            S1 = (rotate_right(e, 6) ^
                  rotate_right(e, 11) ^
                  rotate_right(e, 25))
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + words[i]) & 0xFFFFFFFF
            S0 = (rotate_right(a, 2) ^
                  rotate_right(a, 13) ^
                  rotate_right(a, 22))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Обновление значения хеша
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    # Возвращаем хеш в виде строки
    return '{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}'.format(h0, h1, h2, h3, h4, h5, h6, h7)

def rotate_right(n, b):
    """Побитовый сдвиг вправо."""
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF


def verify_folder_integrity(folder_path):
    """Проверяет целостность файлов в папке."""
    integrity_results = []

    # Инициализация пустого словаря для хранения сохраненных хешей
    saved_hashes = {}

    # Имя файла, в который будут сохраняться хеши
    hash_file = "hashes.json"

    # Загружаем сохраненные хэши (если есть)
    if os.path.exists(hash_file):
        with open(hash_file, "r") as f:
            saved_hashes = json.load(f)

    # Проходим по всем файлам в указанной папке и ее подпапках
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            # Открываем файл в бинарном режиме и читаем его данные(в виде байт)
            with open(file_path, "rb") as file:
                file_data = file.read()

            # Вычисляем ожидаемый хеш для файла
            expected_hash = calculate_sha256(file_data)

            # Получаем сохраненный хеш для файла из словаря
            saved_hash = saved_hashes.get(file_path)

            # Проверяем соответствие хешей
            if saved_hash:
                if saved_hash == expected_hash:
                    integrity_results.append(f"Файл: {file_path} | Целостность подтверждена. Хэш совпадает с сохраненным значением.")
                else:
                    integrity_results.append(f"Файл: {file_path} | Проверка целостности не пройдена. Хэш не совпадает с сохраненным значением.")
            else:
                integrity_results.append(f"Файл: {file_path} | Новый файл. Вычисленный хэш: {expected_hash}")

            # Сохраняем хеш файла в словарь
            saved_hashes[file_path] = expected_hash

    # Сохраняем обновленные хеши в файл JSON
    with open(hash_file, "w") as f:
        json.dump(saved_hashes, f, indent=4)

    return integrity_results


def choose_folder():
    """Открывает диалоговое окно проводника для выбора папки."""
    root = tk.Tk()
    root.withdraw()  # Скрыть главное окно tkinter

    folder_path = filedialog.askdirectory()  # Открываем диалоговое окно для выбора папки
    if folder_path:
        result = verify_folder_integrity(folder_path)
        print(result)
        display_result(result)
    root.mainloop()

def display_result(result):
    """Отображает результат в графическом окне."""
    result_window = tk.Toplevel()
    result_window.title("Результат проверки целостности файлов")

    # Создаем текстовое поле для отображения результата
    result_text = tk.Text(result_window, wrap=tk.WORD)
    result_text.insert(tk.END, "\n".join(result))
    result_text.config(state=tk.DISABLED)  # Запрещаем редактирование текста
    result_text.pack(fill=tk.BOTH, expand=True)

    # Кнопка для закрытия окна и завершения программы
    ok_button = tk.Button(result_window, text="OK", command=lambda: [result_window.destroy(), result_window.quit()])
    ok_button.pack()

if __name__ == "__main__":
    choose_folder()