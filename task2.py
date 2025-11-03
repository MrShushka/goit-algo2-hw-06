import json
import time
from datasketch import HyperLogLog


def process_log_file(file_path):

    print(f"Завантаження та обробка даних із {file_path}...")
    ip_addresses = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, 1):
                try:
                    log_entry = json.loads(line)
                    ip = log_entry.get("remote_addr")
                    if ip:
                        ip_addresses.append(ip)
                except json.JSONDecodeError:
                    # Ігноруємо некоректні рядки (не валідний JSON)
                    print(f"Помилка декодування JSON у рядку {line_number}: {line.strip()[:50]}...")
                    continue
                except Exception as e:
                    # Обробка інших потенційних помилок
                    print(f"Неочікувана помилка в рядку {line_number}: {e}")
                    continue
    except FileNotFoundError:
        print(f"Помилка: Файл не знайдено за шляхом {file_path}")
        return None
        
    print(f"Зчитано {len(ip_addresses)} IP-адрес. Усього записів у файлі: {line_number}")
    return ip_addresses


def exact_count(ip_list):
    start_time = time.time()
    unique_ips = set(ip_list)
    count = len(unique_ips)
    end_time = time.time()
    
    return count, (end_time - start_time)

def hll_count_from_file(file_path, p=14):

    start_time = time.time()
    
    hll = HyperLogLog(p=p)
    processed_lines = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                processed_lines += 1
                try:
                    # Намагаємося декодувати JSON
                    log_entry = json.loads(line)
                    ip = log_entry.get("remote_addr")
                    
                    if ip:
                        # Додаємо елемент безпосередньо до HLL
                        hll.update(ip.encode('utf8'))
                        
                except json.JSONDecodeError:
                    # Ігноруємо некоректні рядки
                    continue
                except Exception as e:
                    # Обробка інших потенційних помилок
                    continue

        # Отримуємо наближену кількість
        approx_count = hll.count()
        end_time = time.time()
        
        print(f"HLL: Зчитано та оброблено {processed_lines} рядків.")
        return approx_count, (end_time - start_time)

    except FileNotFoundError:
        print(f"Помилка: Файл не знайдено за шляхом {file_path}")
        return 0, 0.0


def demo_new_hll_function(file_path, exact_unique_count):
    """
    Демонструє використання потокової HLL функції та порівнює результат.
    """
    
    print("\n--- Демонстрація Адаптованої HLL Функції (Потокова Обробка) ---")
    
    hll_approx_count_stream, hll_time_stream = hll_count_from_file(file_path)

    # Обчислення похибки
    absolute_error = abs(hll_approx_count_stream - exact_unique_count)
    relative_error = (absolute_error / exact_unique_count) * 100 if exact_unique_count > 0 else 0

    print("\n**Результати потокової обробки HyperLogLog:**")
    print(f"* Точна кількість унікальних IP-адрес:  **{exact_unique_count}**")
    print(f"* Наближена кількість (HyperLogLog):   **{hll_approx_count_stream:.0f}**")
    print(f"* Час виконання (сек.):               {hll_time_stream:.4f}")
    print(f"* Відносна похибка:                   **{relative_error:.2f}%**")
    print("\n**Перевага:** Функція не зберігає мільйони IP-адрес у пам'яті, використовуючи лише **кілька кілобайт** для HLL об'єкта, що робить її ефективною для обробки терабайтів логів.")


if __name__ == "__main__":
    


    file_path = 'lms-stage-access.log'
    def process_log_file_for_exact(file_path):
        ip_addresses = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line)
                        ip = log_entry.get("remote_addr")
                        if ip:
                            ip_addresses.append(ip)
                    except json.JSONDecodeError:
                        continue
            return ip_addresses
        except FileNotFoundError:
            return []

    ip_list_all = process_log_file_for_exact(file_path)
    if not ip_list_all:
         print(f"Неможливо виконати точний підрахунок. Переконайтесь, що файл '{file_path}' існує.")
    else:
        exact_count_value, _ = exact_count(ip_list_all)
        
        demo_new_hll_function(file_path, exact_count_value)
            
