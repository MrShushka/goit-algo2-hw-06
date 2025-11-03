import array
import hashlib
import math

class BloomFilter:
    
    def __init__(self, size: int, num_hashes: int):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("Розмір фільтра (size) має бути позитивним цілим числом.")
        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("Кількість хеш-функцій (num_hashes) має бути позитивним цілим числом.")
            
        self.size = size  # Розмір бітового масиву (m)
        self.num_hashes = num_hashes  # Кількість хеш-функцій (k)
        # Створюємо бітовий масив, ініціалізований нулями. 
        # Використовуємо 'B' (unsigned char) для ефективності.
        self.bit_array = array.array('B', [0] * (size // 8 + (1 if size % 8 else 0)))
        
    def _get_hashes(self, item: str) -> list:
        if not item:
            return []
            
        hasher = hashlib.sha256()
        
        # Перетворюємо рядок на байти для хешування
        try:
            item_bytes = item.encode('utf-8')
        except UnicodeEncodeError:
            # Обробка рідкісних випадків некоректних символів
            item_bytes = item.encode('latin-1')

        hasher.update(item_bytes)
        hash_val = int(hasher.hexdigest(), 16)
        
        h1 = hash_val & 0xFFFFFFFFFFFFFFFF 
        h2 = (hash_val >> 64) & 0xFFFFFFFFFFFFFFFF 
        
        indices = []
        for i in range(self.num_hashes):
            # Комбінація хешів: g_i(x) = (h1(x) + i * h2(x)) mod m
            # Використовуємо % self.size для отримання індексу в діапазоні [0, size-1]
            index = (h1 + i * h2) % self.size
            indices.append(index)
            
        return indices

    def add(self, item: str):
        """Додає елемент до фільтра Блума."""
        if not isinstance(item, str) or not item:
            # Ігноруємо порожні або некоректні елементи
            return

        indices = self._get_hashes(item)
        for index in indices:
            # Встановлюємо біт за індексом у масиві
            byte_index = index // 8
            bit_offset = index % 8
            self.bit_array[byte_index] |= (1 << bit_offset)

    def __contains__(self, item: str) -> bool:
        if not isinstance(item, str) or not item:
            return False

        indices = self._get_hashes(item)
        
        # Перевіряємо, чи всі k бітів встановлені
        for index in indices:
            byte_index = index // 8
            bit_offset = index % 8
            
            # Якщо хоча б один біт не встановлений, елемента точно немає
            if not (self.bit_array[byte_index] & (1 << bit_offset)):
                return False
                
        # Якщо всі біти встановлені, елемент ймовірно є (хибно-позитивне спрацювання можливе)
        return True
    
    
def check_password_uniqueness(bloom_filter: BloomFilter, new_passwords: list) -> dict:
    if not isinstance(bloom_filter, BloomFilter):
        raise TypeError("Перший аргумент має бути екземпляром BloomFilter.")
    if not isinstance(new_passwords, list):
        raise TypeError("Другий аргумент має бути списком.")
    
    results = {}
    
    for password in new_passwords:
        # Коректна обробка типів даних: перевіряємо, чи це рядок
        if not isinstance(password, str) or not password.strip():
            status = "Некоректний/порожній пароль"
        else:
            if password in bloom_filter:
                status = "вже використаний"
            else:
                status = "унікальний"
            
            if status == "унікальний":
                bloom_filter.add(password)
                
        results[password] = status
        
    return results
    
if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' - {status}.")  