

# 🛡️ MemGuard — Keyless C/C++ Memory-Safety SAST Analyzer

<p align="center">
  <img src="static/logo.png" alt="MemGuard Logo" width="100" style="border-radius: 16px;">
</p>

<p align="center">
  <b>Автономний статичний аналізатор коду (SAST) для виявлення критичних дефектів пам'яті (Memory Corruption / Zero-Day Primitives) у проєктах на C та C++.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python" alt="Python 3.11">
  <img src="https://img.shields.io/badge/FastAPI-0.110-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/CWE-Top%2025-red" alt="CWE Top 25">
  <img src="https://img.shields.io/badge/Engine-Offline%20%2F%20Keyless-emerald" alt="Keyless">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker" alt="Docker">
</p>

---

## 📌 Про проєкт

**MemGuard** — це легковаговий інструмент для статичного аналізу безпеки вихідного коду (Static Application Security Testing). Проєкт створено для розробників та дослідників безпеки, яким потрібен швидкий локальний аудит коду на наявність вразливостей роботи з пам'яттю (Buffer Overflows, UAF, Double Free тощо) без використання хмарних сервісів чи сторонніх API-ключів (**Keyless**).

Розроблено: **dreamyr**

---

## ✨ Ключові можливості

- 🔍 **Сигнатурний аналіз небезпечних API (Banned Functions):** Виявлення застарілих функцій, які порушують стандарти безпеки (Microsoft SDL / CERT C).
- 🧬 **Трекінг життєвого циклу вказівників (Pointer State Tracking):** Відстеження станів динамічної пам'яті (`malloc` $\rightarrow$ `free` $\rightarrow$ `reused`) для виявлення *Use-After-Free* та *Double Free*.
- 🛡️ **Автоматичні рекомендації (Remediation Patches):** Для кожної знайденої вразливості сканер генерує фрагмент виправленого безпечного коду (наприклад, заміну `strcpy` на `strncpy` з нуль-термінацією).
- ⚡ **Миттєвий локальний рушій:** Працює повністю офлайн завдяки FastAPI та оптимізованим регулярним виразам / контекстним правилам.
- 🎨 **Сучасний SOC Dashboard:** Інтерактивний веб-інтерфейс із вбудованими зразками уразливого коду для тестування в 1 клік.

---

## 🛑 Які типи вразливостей знаходить MemGuard:

| CWE ID | Назва вразливості | Опис | Рівень небезпеки |
|---|---|---|---|
| **CWE-120** | Classic Buffer Overflow | Копіювання даних без перевірки меж (`strcpy`, `gets`, `sprintf`) | 🔴 **CRITICAL** (CVSS 9.8) |
| **CWE-416** | Use After Free (UAF) | Звернення до вказівника після його звільнення через `free()` | 🔴 **CRITICAL** (CVSS 9.1) |
| **CWE-415** | Double Free | Повторний виклик `free()` для тієї самої адреси пам'яті | 🟠 **HIGH** (CVSS 7.8) |
| **CWE-134** | Uncontrolled Format String | Небезпечний прямий друк рядків через `printf(user_input)` | 🟠 **HIGH** (CVSS 8.6) |
| **CWE-770** | Stack Exhaustion (`alloca`) | Виділення динамічної пам'яті на стеку без лімітів | 🟠 **HIGH** (CVSS 7.5) |

---

## 🛠 Технологічний стек

- **Backend:** Python 3.11, FastAPI, Uvicorn, Pydantic v2
- **Frontend:** HTML5, Tailwind CSS, FontAwesome (SOC Dark Theme SPA)
- **Containerization:** Docker, Docker Compose

---

## 🎯 Де це може бути корисним

MemGuard може бути корисним у сценаріях, де потрібно швидко перевірити C/C++-код на типові помилки керування пам'яттю без передачі вихідного коду у зовнішні хмарні сервіси:

- 🔐 **AppSec / Secure SDLC:** локальна перевірка небезпечних конструкцій під час розробки та перед передачею коду на code review.
- 🧪 **Security Research:** швидкий первинний аудит дослідницького або тестового C/C++-коду для пошуку потенційних memory-safety проблем.
- 🏭 **Embedded та IoT:** аналіз коду прошивок і низькорівневих компонентів, де C/C++ активно використовуються та помилки роботи з пам'яттю можуть мати серйозні наслідки.
- 🖥️ **Системне програмне забезпечення:** перевірка native-компонентів, бібліотек, драйверів та інших проєктів із ручним керуванням пам'яттю.
- 🔄 **CI/CD та pre-commit перевірки:** запуск як локального або контейнеризованого етапу перед merge, щоб автоматично знаходити відомі небезпечні патерни.
- 🎓 **Навчальні лабораторії з кібербезпеки:** демонстрація CWE, memory corruption, Use-After-Free та Double Free на контрольованих прикладах із поясненням способу виправлення.
- 🕵️ **Offline / Air-Gapped середовища:** використання там, де вихідний код не можна передавати стороннім сервісам або немає доступу до зовнішніх API.

MemGuard при цьому можна розглядати як **первинний шар SAST-перевірки**, а не як повну заміну комплексним аналізаторам компілятора, fuzzing, dynamic analysis або ручному security review.

---

## 🚀 Швидкий запуск

### 1. Клонування репозиторію

```bash
git clone https://github.com/ВАШ_НІК/memguard.git
cd memguard
```

### 2. Запуск через Docker

```bash
docker compose up --build
```

### 3. Відкриття інтерфейсу

Відкрийте браузер за адресою:
👉 http://localhost:8080

---

## 📁 Структура проєкту

```text
memguard/
├── docker-compose.yml       # Конфігурація сервісу та мапінг порту 8080
├── Dockerfile               # Збірка Python 3.11 середовища
├── requirements.txt         # Залежності бекенду
├── app/
│   ├── __init__.py          # Маркер пакета Python
│   ├── config.py            # Налаштування застосунку
│   ├── rules.py             # База знань CWE, сигнатури та паттерни виправлень
│   ├── analyzer.py          # Ядро SAST-аналізу та трекінг вказівників
│   └── main.py              # FastAPI ендпоінти та пресети кодів
├── static/
│   ├── index.html           # Інтерактивний SOC-інтерфейс
│   └── logo.png             # Логотип проєкту
└── README.md                # Документація
```

## ⚠️ Застереження (Disclaimer)

Цей інструмент розроблено виключно для навчальних цілей, проведення статичного аудиту безпеки та покращення надійності власного коду. Автор не несе відповідальності за наслідки використання програмного забезпечення у протиправних цілях.

<p align="center">
Розроблено з ❤️ користувачем <b>dreamyr</b>
</p>