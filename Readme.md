# Простой проект авторизации на Python

Этот проект представляет собой простое приложение для авторизации пользователей с использованием PyQt5 и SQLite.

## Функциональность

* Регистрация новых пользователей с хэшированием паролей (SHA256).
* Авторизация существующих пользователей.
* Проверка на уникальность логина при регистрации.
* Сообщения об ошибках и успешных действиях.

## Запуск

1. Установите необходимые библиотеки:
   ```bash
   pip install -r requirements.txt
   ```
2. Запустите скрипт `main.py`:
   ```bash
   python main.py
   ```

## База данных

Приложение использует базу данных SQLite (`users.db`) для хранения информации о пользователях. Таблица `users` создается автоматически при первом запуске, если она не существует.

## Структура проекта

* `main.py`: Основной скрипт приложения.
* `users.db`: Файл базы данных SQLite (создается автоматически).
