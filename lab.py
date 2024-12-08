import sqlite3
import tkinter as tk
from tkinter import messagebox
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox

class RegistrationWindow(QWidget):
    def __init__(self, db_conn):
        super().__init__()
        self.db_conn = db_conn
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Регистрация")

        layout = QVBoxLayout()

        self.login_label = QLabel("Логин:")
        self.login_edit = QLineEdit()
        layout.addWidget(self.login_label)
        layout.addWidget(self.login_edit)

        self.password_label = QLabel("Пароль:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)  # Скрываем пароль
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_edit)

        self.register_button = QPushButton("Зарегистрироваться")
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def register(self):
        import hashlib
        login = self.login_edit.text()
        password = self.password_edit.text()
        password = hashlib.sha256(password.encode()).hexdigest()

        if not login or not password:
            QMessageBox.warning(self, "Ошибка", "Пожалуйста, заполните все поля.")
            return

        try:
            cursor = self.db_conn.cursor()
            cursor.execute("INSERT INTO users (login, password) VALUES (?, ?)", (login, password))
            self.db_conn.commit()
            QMessageBox.information(self, "Успех", "Регистрация прошла успешно.")
            self.close()
        except sqlite3.IntegrityError:  # Логин уже существует
            QMessageBox.warning(self, "Ошибка", "Пользователь с таким логином уже существует.")



class AuthorizationWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.db_conn = sqlite3.connect('users.db')  # Подключение к базе данных
        self.create_table() # создание таблицы если ее нет

        self.initUI()

    def create_table(self):
         cursor = self.db_conn.cursor()
         cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    login TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            ''')
         self.db_conn.commit()



    def initUI(self):
        self.setWindowTitle("Авторизация")

        layout = QVBoxLayout()

        self.login_label = QLabel("Логин:")
        self.login_edit = QLineEdit()
        layout.addWidget(self.login_label)
        layout.addWidget(self.login_edit)

        self.password_label = QLabel("Пароль:")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_edit)

        self.auth_button = QPushButton("Авторизоваться")
        self.auth_button.clicked.connect(self.authorize)
        layout.addWidget(self.auth_button)

        self.register_button = QPushButton("Регистрация")
        self.register_button.clicked.connect(self.open_registration_window)
        layout.addWidget(self.register_button)

        self.setLayout(layout)


    def authorize(self):
        import hashlib
        login = self.login_edit.text()
        password = self.password_edit.text()
        password = hashlib.sha256(password.encode()).hexdigest()

        cursor = self.db_conn.cursor()
        cursor.execute("SELECT * FROM users WHERE login = ? AND password = ?", (login, password))
        user = cursor.fetchone()

        if user:
            QMessageBox.information(self, "Успех", "Авторизация успешна!")
           # Здесь можно добавить дальнейшие действия после успешной авторизации
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный логин или пароль.")

    def open_registration_window(self):
        self.registration_window = RegistrationWindow(self.db_conn)
        self.registration_window.show()

if __name__ == '__main__':
    app = QApplication([])
    window = AuthorizationWindow()
    window.show()
    app.exec_()
