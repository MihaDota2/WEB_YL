from flask import Flask, render_template, request, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import LoginManager, UserMixin, login_required
from gigachat import GigaChat
from bs4 import BeautifulSoup
import sqlite3
# import base64
import json
import requests
import uuid

app = Flask(__name__)

hash_word = 'sha256'

# Устанавливаем соединение с базой данных
con = sqlite3.connect('Users.db')
cur = con.cursor()

# Создаем таблицу Users
cur.execute('''
CREATE TABLE IF NOT EXISTS Users (
id INTEGER PRIMARY KEY,
username TEXT NOT NULL,
password TEXT NOT NULL
)
''')

cur.execute('''
CREATE TABLE IF NOT EXISTS Login (
id INTEGER PRIMARY KEY,
ip TEXT NOT NULL,
username TEXT NOT NULL
)
''')

con.commit()


def login_ip():
    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('SELECT username FROM Login WHERE ip = ?', (request.environ['REMOTE_ADDR'],))
    return cur.fetchall()


@app.route('/login', methods=['POST'])
def func_login():
    username = request.form['username']
    password = request.form['password']

    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('SELECT username, password FROM Users WHERE username = ?', (username,))
    users = cur.fetchone()
    # print(check_password_hash(users[1], password))

    if not users:
        flash_msg = 'Данное имя не зарегестрированно'
    elif not password or not username:
        flash_msg = 'Остались незаполенные поля'
    elif not check_password_hash(users[1], password):
        flash_msg = 'Неверный пароль'
    else:
        cur.execute('INSERT INTO Login (ip, username) VALUES (?, ?)',
                    (request.environ['REMOTE_ADDR'], username))
        con.commit()
        return redirect("/home", code=302)

    return render_template('login.html', flash=flash_msg)


@app.route('/login')
def login():
    if not login_ip():
        return render_template('login.html')
    else:
        return redirect("/home", code=302)


@app.route('/registration', methods=['POST'])
def func_registration():
    username = request.form['username']
    password = request.form['password']
    verify_password = request.form['verify_password']
    print(username, password, request.environ['REMOTE_ADDR'])

    flash_msg = ''

    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('SELECT username FROM Users WHERE username = ?', (username,))
    users = cur.fetchall()

    print(users)

    if users:
        flash_msg = 'Данное имя уже зарегестрировано'
    elif not password or not verify_password or not username:
        flash_msg = 'Остались незаполенные поля'
    elif len(password) < 8:
        flash_msg = 'Длина пароля меньше 8 символов'
    elif password != verify_password:
        flash_msg = 'Пароль и подтверждение пароля не совпадают'
    else:
        cur.execute('INSERT INTO Users (username, password) VALUES (?, ?)',
                    (username, generate_password_hash(password)))
        cur.execute('INSERT INTO Login (ip, username) VALUES (?, ?)',
                    (request.environ['REMOTE_ADDR'], username))
        con.commit()
        return redirect("/home", code=302)

    return render_template('registration.html', flash=flash_msg)


@app.route('/registration')
def registration():
    if not login_ip():
        return render_template('registration.html')
    else:
        return redirect("/home", code=302)


@app.route('/chat_gpt ', methods=["POST", "GET"])
def chat_gpt():
    if login_ip():
        pass
    else:
        return render_template('error_401.html')


@app.route('/chat_midjourney', methods=["POST", "GET"])
def chat_midjourney():
    if login_ip():
        pass
    else:
        return render_template('error_401.html')


@app.route('/chat_code', methods=["POST", "GET"])
def chat_code():
    if login_ip():
        pass
    else:
        return render_template('error_401.html')


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
