from flask import Flask, render_template, request, redirect, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import LoginManager, UserMixin, login_required
from gigachat import GigaChat
from config import auth, secret, client_id
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


def get_token(auth_token, scope='GIGACHAT_API_PERS'):
    """
      Выполняет POST-запрос к эндпоинту, который выдает токен.

      Параметры:
      - auth_token (str): токен авторизации, необходимый для запроса.
      - область (str): область действия запроса API. По умолчанию — «GIGACHAT_API_PERS».

      Возвращает:
      - ответ API, где токен и срок его "годности".
      """
    # Создадим идентификатор UUID (36 знаков)
    rq_uid = str(uuid.uuid4())

    # API URL
    url = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"

    # Заголовки
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'RqUID': rq_uid,
        'Authorization': f'Basic {auth_token}'
    }

    # Тело запроса
    payload = {
        'scope': scope
    }

    try:
        # Делаем POST запрос с отключенной SSL верификацией
        # (можно скачать сертификаты Минцифры, тогда отключать проверку не надо)
        response = requests.post(url, headers=headers, data=payload, verify=False)
        return response
    except requests.RequestException as e:
        print(f"Ошибка: {str(e)}")
        return -1


def send_chat_request(giga_token, user_message):
    """
    Отправляет POST-запрос к API GigaChat для получения ответа от модели чата.

    Параметры:
    - giga_token (str): Токен авторизации для доступа к API GigaChat.
    - user_message (str): Сообщение пользователя, которое будет обработано моделью GigaChat.

    Возвращает:
    - str: Строка сгенерированного ответа GigaChat с тэгом img
    """
    # URL API для отправки запросов к GigaChat
    url = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"

    # Заголовки для HTTP-запроса
    headers = {
        'Content-Type': 'application/json',  # Указываем, что отправляемые данные в формате JSON
        'Authorization': f'Bearer {giga_token}',  # Используем токен авторизации для доступа к API
    }

    # Данные для отправки в теле запроса
    payload = {
        "model": "GigaChat:latest",  # Указываем, что хотим использовать последнюю версию модели GigaChat
        "messages": [
            {
                "role": "user",  # Роль отправителя - пользователь
                "content": user_message  # Сообщение от пользователя
            },
        ],
        "temperature": 0.7  # Устанавливаем температуру, чтобы управлять случайностью ответов
    }

    try:
        # Отправляем POST-запрос к API и получаем ответ
        response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
        # Выводим текст ответа. В реальных условиях следует обрабатывать ответ и проверять статус коды.
        print(response.json())
        return response.json()["choices"][0]["message"]["content"]
    except requests.RequestException as e:
        # В случае возникновения исключения в процессе выполнения запроса, выводим ошибку
        print(f"Произошла ошибка: {str(e)}")
        return None


def login_ip():
    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('SELECT username FROM Login WHERE ip = ?', (request.environ['REMOTE_ADDR'],))
    return cur.fetchall()


@app.route('/')
def pop():
    return redirect("/home", code=302)


@app.route('/home')
def home():
    if not login_ip():
        return render_template('unlog_home.html')
    else:
        return render_template('log_home.html')


@app.route('/profile', methods=['POST', 'GET'])
def profile():
    if not login_ip():
        return redirect('/error_401')
    else:
        return render_template('profile.html', name=login_ip()[0][0])


@app.route('/select')
def select():
    if not login_ip():
        return render_template('error_401.html')
    else:
        return render_template('select.html')


@app.route('/info')
def info():
    return render_template('info.html')


@app.route('/log_out', methods=["GET"])
def log_out():
    ip = request.remote_addr

    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('DELETE FROM login WHERE ip = (?)', (ip,))
    con.commit()

    return redirect('/home')


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
        flash_msg = 'Данное имя не зарегистрировано'
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

        # Создаем таблицу Users
        cur.execute(f'''
        CREATE TABLE IF NOT EXISTS {username}_images (
        id INTEGER PRIMARY KEY,
        ai TEXT NOT NULL,
        file TEXT NOT NULL
        )
        ''')

        cur.execute(f'''
        CREATE TABLE IF NOT EXISTS {username}_text (
        id INTEGER PRIMARY KEY,
        ai TEXT NOT NULL,
        promt TEXT NOT NULL,
        answer TEXT NOT NULL
        )
        ''')

        con.commit()
        return redirect("/home", code=302)

    return render_template('registration.html', flash=flash_msg)


@app.route('/registration')
def registration():
    if not login_ip():
        return render_template('registration.html')
    else:
        return redirect("/home", code=302)


def func_chat_giga(promt):
    text_input = promt
    name = login_ip()[0][0]
    with GigaChat(
            credentials=auth,
            verify_ssl_certs=False) as giga:
        response = giga.chat(text_input)
        output = response.choices[0].message.content

    con = sqlite3.connect('Users.db')
    cur = con.cursor()

    cur.execute(f'SELECT max(id) FROM {name}_text')
    max_id = cur.fetchone()[0]
    if not max_id:
        max_id = 0
    else:
        max_id = int(max_id)
    cur.execute(f'INSERT INTO {name}_text (ai, promt, answer) VALUES (?, ?, ?)', ('gigachat', promt, output))
    con.commit()
    return output


# @app.route('/add_chat_giga')
# def registration():
#     return redirect("/chat_giga", code=302)


@app.route('/chat_giga', methods=["POST", "GET"])
def chat_giga():
    mode = 'msg'
    if login_ip():
        if request.method == 'POST':
            output = ''
            msg = request.form["msg"]
            if mode == 'img':
                output = f'<img src="{msg}" alt="Изображение">'
            if mode == 'msg':
                output = func_chat_giga(msg)
            return output
        return render_template('chat_giga.html')
    else:
        return render_template('error_401.html')


def func_chat_kandinsky(promt):
    name = login_ip()[0][0]
    response = get_token(auth)
    if response != 1:
        giga_token = response.json()['access_token']

    user_message = promt
    response_img_tag = send_chat_request(giga_token, user_message)

    # Парсим HTML
    soup = BeautifulSoup(response_img_tag, 'html.parser')

    # Извлекаем значение атрибута `src`
    img_src = soup.img['src']
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {giga_token}', }

    response = requests.get(f'https://gigachat.devices.sberbank.ru/api/v1/files/{img_src}/content',
                            headers=headers,
                            verify=False)

    con = sqlite3.connect('Users.db')
    cur = con.cursor()

    cur.execute(f'SELECT max(id) FROM {name}_images')
    max_id = cur.fetchone()[0]
    if not max_id:
        max_id = 0
    else:
        max_id = int(max_id)
    cur.execute(f'INSERT INTO {name}_images (file, ai) VALUES (?, ?)', (f'{name}_image_{max_id + 1}.jpg', 'kandinsky'))
    con.commit()
    with open(f'static/users_images/{name}_image_{max_id + 1}.jpg', 'wb') as f:
        f.write(response.content)

    return f'static/users_images/{name}_image_{max_id + 1}.jpg'


@app.route('/chat_kandinsky', methods=["POST", "GET"])
def chat_kandinsky():
    mode = 'img'
    if login_ip():
        if request.method == 'POST':
            output = ''
            msg = request.form["msg"]
            if mode == 'img':
                output = f'<img src="{func_chat_kandinsky(msg)}" class="img_msg" alt="Изображение">'
            if mode == 'msg':
                output = msg
            return output
        return render_template('chat_kandinsky.html')
    else:
        return render_template('error_401.html')


@app.route('/chat_gpt', methods=["POST", "GET"])
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


@app.errorhandler(404)
def page_not_found(error):
    return render_template('error_404.html'), 404


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')
