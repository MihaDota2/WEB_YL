from flask import Flask, render_template, request, redirect, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import LoginManager, UserMixin, login_required
from gigachat import GigaChat
from config import auth, secret, client_id, api_key_gpt
from bs4 import BeautifulSoup
import sqlite3
# import base64
import json
import requests
import uuid
from openai import OpenAI

# Создаём объект класса Flask для работы сайта
app = Flask(__name__)

# Создаём слово для хеширования паролей
hash_word = 'sha256'

# Создаём объект класса OpenAI для работы с ChatGTP
client = OpenAI(api_key=api_key_gpt)

# Устанавливаем соединение с базой данных Users
"""
Данная база данных выполняет ряд таких функций как:
1. Хранение логинов и паролей пользователей
(пароли предварительно хешируются)
2. Хранение таблиц с историей запросов пользователей и ответов нейросетей
(у каждого пользователя отдельная страница)
"""
con = sqlite3.connect('Users.db')
cur = con.cursor()

# Создаем таблицу Users
"""
В таблице создаются такие элементы как:
id - номер строки
username - имя пользователя
password - пароль пользователя (предварительно хешируются)
"""
cur.execute('''
CREATE TABLE IF NOT EXISTS Users (
id INTEGER PRIMARY KEY,
username TEXT NOT NULL,
password TEXT NOT NULL
)
''')

# Создаем таблицу Login
"""
В таблице создаются такие элементы как:
id - номер строки
ip - ip устройства, вошедшего в систему
username - имя пользователя под которым залогинен ip
"""
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
    """
    Функция отображает логин под которым залогинено устройство
    если устройство вошло в систему, то функция возвращает имя пользователя
    в противном случае вернётся пустой список, который засчитывается как Null
    """
    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('SELECT username FROM Login WHERE ip = ?', (request.environ['REMOTE_ADDR'],))
    return cur.fetchall()


# Перессылка на главную страницу
@app.route('/')
def pop():
    """
    Начальная страница сайта
    """
    return redirect("/home", code=302)


# Домашняя страница
@app.route('/home')
def home():
    """
    Домашняя страница сайта
    В функции совершается проверка залогинел ли пользователь
    (проверка совершается с помощью функции login_ip())
    если пользователь залогинен, то выводится страница log_home.html
    иначе - unlog_home.html
    """
    if not login_ip():
        return render_template('index.html')
    else:
        return render_template('index_log.html', name=login_ip()[0][0])


# Страница профиля пользователя
@app.route('/profile', methods=['POST', 'GET'])
def profile():
    """
    Страница профиля пользователя
    В функции совершается проверка залогинел ли пользователь
    (проверка совершается с помощью функции login_ip())
    если пользователь залогинен, то выводится страница profile.html
    иначе - выводится ошибка 401

    Также есть именованный аргумент name который берёт имя пользователя из функции login_ip()
    Этот аргумент выводит на странице профиля имя пользователя
    """
    if not login_ip():
        return redirect('/error_401')
    else:
        return render_template('profile.html', name=login_ip()[0][0])


# Страница выбора нейросети
@app.route('/select')
def select():
    """
    Страница выбора нейросети
    В функции совершается проверка залогинел ли пользователь
    (проверка совершается с помощью функции login_ip())
    если пользователь залогинен, то выводится страница select.html
    иначе - выводится ошибка 401
    """
    if not login_ip():
        return render_template('error_401.html')
    else:
        return render_template('select.html')


@app.route('/info')
def info():
    return render_template('info.html')


# Функция выхода пользователя из системы (разлогина)
@app.route('/log_out', methods=["GET"])
def log_out():
    """
    Функция выхода пользователя из системы (разлогина)
    переменная ip получает ip пользователя
    и из базы данных Users в таблице login удаляется строка с данным ip
    После этого устройство считается разлогиненым и ему нужно повторно входить в систему или регастрироваться
    Когда устройство разлогинилось, его автоматически перенаправляют на домашнюю страницу
    """
    ip = request.remote_addr

    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('DELETE FROM login WHERE ip = (?)', (ip,))
    con.commit()

    return redirect('/home')


# Функция логина
@app.route('/login', methods=['POST'])
def func_login():
    """
    Функция получает из форм username и password имя и пароль пользователя
    Далее идёт подключение к базе данных Users
    Совершается проверка есть ли данное имя в базе данных
    Если именя есть, все поля заполнены и пароль указан верно, то пользователь входит в систему
    В базу данных в таблицу Login заносится ip устройства которое вошло в систему
    после этого идёт перенаправление на домашнюю страницу
    Иначе пользователя перекидывает снова страницу логина и выводит соответсвующую ошибку
    """

    username = request.form['username']
    password = request.form['password']
    print(username, password)
    if username == ' ':
        username = ''

    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('SELECT username, password FROM Users WHERE username = ?', (username,))
    users = cur.fetchone()
    # print(check_password_hash(users[1], password))

    if not password or not username:
        flash_msg = 'Остались незаполенные поля'
    elif not users:
        flash_msg = 'Имя не зарегистрировано'
    elif not check_password_hash(users[1], password):
        flash_msg = 'Неверный пароль'
    else:
        cur.execute('INSERT INTO Login (ip, username) VALUES (?, ?)',
                    (request.environ['REMOTE_ADDR'], username))
        con.commit()
        return redirect("/home", code=302)

    return render_template('login.html', flash=flash_msg)


# Страница логина
@app.route('/login')
def login():
    """
    Страница логина
    В функции совершается проверка залогинел ли пользователь
    (проверка совершается с помощью функции login_ip())
    если пользователь залогинен, то выводится страница login.html
    также происходит взаимодействие с функцией func_login()
    иначе - выводится ошибка 401
    """
    if not login_ip():
        return render_template('login.html')
    else:
        return redirect("/select-ai", code=302)


@app.route('/registration', methods=['POST'])
def func_registration():
    """
    Функция получает из форм username, password и verify_password имя, пароль и подтверждение пароля пользователя
    Далее идёт подключение к базе данных Users
    Совершается проверка есть ли данное имя в базе данных
    Если имени нет, все поля заполнены и пароль указан верно, а также соответсвует повтору,
    то пользователь создаёт новый аккаунт и входит в систему
    В базу данных в таблицу Login заносится ip устройства которое вошло в систему
    после этого идёт перенаправление на домашнюю страницу
    Иначе пользователя перекидывает снова страницу регистрации и выводит соответсвующую ошибку
    Также в функции создаются таблицы которые хранят историю переписки с нейросетями пользователя
    """
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
    """
    Страница регистрации
    В функции совершается проверка залогинел ли пользователь
    (проверка совершается с помощью функции login_ip())
    если пользователь залогинен, то выводится страница registration.html
    также происходит взаимодействие с функцией func_registration()
    иначе - выводится ошибка 401
    """
    if not login_ip():
        return render_template('registration.html')
    else:
        return redirect("/home", code=302)


@app.route('/select-ai', methods=["POST", "GET"])
def select_ai():
    if login_ip():
        return render_template('select-ai.html', name=login_ip()[0][0])
    else:
        return redirect('/login')


def func_chat_giga(promt):
    """
    Функция генерации текста с помощью GigaChat
    функция получает promt (текстовый запрос пользователя для нейросети)
    далее с помощью алгоритма обработки создаётся текстовый ответ,
    который загружается в переменную output
    После этого в базу данных с историей пользователя сохраняется строка которая содержит запрос и ответ
    После чего функция возвращает переменную output
    """
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


# Задел на будующее, функция где будет реализовано добавление новых чатов в нейросети
# @app.route('/add_chat_giga')
# def registration():
#     return redirect("/chat_giga", code=302)


@app.route('/chat_giga', methods=["POST", "GET"])
def chat_giga():
    """
    Страница чата с GigaChat
    В функции совершается проверка залогинел ли пользователь
    (проверка совершается с помощью функции login_ip())
    если пользователь залогинен, то выводится страница chat_giga.html
    также происходит взаимодействие с функцией func_chat_giga()
    иначе - выводится ошибка 401

    Также есть проверка режима (текстовый или изображение)
    Функция возвращает на страницу сгенерированный текст или изображение
    которые после отображаются в чате
    """
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
    """
    Функция генерации изображения с помощью Kandinsky
    функция получает promt (текстовый запрос пользователя для нейросети)
    далее с помощью алгоритма обработки создаётся картинка,
    который сохраняется в папке users_images
    После этого в базу данных с историей пользователя сохраняется строка которая содержит название файла картинки
    После чего функция возвращает путь до созданной картинки
    """
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
    """
    Страница чата с Kandinsky
    В функции совершается проверка залогинел ли пользователь
    (проверка совершается с помощью функции login_ip())
    если пользователь залогинен, то выводится страница chat_giga.html
    также происходит взаимодействие с функцией func_chat_kandinsky()
    иначе - выводится ошибка 401

    Также есть проверка режима (текстовый или изображение)
    Функция возвращает на страницу сгенерированный текст или изображение
    которые после отображаются в чате
    """
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


def func_chat_gpt(promt):
    """
    Функция генерации текста с помощью ChatGPT
    функция получает promt (текстовый запрос пользователя для нейросети)
    далее с помощью алгоритма обработки создаётся текстовый ответ,
    который загружается в переменную output
    После этого в базу данных с историей пользователя сохраняется строка которая содержит запрос и ответ
    После чего функция возвращает переменную output
    """
    name = login_ip()[0][0]
    output = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": promt,
            }
        ],
        model="gpt-3.5-turbo", )

    con = sqlite3.connect('Users.db')
    cur = con.cursor()

    cur.execute(f'SELECT max(id) FROM {name}_text')
    max_id = cur.fetchone()[0]
    if not max_id:
        max_id = 0
    else:
        max_id = int(max_id)
    cur.execute(f'INSERT INTO {name}_text (ai, promt, answer) VALUES (?, ?, ?)', ('chatgpt', promt, output))
    con.commit()

    output = output.choices[0].message.content

    return output


@app.route('/chat_gpt', methods=["POST", "GET"])
def chat_gpt():
    mode = 'msg'
    if login_ip():
        if request.method == 'POST':
            output = ''
            msg = request.form["msg"]
            if mode == 'img':
                output = f'<img src="{msg}" alt="Изображение">'
            if mode == 'msg':
                output = func_chat_gpt(msg)
            print(output)
            return output
        return render_template('chat_gpt.html')
    else:
        return render_template('error_401.html')


# нереализованная функция так как у миджорни дорогие апи ¯\_(ツ)_/¯
@app.route('/chat_midjourney', methods=["POST", "GET"])
def chat_midjourney():
    if login_ip():
        return redirect("https://youtu.be/HLQ1cK9Edhc?si=t0l6oJPNYX-ocEdk&t=16", code=302)
    else:
        return render_template('error_401.html')


@app.errorhandler(404)
def page_not_found(error):
    """
    Функция перехватывает ошибку 404 и возвращает страницу error_404.html
    """
    return render_template('404.html'), 404


# функция которая запускает сайт
if __name__ == '__main__':
    app.run(port=7001, host='0.0.0.0')
