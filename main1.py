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

auth = 'ZGIwZmJmZGYtZThiMi00MDI0LTg4YTUtYjU0YTg5NDc3Y2FkOmQ4ZDg0ZWE4LWJjMmUtNGZhNi05YWM4LWRlODgxZDgzZmI2Yg=='
secret = 'd8d84ea8-bc2e-4fa6-9ac8-de881d83fb6b'
client_id = 'db0fbfdf-e8b2-4024-88a5-b54a89477cad'

promt = '''Давай создадим интерактивную игру внутри GigaChat? Как например в настольных ролевых играх, где GigaChat будет выступать в роли ведущего, а я в роли игрока.
В начале мы создадим сеттинг и мир в котором будут происходит события игры. Для этого ты предложишь мне пять вариантов на выбор.
Далее создадим персонажа выбрав из пяти предложенных вариантов на выбор. 
Далее GigaChat будет рассказывать историю про моего персонажа и предоставлять 5 вариантов для действий, которые может совершить мой персонаж. При этом каждая история начинается с четкой завязки, где у нас есть прописанная цель к которой мы идем. Сложность игры достаточно высокая и необдуманные поступки могут привести к трагическим последствиям. Игрок выбирает действие которое совершает персонаж и это продвигает его по сюжету игры
Ответ GigaChat всегда должен выглядеть подобным образом:
Информация
Первый вариант
Второй вариант
Третий вариант
Четвертый вариант
Пятый вариант'''

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

con = sqlite3.connect('History.db')
cur = con.cursor()

cur.execute('''
CREATE TABLE IF NOT EXISTS History (
id INTEGER PRIMARY KEY,
text TEXT NOT NULL
)
''')

cur.execute('DELETE FROM History')
cur.execute('INSERT INTO History (text) VALUES (?)', ('Слова пользователя: ' + promt,))
con.commit()
flag = True
message_history = ''
image_number = 1


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
    return render_template('unlog_home.html')


@app.route('/chat', methods=["POST", "GET"])
def chat():
    global flag
    global message_history
    global image_number
    if request.method == 'POST':
        text_input = request.form['text_label']
        print(text_input)

        connection = sqlite3.connect('History.db')
        cursor = connection.cursor()
        output = text_input
        message_history += '\nСлова пользователя: ' + text_input + '\n'

        cursor.execute('INSERT INTO History (text) VALUES (?)', ('\nСлова пользователя: ' + text_input,))

        history_text = ''

        cursor.execute('SELECT text FROM History')
        texts = cursor.fetchall()
        for text in texts:
            history_text += text[0]
        with GigaChat(
                credentials=auth,
                verify_ssl_certs=False) as giga:
            response = giga.chat(history_text)
            output = response.choices[0].message.content
        print(output)
        message_history += '\nСлова GigaChat: ' + output + '\n'

        cursor.execute('INSERT INTO History (text) VALUES (?)', ('\nСлова GigaChat: ' + output,))
        connection.commit()

        response = get_token(auth)
        if response != 1:
            # print(response.text)
            giga_token = response.json()['access_token']

        with GigaChat(
                credentials=auth,
                verify_ssl_certs=False) as giga:
            response = giga.chat('Создай на базе этого текста промт для генерации картинки' + history_text)
            output = response.choices[0].message.content

        print(output)

        user_message = 'Нарисуй изображение которое будет соответствовать содержанию текста: \n' + output
        response_img_tag = send_chat_request(giga_token, user_message)
        # print(response_img_tag)

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

        with open(f'static/images/image.jpg', 'wb') as f:
            f.write(response.content)

        # with open(f'static/images/image{image_number}.jpg', 'wb') as f:
        #     f.write(response.content)

        # image_number += 1

        connection.commit()

        return render_template("chat.html", sample_output=message_history)
    elif flag:
        with GigaChat(
                credentials=auth,
                verify_ssl_certs=False) as giga:
            response = giga.chat(promt)
            output = response.choices[0].message.content
        connection = sqlite3.connect('History.db')
        cursor = connection.cursor()

        print(output)

        cursor.execute('INSERT INTO History (text) VALUES (?)', ('\nСлова GigaChat: ' + output,))
        connection.commit()
        flag = False
        message_history += '\nСлова GigaChat: ' + output + '\n'
        return render_template('chat.html', sample_output=output)
    else:
        return render_template('chat.html')


@app.route('/model')
def model():
    if not login_ip():
        return 'не в вошли в систему'
    else:
        return render_template('model.html')
    # return render_template('model.html')


# @app.route('/reglog')
# def model():
#     return render_template('reglog.html')

@app.route('/login', methods=['POST'])
def func_login():
    if not login_ip():
        username = request.form['username']
        password = request.form['password']

        con = sqlite3.connect('Users.db')
        cur = con.cursor()
        cur.execute('SELECT username, password FROM Users WHERE username = ?', (username,))
        users = cur.fetchone()
        print(users)

        if users:
            if check_password_hash(users[1], password):
                cur.execute('INSERT INTO Login (ip, username) VALUES (?, ?)',
                            (request.environ['REMOTE_ADDR'], username))
                con.commit()
                return redirect("/model", code=302)

        return render_template('login.html')
    else:
        return redirect("/model", code=302)


@app.route('/login')
def login():
    if not login_ip():
        return render_template('login.html')
    else:
        return redirect("/model", code=302)


# @app.route("/get_my_ip", methods=["GET"])
# def get_my_ip():
#     return jsonify({'ip': request.remote_addr}), 200


@app.route('/registration', methods=['POST'])
def func_registration():
    # ip =
    username = request.form['username']
    password = request.form['password']
    print(username, password, request.environ['REMOTE_ADDR'])

    con = sqlite3.connect('Users.db')
    cur = con.cursor()
    cur.execute('SELECT username FROM Users WHERE username = ?', (username,))
    users = cur.fetchall()
    print(users)
    if not users:
        cur.execute('INSERT INTO Users (username, password) VALUES (?, ?)',
                    (username, generate_password_hash(password)))
        cur.execute('INSERT INTO Login (ip, username) VALUES (?, ?)',
                    (request.environ['REMOTE_ADDR'], username))
        con.commit()
        return redirect("/model", code=302)
    else:
        return redirect("/model", code=302)

    # if username == "2":
    #     # return render_template('login.html')
    #     return redirect("/login", code=302)
    # else:
    #     return render_template('registration.html')
    # return render_template('registration.html')


@app.route('/registration')
def f0():
    return render_template("chat.html", sample_output='<img class="image" src="/static/images/image.jpg" alt="">')
    # if not login_ip():
    #     return render_template('registration.html')
    # else:
    #     return redirect("/model", code=302)


if __name__ == '__main__':
    app.run(port=8080, host='127.0.0.1')

# con = sqlite3.connect('History.db')
# cur = con.cursor()
#
# cur.execute('DELETE FROM text')
# con.commit()

# # Сохраняем изменения и закрываем соединение
# con.commit()
con.close()
