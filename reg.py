# import os
#
# from flask import Flask, render_template, request, url_for, redirect, flash
# from gigachat import GigaChat
# from bs4 import BeautifulSoup
# import base64
# import json
# import requests
# import uuid
#
# app = Flask(__name__)
#
# auth = 'ZGIwZmJmZGYtZThiMi00MDI0LTg4YTUtYjU0YTg5NDc3Y2FkOmQ4ZDg0ZWE4LWJjMmUtNGZhNi05YWM4LWRlODgxZDgzZmI2Yg=='
# secret = 'd8d84ea8-bc2e-4fa6-9ac8-de881d83fb6b'
# client_id = 'db0fbfdf-e8b2-4024-88a5-b54a89477cad'
#
#
# def get_token(auth_token, scope='GIGACHAT_API_PERS'):
#     """
#       Выполняет POST-запрос к эндпоинту, который выдает токен.
#
#       Параметры:
#       - auth_token (str): токен авторизации, необходимый для запроса.
#       - область (str): область действия запроса API. По умолчанию — «GIGACHAT_API_PERS».
#
#       Возвращает:
#       - ответ API, где токен и срок его "годности".
#       """
#     # Создадим идентификатор UUID (36 знаков)
#     rq_uid = str(uuid.uuid4())
#
#     # API URL
#     url = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
#
#     # Заголовки
#     headers = {
#         'Content-Type': 'application/x-www-form-urlencoded',
#         'Accept': 'application/json',
#         'RqUID': rq_uid,
#         'Authorization': f'Basic {auth_token}'
#     }
#
#     # Тело запроса
#     payload = {
#         'scope': scope
#     }
#
#     try:
#         # Делаем POST запрос с отключенной SSL верификацией
#         # (можно скачать сертификаты Минцифры, тогда отключать проверку не надо)
#         response = requests.post(url, headers=headers, data=payload, verify=False)
#         return response
#     except requests.RequestException as e:
#         print(f"Ошибка: {str(e)}")
#         return -1
#
#
# def send_chat_request(giga_token, user_message):
#     """
#     Отправляет POST-запрос к API GigaChat для получения ответа от модели чата.
#
#     Параметры:
#     - giga_token (str): Токен авторизации для доступа к API GigaChat.
#     - user_message (str): Сообщение пользователя, которое будет обработано моделью GigaChat.
#
#     Возвращает:
#     - str: Строка сгенерированного ответа GigaChat с тэгом img
#     """
#     # URL API для отправки запросов к GigaChat
#     url = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"
#
#     # Заголовки для HTTP-запроса
#     headers = {
#         'Content-Type': 'application/json',  # Указываем, что отправляемые данные в формате JSON
#         'Authorization': f'Bearer {giga_token}',  # Используем токен авторизации для доступа к API
#     }
#
#     # Данные для отправки в теле запроса
#     payload = {
#         "model": "GigaChat:latest",  # Указываем, что хотим использовать последнюю версию модели GigaChat
#         "messages": [
#             {
#                 "role": "user",  # Роль отправителя - пользователь
#                 "content": user_message  # Сообщение от пользователя
#             },
#         ],
#         "temperature": 0.7  # Устанавливаем температуру, чтобы управлять случайностью ответов
#     }
#
#     try:
#         # Отправляем POST-запрос к API и получаем ответ
#         response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
#         # Выводим текст ответа. В реальных условиях следует обрабатывать ответ и проверять статус коды.
#         print(response.json())
#         return response.json()["choices"][0]["message"]["content"]
#     except requests.RequestException as e:
#         # В случае возникновения исключения в процессе выполнения запроса, выводим ошибку
#         print(f"Произошла ошибка: {str(e)}")
#         return None
#
#
# @app.route('/text', methods=["POST", "GET"])
# def text():
#     if request.method == 'POST':
#         text_input = request.form['text_label']
#
#         if text_input:
#             print(text_input)
#             # output = text_input
#
#             with GigaChat(
#                     credentials=auth,
#                     verify_ssl_certs=False) as giga:
#                 response = giga.chat(text_input)
#                 output = response.choices[0].message.content
#
#         return render_template("text.html", sample_output=output, sample_input=text_input)
#     else:
#         return render_template("text.html")
#
#
# @app.route('/image', methods=["POST", "GET"])
# def image():
#     if request.method == 'POST':
#         text_input = request.form['text_label']
#
#         # if text_input:
#         #     print(text_input)
#         #     image_filename = os.path.join(app.config['UPLOAD_FOLDER'], 'image.jpg')
#
#         response = get_token(auth)
#         if response != 1:
#             # print(response.text)
#             giga_token = response.json()['access_token']
#
#         user_message = text_input
#         response_img_tag = send_chat_request(giga_token, user_message)
#         # print(response_img_tag)
#
#         # Парсим HTML
#         soup = BeautifulSoup(response_img_tag, 'html.parser')
#
#         # Извлекаем значение атрибута `src`
#         img_src = soup.img['src']
#
#         # print(img_src)
#
#         headers = {
#             'Content-Type': 'application/json',
#             'Authorization': f'Bearer {giga_token}',
#         }
#
#         response = requests.get(f'https://gigachat.devices.sberbank.ru/api/v1/files/{img_src}/content', headers=headers,
#                                 verify=False)
#
#         with open('static/images/image.jpg', 'wb') as f:
#             f.write(response.content)
#         return render_template("image.html", sample_input=text_input)
#     else:
#         return render_template("image.html")
#
#     # if request.method == 'POST':
#     #     text_input = request.form['text_label']
#     #
#     #     if text_input:
#     #         print(text_input)
#     #         image_filename = os.path.join(app.config['UPLOAD_FOLDER'], 'image.jpg')
#     #
#     #     return render_template("image.html", sample_input=text_input, user_image=image_filename)
#     # else:
#     #     return render_template("image.html")
#
#
# if __name__ == "__main__":
#     app.run()

import sqlite3

connection = sqlite3.connect('History.db')
cursor = connection.cursor()

# cursor.execute('INSERT INTO History (text) VALUES (?)', ('promt',))

cursor.execute('SELECT text FROM History')
texts = cursor.fetchall()

# Выводим результаты
for text in texts:
    print(text[0])
