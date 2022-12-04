import requests
from app import app

with app.test_request_context():
    BASE = "http://127.0.0.1:5000/"
    loginForm = {"username": "test", "password": "1234567890"}
    login_response = requests.post(BASE + "login", data=loginForm)
    print("Login Test Response:")
    print(login_response)
    prime_response = requests.get(BASE + "prime/11", data=loginForm)
    print("Prime Test Response:")
    print(prime_response.text)