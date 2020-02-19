from flask import Flask
from config import Config

q_chat_client = Flask(__name__)
q_chat_client.config.from_object(Config)

from q_chat_client import routes
