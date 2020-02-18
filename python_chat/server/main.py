import etcd
import time
import re

from passlib.hash import sha256_crypt

from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from logging.config import dictConfig

import pika

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)

client = etcd.Client(port=2379)

@app.route('/register', methods=['POST'])
def register():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=username)

    password_hash = sha256_crypt.encrypt(password)
    
    client.write('/users/' + username + '/status', "ONLINE")
    client.write('/users/' + username + '/last_activity', int(time.time()))
    client.write('/users/' + username + '/last_heartbeat', int(time.time()))
    client.write('/users/' + username + '/hash', password_hash)
    client.write('/users/' + username + '/token', access_token)

    client.write('/hashes/' + password_hash, username)
    client.write('/tokens/' + access_token, username)

    return jsonify(access_token=access_token), 200

# @app.route('/login', methods=['POST'])
# def login():

@app.route("/whoami", methods=['GET'])
@jwt_required
def whoami():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route("/users")
#@jwt_required
def get_users():
    etcd_users = client.read("/users/", sorted=True)
    users = []
    for child in etcd_users.children:
        u = re.search("/users/(.*)", child.key)
        if u:
            users.append({"username": u.group(1)})
    return jsonify(users)

@app.route("/chat")
@jwt_required
def send_message_to():
    current_user = get_jwt_identity()
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    message = request.json.get('msg', None)
    dest_user = request.json.get('user', None)
    if not message:
        return jsonify(error="Missing msg parameter"), 400
    if not dest_user:
        return jsonify(error="Missing user parameter"), 400
    if dest_user not in _get_users():
        return jsonify(error="User not registered"), 404

    channel.queue_declare(queue=dest_user)
    app.logger.info('Message sent from %s: "%s" to %s', current_user, message, dest_user)
    channel.basic_publish(exchange='',
                      routing_key=dest_user,
                      body="{}: {}".format(current_user, message))
    return jsonify(status="OK"), 200

@app.route("/check_messages")
@jwt_required
def receive_messages():
    current_user = get_jwt_identity()
    channel.queue_declare(queue=current_user)

    messages = {}

    method_frame, header_frame, body = channel.basic_get(current_user)
    if not method_frame:
        app.logger.info('No message returned')
        return jsonify(msg="No new messages")
    else:
        while method_frame:
            app.logger.info("{} | {} | {}".format(method_frame, header_frame, body))
            messages[method_frame.delivery_tag]=body
            channel.basic_ack(method_frame.delivery_tag)
            method_frame, header_frame, body = channel.basic_get(current_user)
    
    return jsonify(messages=messages)


def _get_users():
    etcd_users = client.read("/users/", sorted=True)
    users = []
    for child in etcd_users.children:
        u = re.search("/users/(.*)", child.key)
        if u:
            users.append(u.group(1))
    return users