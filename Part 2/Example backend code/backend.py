import flask
from flask import request
from hashlib import sha256

app = flask.Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def handle_request():
    hash = request.headers.get('Hash')
    body = request.get_data()
    calculated_hash = sha256(body).hexdigest()
    if(hash.strip() == calculated_hash):
        data = request.form.get('data')
        return data
    else:
        return("Invalid signature!")

app.run(host="127.0.0.1", port=5000, debug=True)