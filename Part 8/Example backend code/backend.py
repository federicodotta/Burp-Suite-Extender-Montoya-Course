import flask
from flask import request

import sqlite3
import socket
import requests

app = flask.Flask(__name__)

@app.route('/', methods=['GET'])
def handle_request():

    name = request.args.get('name')
    url = request.args.get('url')

    if name:

        dbfile = 'test.db'
        con = sqlite3.connect(dbfile)

        cur = con.cursor()

        cur.execute("SELECT * FROM items WHERE name='" + name + "';")
        items = cur.fetchall();
        
        con.close()

        return items;

    else:

        if url:

            # Emulate egress filtering
            #addr = socket.gethostbyname(url.replace("http://",""))
            #return addr

            r = requests.get(url = url)
            return r.text

        else:

            return "Missing parameters";
    

app.run(host="127.0.0.1", port=5000, debug=True)