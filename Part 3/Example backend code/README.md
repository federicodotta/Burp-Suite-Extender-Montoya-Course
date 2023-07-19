# Part 3 - Backend code

The backend of this example is one of the examples of the [Flask-SocketIO project](https://github.com/miguelgrinberg/Flask-SocketIO/tree/main/example), with some minor modifications. The default configuration has been changed to use the WebSocket (Flask-SocketIO can work also using HTTP request/responses), some ping/pong WebSocket messages have been removed (to make the analysis simpler) and a signature has been added to one of the exchanged messages (see the article for more details).

To run the example backend simply install the python requirements and then run the **app.py** file.

The procedure to run the backend in a python virtual environment is the following one:

```bash
cd "./Burp-Suite-Extender-Montoya-Course/Part 3/Example backend code"
python -m venv montoya_venv
source montoya_venv/bin/activate
pip install -r ./requirements.txt
python ./app.py
```

Please note that this backend does not print any output when it is started. You can reach the application using the browser at http://localhost:5000/.

TO kill the Flask python server press CTRL+C and then leave the virtual environment with:

```bash
deactivate
```