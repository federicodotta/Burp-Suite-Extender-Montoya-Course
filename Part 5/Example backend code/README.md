# Part 5 - Backend code

To run the example backend simply install the python requirements and then run the **backend.py** file.

The procedure to run the backend in a python virtual environment is the following one:

```bash
cd "./Burp-Suite-Extender-Montoya-Course/Part 4/Example backend code"
python -m venv montoya_venv
source montoya_venv/bin/activate
pip install -r ./requirements.txt
python ./backend.py
```

And then press CTRL+C to kill the Flask python server and leave the virtual environment with:

```bash
deactivate
```