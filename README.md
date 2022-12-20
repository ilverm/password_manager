# Password Manager

## Setup

First clone the repository:

```sh
$ git clone https://github.com/ilverm/password_manager.git
$ cd password_manager
```

Create a virtual environment:

```sh
$ python3 -m venv venv
$ source venv/bin/activate
```

And install the dependencies:

```sh
(venv)$ python -m pip install requirements.txt
```

Once `pip` has finished downloading the dependencies:

```sh
(venv)$ python manage.py runserver
```

And navigate to `http://127.0.0.1/`
