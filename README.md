# ADS-Module-Page

## To Run the project clone this repository and open a terminal and run the following

```
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## If you have not created the database or database schema is modified, do below steps to re-create it. 

```
    python
    from main import db
    db.create_all()
```

Make sure that ssl.key and ssl.crt are created, then run

```
python main.py
```

Now access
https://localhost:5000 
to see the Homepage.
