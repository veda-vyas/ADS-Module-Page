# ADS-Module-Page

## To Run the project clone this repository and open a terminal and run the following
```
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## If you don't have PostgreSQL installed on your machine, do the following (Ubuntu specific)
```
sudo nano /etc/apt/sources.list.d/pgdg.list
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc
sudo apt-key add -
sudo apt-get update
sudo apt-get install postgresql-9.6
```

## To start and create a new database
```
sudo -i -u postgres
psql
(In psql cli)
create database module_page
```

## If you have not created the database tables or database schema is modified, do below steps to re-create it. 
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
