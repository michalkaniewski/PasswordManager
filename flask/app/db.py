from app import app
from flaskext.mysql import MySQL
from dotenv import load_dotenv
from os import getenv

mysql = MySQL()

# MySQL configurations
load_dotenv()
app.config['MYSQL_DATABASE_USER'] = getenv('MYSQL_DATABASE_USER')
app.config['MYSQL_DATABASE_PASSWORD'] = getenv('MYSQL_DATABASE_PASSWORD')
app.config['MYSQL_DATABASE_DB'] = getenv('MYSQL_DATABASE_DB')
app.config['MYSQL_DATABASE_HOST'] = getenv('MYSQL_DATABASE_HOST')
mysql.init_app(app)