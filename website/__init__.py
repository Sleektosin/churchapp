#from website.models import User
#from .models import Userss
#from .models import Userss
from unittest.mock import Base
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from datetime import timedelta
from sqlalchemy.ext.automap import automap_base
from flask_login import UserMixin
from flask_migrate import Migrate
import os
# ffrom website.models import User

import pandas as pd
from sqlalchemy import create_engine
import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from flask_mail import Mail
import logging
from logging.handlers import RotatingFileHandler
from flask_restx import Api
from .config import Config


mail = Mail()
api =  Api()

db = SQLAlchemy()
#db_ = SQLAlchemy()
DB_NAME = "Sleektech.db"

# --------------------------------


# ------------------------------------

#server_ = 'ghsc.database.windows.net'
#database_ = 'psm'
#username_ = 'stosin'
#password_ = 'E0bhuk1t2r2sjcpslw3t'
#driver_ = '{ODBC Driver 17 for SQL Server}'
#driver__ = "ODBC+Driver+17+for+SQL+Server"
# 'database_con = f'mssql+pyodbc://{username_}:{password_}@{server_}/{database_}?driver={driver__}'

#engine_ = create_engine(database_con)
#connn = engine_.connect()

# -----------------Connection to mysql------------

"""
app__ = Flask(__name__)
app__.config['SECRET_KEY'] = 'fgttxtyuytxouioy ytuyutfutttty'
app__.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/test'
app__.config['SQLALCHEMY_TRACK_MODIFCATIONS'] = False
db_ = SQLAlchemy(app__)

db_.init_app(app__)


class Userss(db_.Model):
    id = db_.Column(db_.Integer, primary_key=True)
    username = db_.Column(db_.String(150), unique=True)
    email = db_.Column(db_.String(150), unique=True)
    password = db_.Column(db_.String(150))

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

#db_.app = app__


db_.create_all(app__)
"""

# -----------------Connect to Sql Server-----------------
server_ = 'PSM-NG-0003259'
database_ = 'AdventureWorksDW2019'
username_ = 'sa'
password_ = 'Sleektech@2375#'
#driver_ = '{ODBC Driver 17 for SQL Server}'
driver__ = "ODBC+Driver+17+for+SQL+Server"
database_con = f'mssql+pyodbc://{username_}:{password_}@{server_}/{database_}?driver={driver__}'


engine2 = create_engine(database_con, echo=True)


# def connect_to_product():
#     app = Flask(__name__)
#     app.config['SECRET_KEY'] = 'gsghhjlmpoprfe afdttrgragagesgtgstr'
#     server_ = 'PSM-NG-0003259'
#     database_ = 'AdventureWorksDW2019'
#     username_ = 'sa'
#     password_ = 'Sleektech@2375#'
#     #driver_ = '{ODBC Driver 17 for SQL Server}'
#     driver__ = "ODBC+Driver+17+for+SQL+Server"
#     database_con = f'mssql+pyodbc://{username_}:{password_}@{server_}/{database_}?driver={driver__}'
#     app.config['SQLALCHEMY_DATABASE_URI'] = database_con
#     app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
#     db = SQLAlchemy(app)
#     db.init_app(app)
#     Base = automap_base()
#     Base.prepare(db.engine, reflect=True)
#     product = Base.classes.TempmsProduct
#     #metadata = db.MetaData()
#     #product = db.Table('TempmsProduct', metadata,autoload=True, autoload_with=db.engine)
#     results = db.session.query(product).all()
#     return results

#Base = automap_base()
#Base.prepare(db.engine, reflect=True)
#product = Base.classes.TempmsProduct

# reflection method
# product = db.Table('TempmsProduct', db.metadata,
 #                  autoload=True, autoload_with=db.engine)

#results = db.session.query(product).all()

# for r in results:
#    print(r.GenericNameUpdated)


# ------------------------------------


def create_app():   
    app = Flask(__name__)
    app.config['SESSION_PERMANENT'] = False
    app.config['SECRET_KEY'] = 'gsghhj afdttrgragagesgtgstr'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    # app.config['SQLALCHEMY_BINDS'] = {
    #     'bind_name_1': 'mssql+pyodbc://sa:Sleektech@2375#@DESKTOP-ORK9FHS/AdventureWorksDW2019?driver=ODBC+Driver+17+for+SQL+Server',}
    # Flask-Mail configuration for Gmail
    # app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    # app.config['MAIL_PORT'] = 587
    # app.config['MAIL_USE_TLS'] = True
    # app.config['MAIL_USE_SSL'] = False
    # app.config['MAIL_USERNAME'] = 'tosinsleek01@gmail.com'
    # app.config['MAIL_PASSWORD'] = 'ugqm eupj ikts asom'
    # app.config['MAIL_DEFAULT_SENDER'] = 'tosinsleek01@gmail.com'

    # # Configure logging
    # # Configure logging
    # if not app.debug:
    #     log_dir = os.path.join(os.getcwd(), 'logs')
    #     if not os.path.exists(log_dir):
    #         os.makedirs(log_dir)

    #     file_handler = RotatingFileHandler(os.path.join(log_dir, 'flask_mail.log'), maxBytes=10240, backupCount=10)
    #     file_handler.setFormatter(logging.Formatter(
    #         '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    #     ))
    #     file_handler.setLevel(logging.INFO)

    #     app.logger.addHandler(file_handler)
    #     app.logger.setLevel(logging.INFO)
    #     app.logger.info('Flask Mail startup')


    mail.init_app(app)
    db.init_app(app)
    api.init_app(app)
    migrate = Migrate(app, db)

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')


    from .models import User,Session

    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = 'views.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app



def create_database(app):
    with app.app_context():
        database_path = 'website/' + DB_NAME        
        if path.exists(database_path):
            db.create_all()
            #db.create_all(bind='bind_name_1')
            print('Database Created!!!')


