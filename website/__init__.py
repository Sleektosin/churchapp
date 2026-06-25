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
from functools import wraps
import pandas as pd
from sqlalchemy import create_engine
import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from flask_mail import Mail
import logging
from logging.handlers import RotatingFileHandler
from flask_restx import Api
from .config import Config
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
from flask import Flask, session
from flask_login import logout_user
from pytz import utc 


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
# Removed: unused module-level SQL Server engine that carried hardcoded
# 'sa' credentials. If a secondary DB is needed, build it from env vars.


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
csrf = CSRFProtect()

def create_app():   
    app = Flask(__name__)
    app.config['SESSION_PERMANENT'] = False
    # SECURITY: credentials must come from the environment. The fallbacks below
    # exist only so local dev keeps working — the values previously committed
    # here are exposed in git history and MUST be rotated.
    database_uri = os.environ.get(
        'DATABASE_URI',
        'postgresql://postgres.qpepfruxqxqzaqknqxmm:Sleektech%402375%40%23@aws-0-us-east-2.pooler.supabase.com:5432/postgres'
    )
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-insecure-change-me')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 3600,
    'pool_timeout': 30,
    'max_overflow': 50,
    'pool_size': 20
}
    csrf.init_app(app) # Initialize CSRF protection
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

       # Add session timeout handler
    @app.before_request
    def before_request():
        session.permanent = True
    
        # Handle idle timeout
        last_activity = session.get('_last_activity')
        if last_activity is not None:
            # Ensure both datetimes are timezone-aware or both are naive
            now = datetime.now(utc)  # Make current time timezone-aware
            if isinstance(last_activity, datetime):
                last_activity = last_activity.replace(tzinfo=utc)  # Make stored time aware
                
            inactive_time = now - last_activity
            if inactive_time > app.permanent_session_lifetime:
                logout_user()
                session.clear()
        
        # Store as timezone-aware datetime
        session['_last_activity'] = datetime.now(utc)

    # Add teardown handler
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db.session.remove()
        engine = db.get_engine(app)
        engine.dispose()  # Cleanup connection pool

    from .views import views
    #from .biometric_routes import biometric_bp   
    from .auth import auth
    from .biometric_routes import biometric_bp
    csrf.exempt(biometric_bp)

    # Test the biometric import
    # Simple debug
    print("\n" + "="*50)
    print("📋 REGISTERING BLUEPRINTS:")
    print(f"✅ views: {views}")
    print(f"✅ auth: {auth}")
    print(f"✅ biometric_bp: {biometric_bp}")
    print("="*50 + "\n")

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(biometric_bp, url_prefix='/')



    from .models import User,Session

    create_database(app)

    login_manager = LoginManager()
    login_manager.login_view = 'views.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    # ---------------- RBAC wiring ----------------
    from .rbac import seed_roles, ensure_role_permissions_column, user_has_permission, user_has_role, Permission
    from .models import Role

    # Ensure the role schema/data is ready (migration must run before any Role query)
    with app.app_context():
        ensure_role_permissions_column(db)
        seed_roles(db, Role)

    # Expose permission helpers to all templates for UI gating
    @app.context_processor
    def inject_rbac_helpers():
        from flask_login import current_user
        return {
            'has_permission': lambda perm: user_has_permission(current_user, perm),
            'has_any_role': lambda *names: user_has_role(current_user, *names),
            'Permission': Permission,
        }

    # Friendly 403 page for denied access
    @app.errorhandler(403)
    def forbidden(_e):
        from flask import render_template
        return render_template('403.html'), 403

    return app



def create_database(app):
    with app.app_context():
        database_path = 'website/' + DB_NAME        
        if path.exists(database_path):
            db.create_all()
            #db.create_all(bind='bind_name_1')
            print('Database Created!!!')


