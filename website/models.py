#from enum import unique
from website import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import Column, Integer, String, Table
from datetime import datetime
import base64
#from sqlalchemy.orm import declarative_base

#Base = declarative_base()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable= False)
    password = db.Column(db.String(255))
    username = db.Column(db.String(150), unique=True, nullable = False)
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    date_of_birth = db.Column(db.Date, nullable=True)
    gender = db.Column(db.String(150), nullable=True)
    phone_no = db.Column(db.String(150), nullable=True)
    home_address = db.Column(db.String(150), nullable=True)
    qr_code = db.Column(db.String(255)) # Column to store QR code data

    def __init__(self, username, email, password, qr_code, first_name, last_name, date_of_birth, gender,phone_no,home_address ):
        self.username = username
        self.email = email
        self.password = password
        self.qr_code = qr_code
        self.first_name = first_name
        self.last_name = last_name
        self.date_of_birth = date_of_birth
        self.gender = gender
        self.home_address = home_address
        self.phone_no = phone_no
        self.date_of_birth = date_of_birth

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'gender':self.gender,
            'home_address':self.home_address,
            'phone_no':self.phone_no,
            'date_of_birth': self.date_of_birth.isoformat() if self.date_of_birth else None,
            'qr_code': base64.b64encode(self.qr_code).decode('utf-8') if self.qr_code else None
        }       



# Define the Session model
class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False)

    # Define the many-to-many relationship with users
    users = db.relationship('User', secondary='session_users', backref=db.backref('sessions', lazy='dynamic'))        


# Define the association table for the many-to-many relationship
session_users = db.Table('session_users',
    db.Column('session_id', db.Integer, db.ForeignKey('session.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('date', db.DateTime, nullable=True)
)

# Define a model for the secondary database
class Product(db.Model):
    __bind_key__ = 'bind_name_1'
    __tablename__ = 'TempmsProduct'
    # Define model fields here
    Id = db.Column(db.Integer, primary_key=True)
    ProductCode = db.Column(db.String(80), unique=False)
    ItemName = db.Column(db.String(80), unique=False)
    GenericName = db.Column(db.String(100), unique=False)
    GenericNameUpdated = db.Column(db.String(100), unique=False)
    BasicUnit = db.Column(db.Numeric(18, 4), unique=False)
    GenericRatio = db.Column(db.String(100), unique=False)
    StorageCondition = db.Column(db.String(100), unique=False)
    IvedexGenericCode = db.Column(db.String(100), unique=False)
    NHLMISGenericParent = db.Column(db.String(100), unique=False)
    InventoryConversionFactor = db.Column(db.Numeric(18, 4), unique=False)
    Volume = db.Column(db.Numeric(18, 4), unique=False)
    Weight = db.Column(db.Numeric(18, 4), unique=False)
    PriceDollar = db.Column(db.Numeric(18, 4), unique=False)
    Program = db.Column(db.String(100), unique=False)
    ProductGroup = db.Column(db.String(100), unique=False)
