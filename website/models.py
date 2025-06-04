#from enum import unique
from unicodedata import numeric
from website import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import Column, Integer, String, Table
from datetime import datetime
import base64
from sqlalchemy import DateTime
from datetime import datetime, timezone
#from sqlalchemy.orm import declarative_base

#Base = declarative_base()

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))


    def __init__(self, name, description=None):
        self.name = name
        self.description = description

    def __repr__(self):
        return f'<Role {self.name}>'
    
    
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)    


class User(db.Model, UserMixin):
    __tablename__ = 'user'
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

     # New fields for first-timer tracking
    is_first_timer = db.Column(db.Boolean, default=False, nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Define the relationship with roles
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))


    def __init__(self, username, email, password, qr_code, first_name, last_name, 
                 date_of_birth, gender, phone_no, home_address, is_first_timer=True,date_joined=None):
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
        self.is_first_timer = is_first_timer
        self.date_joined = date_joined

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
            'qr_code': base64.b64encode(self.qr_code).decode('utf-8') if self.qr_code else None,
            'roles': [role.name for role in self.roles],
            'is_first_timer': self.is_first_timer,
            'date_joined': self.date_joined.isoformat() if self.date_joined else None
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



class Item(db.Model):
    __tablename__ = 'item'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    custodian_unit = db.Column(db.String(100))
    date_of_purchase = db.Column(db.Date, default=datetime.utcnow)
    amount = db.Column(db.Numeric(18, 2), nullable=True)  # Modify the datatype if necessary
    quantity = db.Column(db.Integer, nullable=False, default=1)  # New quantity field

    # Relationship with Maintenance and Inventory
    maintenance = db.relationship('Maintenance', backref='item', lazy=True)
    inventory = db.relationship('Inventory', backref='item', lazy=True)



class Maintenance(db.Model):
    __tablename__ = 'maintenance'

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    maintenance_description = db.Column(db.String(255))
    maintenance_vendor = db.Column(db.String(100))
    date = db.Column(db.Date, default=datetime.utcnow)
    amount = db.Column(db.Numeric(18, 2), nullable=True)  # Modify the datatype if necessary

    # Add a unique constraint to prevent duplicates
    __table_args__ = (
        db.UniqueConstraint('item_id', 'maintenance_description', 'date', name='unique_maintenance_record'),
    )



class Inventory(db.Model):
    __tablename__ = 'inventory'

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    positive_adjustment = db.Column(db.Integer, default=0)
    negative_adjustment = db.Column(db.Integer, default=0)
    description = db.Column(db.String(255))



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
