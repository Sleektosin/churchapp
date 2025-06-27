#from enum import unique
from unicodedata import numeric
from website import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy import Column, Integer, String, Table
from datetime import datetime
import base64
from sqlalchemy import DateTime
from datetime import datetime, timezone,date, time, timedelta
import uuid
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
    email = db.Column(db.String(150), unique=True, nullable= True)
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
    attendances = db.relationship('Attendance', back_populates='user')


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
    """
    Enhanced Session model for scalable attendance tracking
    """
    # Basic session information
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

    # Scheduling fields
    date = db.Column(db.Date, nullable=False)   # When session happens
    start_time = db.Column(db.Time)             # Session start time
    end_time = db.Column(db.Time)               # Session end time
    location = db.Column(db.String(200))        # Where session happens 

    # Capacity management
    max_capacity = db.Column(db.Integer)        # Maximum attendees allowed

    # QR Code and self-service fields
    qr_code = db.Column(db.String(255), unique=True, nullable=False)  # Unique QR identifier
    qr_expires_at = db.Column(db.DateTime)                       # Optional QR expiration
    allow_self_checkin = db.Column(db.Boolean, default=True)     # Enable/disable self check-in

    # Check-in window settings
    checkin_opens_minutes = db.Column(db.Integer, default=30)    # Minutes before start time
    checkin_closes_minutes = db.Column(db.Integer, default=15)   # Minutes after start time
    
    # Session lifecycle management
    status = db.Column(db.String(20), default='scheduled')       # scheduled, active, completed, cancelled
    
    # Audit trail
    created_at = db.Column(db.DateTime, default=datetime.utcnow) # When record was created
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


    # Define the many-to-many relationship with users
    users = db.relationship('User', secondary='session_users', backref=db.backref('sessions', lazy='dynamic'))   
    attendances = db.relationship('Attendance', backref='session_ref', lazy='dynamic', cascade='all, delete-orphan')    

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Auto-generate QR code if not provided
        if not self.qr_code:
            self.qr_code = str(uuid.uuid4()) 

    @property
    def qr_code_url(self):
        """Generate the full URL for QR code scanning"""
        return f"https://churchapp-8ael.onrender.com/checkin/{self.qr_code}"  


    def is_checkin_open(self):
        """Check if check-in window is currently open"""
        if not self.start_time or not self.date:
            return False
            
        session_datetime = datetime.combine(self.date, self.start_time)
        now = datetime.now()
        
        checkin_opens = session_datetime - timedelta(minutes=self.checkin_opens_minutes)
        checkin_closes = session_datetime + timedelta(minutes=self.checkin_closes_minutes)
        
        return checkin_opens <= now <= checkin_closes 


    def get_attendance_count(self):
        """Get current number of attendees"""
        return self.attendances.filter_by(status='present').count()     
    

    def is_at_capacity(self):
        if not self.max_capacity:
            return False
        return self.get_attendance_count() >= self.max_capacity


    def __repr__(self):
        return f'<Session {self.name} - {self.date}>'  



class Attendance(db.Model):
    """
    Enhanced Attendance model for detailed tracking
    """
    __tablename__ = 'attendances'
    
    # Primary keys and relationships
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    
    # Attendance status and method
    status = db.Column(db.String(20), default='present')          # present, absent, late, left_early
    check_in_method = db.Column(db.String(30), default='qr_scan') # qr_scan, admin_add, manual, self_checkin
    
    # Timing information
    check_in_time = db.Column(db.DateTime, default=datetime.utcnow)  # When user checked in
    check_out_time = db.Column(db.DateTime)                       # When user checked out (optional)
    
    # Security and tracking
    ip_address = db.Column(db.String(45))                         # IP address for web check-ins
    user_agent = db.Column(db.String(500))                        # Browser/device info

    
    # Additional information
    notes = db.Column(db.Text)                                    # Admin notes about attendance
    verified_by_admin = db.Column(db.Boolean, default=False)      # Manual verification flag
    
    # Audit trail
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # When attendance record was created
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='attendances_ref')
    session = db.relationship('Session', backref='attendances_ref')
    
    # Unique constraint - one attendance record per user per session
    __table_args__ = (
        db.UniqueConstraint('user_id', 'session_id', name='unique_user_session_attendance'),
    )
    
    def get_duration_minutes(self):
        """Calculate attendance duration in minutes"""
        if not self.check_out_time:
            return None
        delta = self.check_out_time - self.check_in_time2
        return int(delta.total_seconds() / 60)
    
    def was_on_time(self):
        """Check if user checked in on time"""
        if not self.session.start_time or not self.session.date:
            return None
        
        session_start = datetime.combine(self.session.date, self.session.start_time)
        return self.check_in_time <= session_start
    
    def __repr__(self):
        return f'<Attendance {self.user.name} - {self.session.name}>'          


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
