#from crypt import methods
#from crypt import methods
#from crypt import methods
import json
import random
from PIL import Image
import qrcode
import base64
from tabnanny import check
from io import BytesIO, StringIO
from flask import Flask
from sqlalchemy import distinct
from datetime import timedelta
from unicodedata import category
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
import requests
from .models import User, Session,session_users, Role,Item, Maintenance, Attendance 
from website import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from flask_login import LoginManager
import os
from flask import send_from_directory, send_file,abort
from sqlalchemy.ext.automap import automap_base
from . import create_app, mail, api,csrf
from flask_paginate import Pagination, get_page_args
from flask_sqlalchemy import SQLAlchemy
from json2html import json2html
import urllib.parse
import html, re
import csv
import pandas as pd
from flask import Response
from datetime import datetime,date
from sqlalchemy import func
from flask_mail import Message
from flask import current_app
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from flask_restx import Resource
from email.mime.base import MIMEBase
from email import encoders
import traceback
import time
import pytz
import mimetypes  # Import mimetypes module
import smtplib
from email.message import EmailMessage
from email.utils import formataddr
import time
import threading
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
import logging
from sqlalchemy import text
from flask import session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import or_
import uuid
from flask import session as flask_session
from flask_wtf.csrf import CSRFProtect
from collections import defaultdict



views = Blueprint('views', __name__)


######################################################
@api.route('/api', '/api/')
class GetAndPost(Resource):
    # Get all
    def get(self):
        users = User.query.all()
        users_dict = [user.to_dict() for user in users]
        return jsonify(users_dict)
    
    def post(self):
        data = api.payload
        # Generate QR code
        qr_data = f'Username: {data["username"]}\nEmail: {data["email"]}'
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer)
        qr_code_bytes = buffer.getvalue()
        new_user = User(
                email=data["email"],
                first_name=data["first_name"],
                last_name= data["last_name"],
                date_of_birth=datetime.strptime(data["date_of_birth"], '%Y-%m-%d').date(),
                qr_code=qr_code_bytes,
                password=generate_password_hash(data["password"], method='sha256'),
                username=data["username"] 
            )
        db.session.add(new_user)
        db.session.commit() 
        return jsonify(User.query.filter_by(id = data["id"])).to_dict() 
    

    

@api.route('/api/<idx>')
class GetUpdateDelete(Resource):
    # Get one
    def get(self, idx):
        user = User.query.filter_by(id = idx).first()
        user_dict = user.to_dict()
        return jsonify(user_dict) 

#######################################################################

# Function to send email with out QR code
def send_test_email(user_email):
    try:
        msg = Message('Test Email', recipients=[user_email])
        msg.body = "This is a test email."
        
        mail.send(msg)
        current_app.logger.info(f'Test email sent to {user_email}')
        return True
    except Exception as e:
        current_app.logger.error(f'Failed to send test email to {user_email}. Error: {str(e)}')
        return False


#Send email with QR Code
# Global rate limit parameters
RATE_LIMIT = 10  # Max number of emails per minute
RATE_PERIOD = 60  # Time period in seconds
rate_limit_lock = threading.Lock()
emails_sent = 0
start_time = time.time()

def send_email_with_qr(user_email, username, attachment, is_first_timer=False, filename='attachment.png', retries=3, delay=5):
    global emails_sent, start_time
    
    # Define your email parameters
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_user = 'tosinsleek01@gmail.com'
    smtp_password = 'ugqm eupj ikts asom'

    # Create the email message
    msg = EmailMessage()
    msg['From'] = formataddr(('Saka Tosin', smtp_user))
    msg['To'] = user_email
    msg['Subject'] = 'Welcome to Our Service'  # Updated subject line

    # Customize message based on first-timer status
    if is_first_timer:
        msg_body = f"""
        <html>
            <body>
                <h1>Welcome {username}!</h1>
                <p>We're thrilled to have you join our service for the first time!</p>
                <p>Here's your QR code that you can use to access your account:</p>
            </body>
        </html>
        """
    else:
        msg_body = f"""
        <html>
            <body>
                <h1>Welcome back {username}!</h1>
                <p>Thank you for using our service again.</p>
                <p>Here's your updated QR code for your account:</p>
            </body>
        </html>
        """
    
    msg.set_content(msg_body, subtype='html')

    # Handle attachment only if provided
    if attachment:
        # Ensure the attachment is a BytesIO object
        if isinstance(attachment, bytes):
            attachment_io = BytesIO(attachment)
        else:
            attachment_io = attachment

        # Determine the MIME type
        content_type, encoding = mimetypes.guess_type(filename)
        if content_type is None:
            content_type = 'application/octet-stream'
        maintype, subtype = content_type.split('/')

        # Create the MIME part
        mime_part = MIMEBase(maintype, subtype)
        mime_part.set_payload(attachment_io.read())
        encoders.encode_base64(mime_part)
        mime_part.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.add_attachment(mime_part)

    # Rate limiting mechanism
    with rate_limit_lock:
        current_time = time.time()
        if current_time - start_time < RATE_PERIOD:
            if emails_sent >= RATE_LIMIT:
                sleep_time = RATE_PERIOD - (current_time - start_time)
                print(f"Rate limit reached, sleeping for {sleep_time} seconds")
                time.sleep(sleep_time)
                emails_sent = 0
                start_time = time.time()
        else:
            emails_sent = 0
            start_time = current_time

    # Send the email with retries
    for attempt in range(retries):
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            print(f'Email sent to {user_email}')
            with rate_limit_lock:
                emails_sent += 1
            return True
        except smtplib.SMTPException as e:
            print(f'Failed to send email to {user_email} on attempt {attempt + 1}: {e}')
            time.sleep(delay)

    print(f'Failed to send email to {user_email} after {retries} attempts')
    return False





def send_email_with_qr_(user_email, username, qr_code_bytes):
    try:
        message = Mail(
            from_email=current_app.config['MAIL_FROM_EMAIL'],
            to_emails=user_email,
            subject='Your QR Code Attachment',
            html_content=f"<strong>Hello {username},</strong><br><p>Here is your QR code:</p>"
        )
        
        # Encode the QR code as base64
        encoded_qr_code = base64.b64encode(qr_code_bytes).decode()

        # Create the attachment
        attachment = Attachment(
            FileContent(encoded_qr_code),
            FileName('qr_code.png'),
            FileType('image/png'),
            Disposition('attachment')
        )
        message.add_attachment(attachment)
        
        # Send email
        sg = SendGridAPIClient(current_app.config['SENDGRID_API_KEY'])
        response = sg.send(message)
        
        current_app.logger.info(f'Email sent to {user_email}, Status Code: {response.status_code}')
        return True
    except Exception as e:
        current_app.logger.error(f'Failed to send email to {user_email}: {e}')
        return False






# Load favicon


@views.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(views.root_path, 'static'),
                               'uploads/favicon.png', mimetype='image/vnd.microsoft.icon')


def extract_user_info(user_string):
    # Define a regular expression pattern to match username and email
    pattern = r"Username: (.+)\nEmail: (.+)"

    # Execute the regular expression pattern on the input string
    match = re.search(pattern, user_string)

    if match:
        # Extracted username is at group 1 and email is at group 2
        username = match.group(1)
        email = match.group(2)
        return email
    else:
        # Return None if the pattern did not match
        return None, None
    





@views.route('/barcodelogin')
def barcodelogin():
    return render_template('loginn.html')



@views.route('/addUsersToSession/<id>', methods=['GET', 'POST'])  
@csrf.exempt
def addUsersToSession_handler(id):
    session = Session.query.get(id)
    if not session:
        flash('Session not found.', 'error')
        return render_template('adduserstosession.html', user=current_user, session_data=session)

    returned_qr_code = request.form.get('qr_code')
    email = extract_user_info(returned_qr_code)
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('User not found.', 'error')
        return render_template('adduserstosession.html', user=current_user, session_data=session)

    # Check if attendance record already exists using the unique constraint
    existing_attendance = Attendance.query.filter_by(
        session_id=session.id, 
        user_id=user.id
    ).first()

    if existing_attendance:
        # Update existing record instead of creating new one
        existing_attendance.status = 'present'
        existing_attendance.check_in_method = 'qr_scan'
        existing_attendance.check_in_time = datetime.utcnow()
        existing_attendance.updated_at = datetime.utcnow()
        
        db.session.commit()
        flash('User attendance updated successfully!', 'success')
    else:
        try:
            # Create new attendance record
            new_attendance = Attendance(
                user_id=user.id,
                session_id=session.id,
                status='present',
                check_in_method='qr_scan',
                check_in_time=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            db.session.add(new_attendance)
            db.session.commit()
            flash('User added to session successfully!', 'success')
            
        except IntegrityError:
            db.session.rollback()
            # Handle race condition where record might have been created by another process
            flash('User is already in this session.', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding user to session: {str(e)}', 'error')

    return render_template('adduserstosession.html', user=current_user, session_data=session)
        

# adding maintenance to product
@views.route('/addMaintenanceToProduct/<id>', methods=['POST'])  
@csrf.exempt
@login_required
def addMaintenanceToProduct(id):
    # Fetch the selected product details
    product = db.session.query(
        Item.id,
        Item.name,
        Item.description,
        Item.manufacturer,
        Item.model,
        Item.custodian_unit,
        Item.date_of_purchase,
        Item.amount
    ).filter_by(id=id).first()
    
    if product:
        maintenance_description = request.form.get('maintenance_description')
        maintenance_vendor = request.form.get('maintenance_vendor')
        maintenance_date = request.form.get('maintenance_date')
        date_of_maintenance = datetime.strptime(maintenance_date, '%Y-%m-%d').date()
        maintenance_amount = request.form.get('maintenance_amount')

        # Ensure all required fields are provided
        if not (maintenance_description and maintenance_vendor and maintenance_date and maintenance_amount):
            return jsonify({'error': 'All fields are required.'}), 400

        try:
            # Create a new Maintenance record
            new_maintenance = Maintenance(
                item_id=id,
                maintenance_description=maintenance_description,
                maintenance_vendor=maintenance_vendor,
                date=date_of_maintenance,
                amount=maintenance_amount
            )

            # Add the new maintenance record to the session and commit to the database
            db.session.add(new_maintenance)
            db.session.commit()

            flash('Record added successfully!', 'success')
            return render_template('maintenance.html', user=current_user, product=product)

        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            return jsonify({'error': f'Error occurred while creating maintenance record: {str(e)}'}), 500
    else:
        flash('Product does not exist!', 'error')
        return render_template('maintenance.html', user=current_user, product=product)



@views.route('/logging', methods=['POST'])
def logging_handler():
    returned_qr_code = request.form.get('qr_code')
    email = extract_user_info(returned_qr_code)
    user = User.query.filter_by(email=email).first()  
    if user:
        flash('Logged in successfully!', category='success')
        login_user(user, remember=True)
        return redirect(url_for('views.session'))
    else:
        # Show error message on failed login
        return render_template('login.html', error='Invalid QR code. Please try again.')




from sqlalchemy.exc import OperationalError

@views.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect appropriately
    if current_user.is_authenticated:
        if 'next' in session and session['next'] == url_for('views.user_checkin'):
            return handle_checkin_redirect()
        return redirect(url_for('views.sessions'))

    if request.method == 'GET':
        return render_template("login.html")

    # POST handling
    email = request.form.get("email")
    password = request.form.get("password")        

    try:
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid credentials', category='error')  # Generic message for security
            return render_template("login.html", user=current_user)
        
        if check_password_hash(user.password, password):
            # Generate and store validation code
            code = generate_code()
            session['pending_user'] = user.username
            session['validation_code'] = code
            
            # Send email (uncomment when ready)
            # send_login_validation_email(user.email, user.username, code)
            
            # Login user immediately or after validation based on your flow
            login_user(user, remember=True)
            
            # Handle check-in redirect if coming from QR scan
            if 'next' in session and session['next'] == url_for('views.user_checkin'):
                return handle_checkin_redirect()
                
            flash('Logged in successfully!', category='success')
            return redirect(url_for('views.sessions'))
            
        else:
            flash('Invalid credentials', category='error')
            return render_template("login.html", user=current_user)
            
    except OperationalError as e:
        flash('Database connection error. Please try again later.', category='error')
        return render_template("login.html", user=current_user)
    


@views.route('/silent_logout', methods=['POST'])
def silent_logout():
    logout_user()
    session.clear()
    return jsonify({'status': 'success'}), 200  



def handle_checkin_redirect():
    """Helper function to handle check-in session redirects"""
    session_id = session.get('checkin_session_id')
    if session_id and Session.query.get(session_id):
        # Clear the redirect flags
        session.pop('next', None)
        return redirect(url_for('views.user_checkin'))
    # Fallback if session is invalid
    flash('Check-in session expired', category='warning')
    return redirect(url_for('views.sessions'))

def get_gender_count_by_date():
    query = db.session.query(
        func.to_char(Session.date, 'YYYY-MM-DD').label('session_date'),
        User.gender.label('user_gender'),
        func.count(User.id).label('user_count')
    ).join(session_users, session_users.c.session_id == Session.id) \
    .join(User, User.id == session_users.c.user_id) \
    .group_by(func.to_char(Session.date, 'YYYY-MM-DD'), User.gender) \
    .order_by(func.to_char(Session.date, 'YYYY-MM-DD'), User.gender)

    results = query.all()
    return results

 
 

# Count users
def count_registered_users():
    registered_users_count = db.session.query(User).count()
    return registered_users_count

# Count sessions
def count_sessions():
    session_count = db.session.query(Session).count()
    return session_count


# Function to count the number of male users
def count_male_users():
    male_count = db.session.query(User).filter(User.gender == 'male').count()
    return male_count  


# Function to count the number of male users
def count_female_users():
    female_count = db.session.query(User).filter(User.gender == 'female').count()
    return female_count 


@views.route('/analytics')
@login_required
def analytics():
    user_count = count_registered_users()
    session_count = count_sessions()
    male_count = count_male_users()
    female_count = count_female_users()
    results = get_gender_count_by_date()
    data = {}
    today = datetime.now().date()
    sixty_days_ago = today - timedelta(days=60)
    
    for result in results:
        date_str = result.session_date # already a string
        if date_str not in data:
            data[date_str] = {'male': 0, 'female': 0}
        data[date_str][result.user_gender] = result.user_count

    # Convert the data to JSON
    data_json = json.dumps(data)
    return render_template("analytics.html", user=current_user, user_count = user_count, 
                           session_count = session_count, male_count = male_count,
                             female_count = female_count,data = data_json,default_start_date=sixty_days_ago.strftime('%Y-%m-%d'),
                         default_end_date=today.strftime('%Y-%m-%d'))


@views.route('/home')
def home():
    return render_template("home.html", user=current_user)


# @views.route('/product')
# def product():
#     return render_template('Products.html')

@views.route('/datatable')
def datatable():
    return render_template('datatable.html')


# #  Edit product view
# @views.route('/editproduct', methods=['GET', 'POST'])
# def editProduct():
#     if request.method == 'POST':
#         my_data = Product.query.get(request.form.get('productid'))
#         if my_data:
#             my_data.ProductCode = request.form['productcode']
#             my_data.ItemName = request.form['itemname']
#             my_data.GenericName = request.form['genericname']
#             my_data.GenericNameUpdated = request.form['genericnameupdate']
#             my_data.BasicUnit = request.form['basicunit']
#             my_data.GenericRatio = request.form['genericratio']
#             my_data.StorageCondition = request.form['storagetype']
#             my_data.IvedexGenericCode = request.form['ivedexgenericcode']
#             my_data.Volume = request.form['volume']
#             my_data.Weight = request.form['weight']
#             my_data.PriceDollar = request.form['price']
#             my_data.Program = request.form['program']
#             my_data.ProductGroup = request.form['productgroup']    
#         # db_.session.add(my_data)
#         db.session.commit()

#         flash("Product Updated Successfully")
        
#         return redirect(url_for('views.datatable'))


# Delete product
# @views.route('/productdelete/<id>/', methods=['GET', 'POST'])
# def productdelete(id):
#     my_data = Product.query.get(id)
#     db.session.delete(my_data)
#     db.session.commit()

#     flash("Product Deleted Successfully")
#     return render_template('datatable.html') 



# Route to delete user
@views.route('/userdelete/<id>/', methods=['POST'])
@csrf.exempt
def userdelete(id):
    my_data = User.query.get(id)
    if my_data:
        db.session.delete(my_data)
        db.session.commit()
        return jsonify({"message": "User Deleted Successfully"}), 200
    else:
        return jsonify({"message": "User Not Found"}), 404


# Route to delete session
@views.route('/sessiondelete/<id>/', methods=['POST'])
@csrf.exempt
def sessiondelete(id):
    my_data = Session.query.get(id)
    if my_data:
        db.session.delete(my_data)
        db.session.commit()
        return jsonify({"message": "Session Deleted Successfully"}), 200
    else:
        return jsonify({"message": "Session Not Found"}), 404




# Route to delete session
@views.route('/itemdelete/<id>/', methods=['POST'])
@csrf.exempt
def itemdelete(id):
    my_data = Item.query.get(id)
    if my_data:
        db.session.delete(my_data)
        db.session.commit()
        return jsonify({"message": "Item Deleted Successfully"}), 200
    else:
        return jsonify({"message": "Item Not Found"}), 404        




# Route to delete session
@views.route('/maintenancdelete/<id>/', methods=['GET', 'POST'])
@csrf.exempt
def maintenancdelete(id):
    my_data = Maintenance.query.get(id)
    if my_data:
        db.session.delete(my_data)
        db.session.commit()
        return jsonify({"message": "Record Deleted Successfully"}), 200
    else:
        return jsonify({"message": "Item Not Found"}), 404




# Route to delete user from session
@views.route('/remove_user_from_session/<userId>/<sessionId>', methods=['POST'])
@csrf.exempt
def remove_user_from_session(userId, sessionId):
    user = User.query.get(userId)
    session = Session.query.get(sessionId)
    
    if user and session:
        try:
            # Remove the user from the session
            session.users.remove(user)
            db.session.commit()
            return 'User removed from session successfully', 200
        except Exception as e:
            print('Error removing user from session:', e)
            db.session.rollback()
            return 'Error removing user from session', 500
    else:
        return 'User or session not found', 404

@views.route('/get_sessions_users/<session_id>/users', methods=['POST','GET'])
def get_sessions_users(session_id):
    # Define parameters for server-side processing
    draw = request.form.get('draw')
    start = int(request.form.get('start', 0))
    length = int(request.form.get('length', 10))
    search_value = request.form.get('search[value]', '').strip().lower()

    # Query to get users for a specific session
    base_query = db.session.query(
        User.id,
        User.username,
        User.email,
        User.first_name,
        User.last_name,
        Attendance.check_in_time.label('added_date')
        ).join(Attendance, Attendance.user_id == User.id)\
         .filter(Attendance.session_id == session_id)

    # Apply search filter
    if search_value:
        base_query = base_query.filter(
            or_(
                User.username.ilike(f'%{search_value}%'),
                User.email.ilike(f'%{search_value}%'),
                User.first_name.ilike(f'%{search_value}%'),
                User.last_name.ilike(f'%{search_value}%'),
                func.cast(Attendance.check_in_time, db.String).like(f'%{search_value}%')
            )
        )

    # Get the total number of records before filtering
    total_records = base_query.count()

    # Apply pagination
    paginated_query = base_query.order_by(Attendance.check_in_time.desc()).offset(start).limit(length)

    # Fetch filtered data
    users = paginated_query.all()

    # Prepare data for DataTables response
    data = []
    nigeria_tz = pytz.timezone('Africa/Lagos')
    
    for user in users:
        if user.added_date:
            # Check if datetime is timezone-aware
            if user.added_date.tzinfo is None:
                # If naive (no timezone), localize to UTC
                added_date_utc = pytz.utc.localize(user.added_date)
            else:
                # If already timezone-aware, convert to UTC timezone first
                added_date_utc = user.added_date.astimezone(pytz.utc)
            
            # Convert the UTC datetime to Nigeria time zone
            added_date_nigeria = added_date_utc.astimezone(nigeria_tz)
            
            # Format the datetime to a string
            added_date_str = added_date_nigeria.strftime('%Y-%m-%d %H:%M:%S')
        else:
            added_date_str = None
            
        data.append({
            'Id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'added_date': added_date_str,
            'update_button': '<button class="btn btn-primary btn-sm">Update</button>',
            'delete_button': '<button class="btn btn-danger btn-sm">Delete</button>',
        })

    response = {
        'draw': draw,
        'recordsTotal': total_records,
        'recordsFiltered': total_records if not search_value else base_query.count(),
        'data': data,
    }

    return jsonify(response)


@views.route('/get_session_status_options')
def get_session_status_options():
    status_options = [
        {"value": "scheduled", "label": "Scheduled"},
        {"value": "active", "label": "Active"},
        {"value": "completed", "label": "Completed"},
        {"value": "cancelled", "label": "Cancelled"}
    ]
    
    response = {
        "status_options": status_options,
        "current_status": None  # Initialize as None
    }
    
    session_id = request.args.get('session_id')
    if session_id:
        try:
            session = Session.query.get(session_id)
            if session and session.status:
                response['current_status'] = {
                    "value": session.status,
                    "label": session.status.capitalize()
                }
        except Exception as e:
            views.logger.error(f"Error fetching session status: {str(e)}")
    
    return jsonify(response)


@views.route('/get_roles', methods=['GET'])
@csrf.exempt
def get_roles():
    user_id = request.args.get('user_id')  # Get user_id from the query parameters if provided

    # Fetch all roles from the database
    roles = Role.query.all()
    roles_data = [{'id': role.id, 'name': role.name} for role in roles]  # Convert roles to list of dictionaries

    current_role = None  # Default to no role
    if user_id:
        user = User.query.get(user_id)
        if user and user.roles:
            # Assuming a user has only one role; modify if users can have multiple roles
            current_role = {'id': user.roles[0].id, 'name': user.roles[0].name}

    return jsonify({
        'roles': roles_data,           # List of all available roles
        'current_role': current_role   # User's current role if it exists
    })





@views.route('/get_roless', methods=['GET'])
@csrf.exempt
def get_roless():
    user_id = request.args.get('user_id')  # Get user_id from the query parameters if provided

    # Fetch all roles from the database
    roles = Role.query.all()
    roles_data = [{'id': role.id, 'name': role.name} for role in roles]  # Convert roles to list of dictionaries

    current_role = None  # Default to no role
    if user_id:
        user = User.query.get(user_id)
        if user and user.roles:
            # Assuming a user has only one role; modify if users can have multiple roles
            current_role = {'id': user.roles[0].id, 'name': user.roles[0].name}

    return jsonify({
        'roles': roles_data,           # List of all available roles
        'current_role': current_role   # User's current role if it exists
    })




from datetime import datetime  # Import datetime module

@views.route('/update_user_data', methods=['POST'])
@csrf.exempt
def update_user_data():
    try:
        # Get form data from the AJAX request
        user_id = request.form.get('user_id')
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        date_of_birth = request.form.get('date_of_birth')
        email = request.form.get('email')
        phone_no = request.form.get('phone_no')
        role_id = request.form.get('role_id')

        # Convert the date_of_birth from string to Python date object
        if date_of_birth:
            try:
                # Adjust format string according to the date format received, e.g., "%Y-%m-%d" for "2024-09-12"
                date_of_birth = datetime.strptime(date_of_birth, "%Y-%m-%d").date()
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Invalid date format'}), 400

        # Find the user by ID
        user = User.query.get(user_id)

        if user:
            # Update the user's details
            user.username = username
            user.first_name = first_name
            user.last_name = last_name
            user.date_of_birth = date_of_birth  # Set the converted date object
            user.email = email
            user.phone_no = phone_no
            
            # Update the user's role
            if role_id:
                role = Role.query.get(role_id)
                if role:
                    # If the user already has a role, replace it
                    if user.roles:
                        user.roles.clear()  # Remove all previous roles
                    user.roles.append(role)  # Assign the new role to the user
                else:
                    return jsonify({'status': 'error', 'message': 'Role not found'}), 404

            # Commit the changes to the database
            db.session.commit()

            return jsonify({'status': 'success', 'message': 'User data updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return jsonify({'status': 'error', 'message': str(e)}), 500




@views.route('/addmaintenance', methods=['POST'])
@csrf.exempt
@login_required
def addmaintenance():
    print(request.form) 
    # Get the form data
    item_id = request.form.get('item_id')
    maintenance_description = request.form.get('maintenance_description')
    maintenance_vendor = request.form.get('maintenance_vendor')
    maintenance_date = request.form.get('maintenance_date')
    maintenance_amount = request.form.get('maintenance_amount')

    # Ensure all required fields are provided
    if not (maintenance_description and maintenance_vendor and maintenance_date and maintenance_amount):
        return jsonify({'error': 'All fields are required.'}), 400

    try:
        # Create a new Maintenance record
        new_maintenance = Maintenance(
            item_id=item_id,
            maintenance_description=maintenance_description,
            maintenance_vendor=maintenance_vendor,
            date=maintenance_date,
            amount=maintenance_amount
        )
        
        # Add the new maintenance record to the session and commit to the database
        db.session.add(new_maintenance)
        db.session.commit()

        return jsonify({'success': 'Maintenance record added successfully!'}), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of error
        return jsonify({'error': str(e)}), 500




@views.route('/update_maintenance_data', methods=['POST'])
@csrf.exempt
def update_maintenance_data():
    try:
        # Get form data from the AJAX request
        editmaintenanceid = request.form.get('maintenance_id')
        editmaintenancedescripton = request.form.get('maintenance_description')
        editmaintenancevendor = request.form.get('maintenance_vendor')
        editmaintenancedate = request.form.get('maintenance_date')
        editmaintenanceamount = request.form.get('maintenance_amount')
          
        # Convert the date_of_birth from string to Python date object
        if editmaintenancedate:
            try:
                # Adjust format string according to the date format received, e.g., "%Y-%m-%d" for "2024-09-12"
                editmaintenancedate = datetime.strptime(editmaintenancedate, "%Y-%m-%d").date()
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Invalid date format'}), 400

        # Find the user by ID
        maintenance = Maintenance.query.get(editmaintenanceid)

        if maintenance:
            # Update the user's details
            maintenance.maintenance_description = editmaintenancedescripton
            maintenance.maintenance_vendor = editmaintenancevendor
            maintenance.date = editmaintenancedate
            maintenance.amount = editmaintenanceamount
            # Commit the changes to the database
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Maintenance data updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Maintenance not found'}), 404

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return jsonify({'status': 'error', 'message': str(e)}), 500


@views.route('/update_session_data', methods=['POST'])
@csrf.exempt
def update_session_data():
    print("Received form data:", request.form)  # Debug what's actually being received
    
    try:
        # Validate required fields
        session_id = request.form.get('session_id')
        if not session_id:
            return jsonify({'status': 'error', 'message': 'Missing session ID'}), 400
            
        # Get the session
        session = Session.query.get(session_id)
        if not session:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404

        # Update fields with validation
        try:
            # Get current attendance count before any updates
            current_attendance = db.session.query(func.count(Attendance.id)).filter(
                Attendance.session_id == session_id,
                Attendance.status == 'present'
            ).scalar()
            
            print(f"Current attendance: {current_attendance}")  # Debug logging

            # Validate max capacity before applying changes
            max_capacity = request.form.get('editmaxCapacity')
            if max_capacity:
                max_capacity_int = int(max_capacity)
                print(f"Proposed max capacity: {max_capacity_int}")  # Debug logging
                
                # Check if new max capacity is less than current attendance
                if max_capacity_int < current_attendance:
                    return jsonify({
                        'status': 'error', 
                        'message': f'Cannot set max capacity to {max_capacity_int} because there are already {current_attendance} attendees. Max capacity must be at least {current_attendance}.'
                    }), 400
                
                session.max_capacity = max_capacity_int

            # Required fields
            session.name = request.form.get('editactivityName')
            session.description = request.form.get('editactivityDescription')
            session.status = request.form.get('editstatus', 'scheduled')
            
            # Date field with validation
            date_str = request.form.get('editactivitydate')
            if date_str:
                session.date = datetime.strptime(date_str, "%Y-%m-%d").date()
            
            # Time fields with validation
            time_fields = {
                'start_time': request.form.get('editstartTime'),
                'end_time': request.form.get('editendTime')
            }
            
            for field, value in time_fields.items():
                if value:
                    setattr(session, field, datetime.strptime(value, "%H:%M").time())
            
            # Optional fields
            session.location = request.form.get('editlocation')
            
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Session updated successfully'})
            
        except ValueError as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'Invalid data format: {str(e)}'}), 400
            
    except Exception as e:
        db.session.rollback()
        print(f"Server error: {str(e)}")  # Detailed error logging
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500



@views.route('/update_item_data', methods=['POST'])
@csrf.exempt
def update_item_data():
    try:
        # Get form data from the AJAX request
        item_id = request.form.get('item_id')
        editItemName = request.form.get('editItemName')
        editItemDescription = request.form.get('editItemDescription')
        editItemManufacturer = request.form.get('editItemManufacturer')
        editItemModel = request.form.get('editItemModel')
        editItemcustodianunit = request.form.get('editItemcustodianunit')
        editItemDateofpurchase = request.form.get('editItemDateofpurchase')
        editItemamount = request.form.get('editItemamount')
        editQuantity = request.form.get('editQuantity')
  
        # Convert the date_of_birth from string to Python date object
        if editItemDateofpurchase:
            try:
                # Adjust format string according to the date format received, e.g., "%Y-%m-%d" for "2024-09-12"
                editItemDateofpurchase = datetime.strptime(editItemDateofpurchase, "%Y-%m-%d").date()
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Invalid date format'}), 400

        # Find the user by ID
        item = Item.query.get(item_id)

        if item:
            # Update the user's details
            item.name = editItemName
            item.description = editItemDescription
            item.manufacturer = editItemManufacturer
            item.model = editItemModel
            item.custodian_unit = editItemcustodianunit
            item.date_of_purchase = editItemDateofpurchase
            item.amount = editItemamount
            item.quantity = editQuantity
            # Commit the changes to the database
            db.session.commit()

            return jsonify({'status': 'success', 'message': 'Item data updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Item not found'}), 404

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return jsonify({'status': 'error', 'message': str(e)}), 500




@views.route('/get_users_data', methods=['POST','GET'])
def get_users_data():
    # Define parameters for server-side processing
    draw = request.form.get('draw')
    start = int(request.form.get('start'))
    length = int(request.form.get('length'))
    search_value = request.form.get('search[value]','').strip().lower()

    # Base query to get session data
    base_query = User.query.with_entities(
        User.id,
        User.username,
        User.first_name,
        User.last_name,
        User.date_of_birth,
        User.email,
        User.phone_no
    )

    # Apply search filter
    if search_value:

        base_query = base_query.filter(
            or_(
            User.username.ilike(f'%{search_value}%'),
            User.first_name.ilike(f'%{search_value}%'),
            User.last_name.ilike(f'%{search_value}%'),
            User.phone_no.ilike(f'%{search_value}%'),
            func.cast(User.date_of_birth, db.String).ilike(f'%{search_value}%')
            )
        )

    # Get the total number of records before filtering
    total_records = User.query.count()

    # Get the total number of filtered records
    total_filtered_records = base_query.count()

    # Apply pagination
    query = base_query.order_by(User.id.asc()).offset(start).limit(length)

    # Fetch filtered data
    items = query.all()

    # Prepare data for DataTables response
    data = []
    for item in items:
        data.append({
            'Id': item.id,
            'username': item.username,
            'first_name': item.first_name,
            'last_name': item.last_name,
            'date_of_birth': item.date_of_birth.strftime('%Y-%m-%d'),  # Format date if needed
            'email': item.email,
            'phone_no':item.phone_no,
            'update_button': '<button class="btn btn-primary btn-sm">Update</button>',
            'delete_button': '<button class="btn btn-danger btn-sm">Delete</button>',
        })

    response = {
        'draw': draw,
        'recordsTotal': total_records,
        'recordsFiltered': total_filtered_records,
        'data': data,
    }

    return jsonify(response)


@views.route('/download_users/<format>', methods=['POST'])
def download_users(format):
    # Get the same filters used in your DataTable
    search_value = request.form.get('search_value', '').strip().lower()
    order_column = request.form.get('order_column', '0')
    order_direction = request.form.get('order_direction', 'asc')
    
    # Map column index to actual column name
    column_map = {
        '0': 'id',
        '1': 'username', 
        '2': 'first_name',
        '3': 'last_name',
        '4': 'date_of_birth',
        '5': 'email',
        '6': 'phone_no'
    }
    
    order_by_column = column_map.get(order_column, 'id')
    
    # Base query (same as your DataTable endpoint)
    base_query = User.query.with_entities(
        User.id,
        User.username,
        User.first_name,
        User.last_name,
        User.date_of_birth,
        User.email,
        User.phone_no
    )
    
    # Apply the same search filter
    if search_value:
        base_query = base_query.filter(
            or_(
                User.username.ilike(f'%{search_value}%'),
                User.first_name.ilike(f'%{search_value}%'),
                User.last_name.ilike(f'%{search_value}%'),
                User.phone_no.ilike(f'%{search_value}%'),
                func.cast(User.date_of_birth, db.String).ilike(f'%{search_value}%')
            )
        )
    
    # Apply sorting
    order_column_obj = getattr(User, order_by_column)
    if order_direction == 'desc':
        base_query = base_query.order_by(order_column_obj.desc())
    else:
        base_query = base_query.order_by(order_column_obj.asc())
    
    # Get ALL data (no pagination for download)
    items = base_query.all()
    
    # Prepare data
    data = []
    for item in items:
        data.append({
            'ID': item.id,
            'Username': item.username,
            'First Name': item.first_name,
            'Last Name': item.last_name,
            'Date of Birth': item.date_of_birth.strftime('%Y-%m-%d'),
            'Email': item.email,
            'Phone Number': item.phone_no
        })
    
    # Handle different formats
    if format == 'csv':
        return download_csv(data)
    elif format == 'excel':
        return download_excel(data)
    elif format == 'json':
        return download_json(data)
    else:
        return "Invalid format", 400

def download_csv(data):
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    if data:
        writer.writerow(data[0].keys())
    
    # Write data
    for row in data:
        writer.writerow(row.values())
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=users_data.csv"}
    )

def download_excel(data):
    df = pd.DataFrame(data)
    
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Users')
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment;filename=users_data.xlsx"}
    )

def download_json(data):
    return Response(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=users_data.json"}
    )






@views.route('/get_items_data', methods=['POST','GET'])
@csrf.exempt
def get_items_data():
    # Define parameters for server-side processing
    draw = request.form.get('draw')
    start = int(request.form.get('start'))
    length = int(request.form.get('length'))
    search_value = request.form.get('search[value]','').strip().lower()

    # Base query to get session data
    base_query = db.session.query(
    Item.id,
    Item.name,
    Item.description,
    Item.manufacturer,
    Item.model,
    Item.custodian_unit,
    Item.date_of_purchase,
    Item.amount,
    Item.quantity
)

    # Apply search filter
    if search_value:
        base_query = base_query.filter(
            or_(
            Item.name.ilike(f'%{search_value}%') |
            Item.description.ilike(f'%{search_value}%') |
            Item.manufacturer.ilike(f'%{search_value}%') |
            Item.custodian_unit.ilike(f'%{search_value}%') |
            func.cast(Item.date_of_purchase, db.String).ilike(f'%{search_value}%')
        )
    )

    # Get the total number of records before filtering
    total_records = db.session.query(func.count(Item.id)).scalar()

    # Get the total number of filtered records
    total_filtered_records = base_query.count()

    # Apply pagination
    query = base_query.order_by(Item.id.asc()).offset(start).limit(length)

    # Fetch filtered data
    items = query.all()

    # Prepare data for DataTables response
    data = []
    for item in items:
        data.append({
            'Id': item.id,
            'name': item.name,
            'description': item.description,
            'manufacturer': item.manufacturer,
            'model': item.model,
            'custodian_unit': item.custodian_unit,
            'date_of_purchase': item.date_of_purchase.strftime('%Y-%m-%d'),  # Format date if needed
            'amount': item.amount,
            'quantity': item.quantity,
            'update_button': '<button class="btn btn-primary btn-sm">Update</button>',
            'delete_button': '<button class="btn btn-danger btn-sm">Delete</button>',
        })

    response = {
        'draw': draw,
        'recordsTotal': total_records,
        'recordsFiltered': total_filtered_records,
        'data': data,
    }

    return jsonify(response)







@views.route('/get_sessions_data', methods=['POST','GET'])
def get_sessions_data():
    # Define parameters for server-side processing
    draw = request.form.get('draw')
    start = int(request.form.get('start'))
    length = int(request.form.get('length'))
    search_value = request.form.get('search[value]', '').strip().lower()

    # Base query to get session data with attendance count from Attendance model
    base_query = db.session.query(
        Session.id,
        Session.name,
        Session.description,
        Session.date,
        Session.start_time,
        Session.end_time,
        Session.location,
        Session.status,
        Session.max_capacity,
        func.coalesce(func.count(Attendance.id), 0).label('attendance_count'),
        (Session.max_capacity - func.coalesce(func.count(Attendance.id), 0)).label('remaining_capacity')
    ).outerjoin(
        Attendance,
        db.and_(
            Attendance.session_id == Session.id,
            Attendance.status == 'present'  # Only count present attendees
        )
    ).group_by(Session.id)

    # Apply search filter (expanded to search more fields)
    if search_value:
        base_query = base_query.filter(
            or_(
                Session.name.ilike(f'%{search_value}%'),
                Session.description.ilike(f'%{search_value}%'),
                func.cast(Session.date, db.String).ilike(f'%{search_value}%'),
                Session.location.ilike(f'%{search_value}%'),
                Session.status.ilike(f'%{search_value}%')
            )
        )

    # Get the total number of records before filtering
    total_records = db.session.query(func.count(Session.id)).scalar()

    # Get the total number of filtered records
    total_filtered_records = base_query.count()

    # Apply pagination and sort by date (newest first) and time
    query = base_query.order_by(
        Session.date.desc(),
        Session.start_time.desc()
    ).offset(start).limit(length)

    # Fetch filtered data
    items = query.all()

    # Prepare data for DataTables response with additional fields
    data = []
    for item in items:
        data.append({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'date': item.date.strftime('%Y-%m-%d') if item.date else '',
            'start_time': item.start_time.strftime('%H:%M') if item.start_time else '',
            'end_time': item.end_time.strftime('%H:%M') if item.end_time else '',
            'location': item.location or '',
            'status': item.status or '',
            'capacity': f"{item.attendance_count}/{item.max_capacity}" if item.max_capacity else f"{item.attendance_count}",
            'remaining': item.remaining_capacity if item.max_capacity else 'Unlimited',
            'attendance_count': item.attendance_count,
            'actions': f'''
                <button class="btn btn-primary btn-sm update-btn" data-id="{item.id}">Update</button>
                <button class="btn btn-danger btn-sm delete-btn" data-id="{item.id}">Delete</button>
                <button class="btn btn-info btn-sm view-attendees-btn" data-id="{item.id}">Attendees</button>
            '''
        })

    response = {
        'draw': draw,
        'recordsTotal': total_records,
        'recordsFiltered': total_filtered_records,
        'data': data,
    }

    return jsonify(response)


@views.route('/get_sessions_summary_data', methods=['POST','GET'])
def get_sessions_summary_data():
    try:
        # Handle both GET and POST requests
        if request.method == 'GET':
            # For GET requests, use args instead of form
            draw = request.args.get('draw', '0')
            start = int(request.args.get('start', 0))
            length = int(request.args.get('length', 10))
            search_value = request.args.get('search[value]', '').strip().lower()
        else:
            # For POST requests, use form data
            draw = request.form.get('draw', '0')
            start = int(request.form.get('start', 0))
            length = int(request.form.get('length', 10))
            search_value = request.form.get('search[value]', '').strip().lower()

        # Base query to get session data with attendance count
        base_query = db.session.query(
            Session.id,
            Session.date,
            Session.name,
            Session.description,
            func.coalesce(func.count(Attendance.id), 0).label('user_count')
        ).outerjoin(
            Attendance,
            db.and_(
                Attendance.session_id == Session.id,
                Attendance.status == 'present'
            )
        ).group_by(Session.id, Session.date, Session.name, Session.description)

        # Apply search filter
        if search_value:
            base_query = base_query.filter(
                Session.name.ilike(f'%{search_value}%') |
                Session.description.ilike(f'%{search_value}%') |
                func.cast(Session.date, db.String).ilike(f'%{search_value}%')
            )

        # Get the total number of records before filtering
        total_records = db.session.query(func.count(Session.id)).scalar()

        # Get the total number of filtered records
        total_filtered_records = base_query.count()

        # Apply pagination and sort by date (newest first)
        query = base_query.order_by(Session.date.desc()).offset(start).limit(length)

        # Fetch filtered data
        items = query.all()

        # Prepare data for DataTables response
        data = []
        for item in items:
            data.append({
                'Id': item.id,
                'date': item.date.strftime('%Y-%m-%d') if item.date else '',
                'name': item.name,
                'description': item.description or '',
                'user_count': item.user_count
            })

        response = {
            'draw': draw,
            'recordsTotal': total_records,
            'recordsFiltered': total_filtered_records,
            'data': data,
        }

        return jsonify(response)
        
    except Exception as e:
        print(f"Error in get_sessions_summary_data: {str(e)}")
        return jsonify({
            'error': 'Server error',
            'message': str(e)
        }), 500



# @views.route('/get_data', methods=['POST','GET'])
# def get_data():
#     # Define parameters for server-side processing
#     draw = request.form.get('draw')
#     start = int(request.form.get('start'))
#     length = int(request.form.get('length'))
#     search_value = request.form.get('search[value]').strip().lower()

#     # Query data from the database
#     query = Product.query.order_by(Product.Id.asc())

#     # Apply search filter
#     if search_value:
#         query = query.filter(Product.ProductCode.like(f'%{search_value}%') | Product.GenericNameUpdated.like(f'%{search_value}%') | Product.Program.like(f'%{search_value}%'))
        
        

#     # Get the total number of records before filtering
#     total_records = query.count()

#     # Apply pagination
#     query = query.offset(start).limit(length)

#     # Fetch filtered data
#     items = query.all()

#     # Prepare data for DataTables response
#     data = []
#     for item in items:
#         data.append({
#             'Id': item.Id,
#             'ProductCode': item.ProductCode,
#             'ItemName' : item.ItemName,
#             'GenericName': item.GenericName,
#             'GenericNameUpdated': item.GenericNameUpdated,
#             'BasicUnit': item.BasicUnit,
#             'GenericRatio': item.GenericRatio,
#             'StorageCondition': item.StorageCondition,
#             'IvedexGenericCode': item.IvedexGenericCode,
#             'NHLMISGenericParent' : item.NHLMISGenericParent,
#             'InventoryConversionFactor' : item.InventoryConversionFactor,
#             'Volume' : item.Volume,
#             'Weight' : item.Weight,
#             'PriceDollar' : item.PriceDollar,
#             'Program' : item.Program,
#             'ProductGroup' : item.ProductGroup,
#             'update_button': '<button class="btn btn-primary btn-sm">Update</button>',
#             'delete_button': '<button class="btn btn-danger btn-sm">Delete</button>',
#         })

#     response = {
#         'draw': draw,
#         'recordsTotal': total_records,
#         'recordsFiltered': total_records if not search_value else len(items),
#         'data': data,
#     }

#     return jsonify(response)


# @views.route('/products', methods=['GET', 'POST'])
# @login_required
# def products():
#     return_value = ''
#     if request.method == 'GET':
#         all_products = Product.query.all()
#         if all_products:
#             return_value = 'Data Returned'
#         else:
#             return_value = 'No Data returned'
                
            
#     return render_template("Products.html", user=current_user, products=all_products)



@views.route('/addsession', methods=['POST'])
@csrf.exempt
@login_required
def addsession():
    if request.method == 'POST':
        try:
            # Basic session information
            name = request.form.get("activityname")
            description = request.form.get("activitydescription")
            
            # Scheduling fields
            date_str = request.form.get("activitydate")
            date = datetime.strptime(date_str, '%Y-%m-%d').date() if date_str else None
            start_time_str = request.form.get("starttime")
            start_time = datetime.strptime(start_time_str, '%H:%M').time() if start_time_str else None
            end_time_str = request.form.get("endtime")
            end_time = datetime.strptime(end_time_str, '%H:%M').time() if end_time_str else None
            location = request.form.get("location")
            
            # Capacity management
            max_capacity = request.form.get("maxcapacity")
            max_capacity = int(max_capacity) if max_capacity else None
            
            # Check-in window settings
            checkin_opens_minutes = int(request.form.get("checkinopens") or 30)
            checkin_closes_minutes = int(request.form.get("checkincloses") or 15)
            
            # Session settings
            allow_self_checkin = request.form.get("allowselfcheckin") == 'on'
            status = request.form.get("status", "scheduled")
            
            # Generate QR code data
            qr_code = str(uuid.uuid4())
            checkin_url = url_for('views.scan_session', qr_code=qr_code, _external=True)

            # Create new session object first to get ID
            new_session = Session(
                name=name,
                description=description,
                date=date,
                start_time=start_time,
                end_time=end_time,
                location=location,
                max_capacity=max_capacity,
                checkin_opens_minutes=checkin_opens_minutes,
                checkin_closes_minutes=checkin_closes_minutes,
                allow_self_checkin=allow_self_checkin,
                status=status,
                qr_code=qr_code,
                qr_expires_at=None
            )
            
            db.session.add(new_session)
            db.session.flush()  # Assigns ID without committing
            
            # Now create filename with the new session's ID
            safe_name = "".join(c for c in name.lower() 
                              if c.isalnum() or c in (' ', '-')).strip().replace(' ', '-')
            filename = f"qr-{safe_name}-{new_session.id}-{qr_code}.png"
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(checkin_url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Save QR code
            qr_dir = os.path.join(current_app.root_path, 'static', 'qrcodes')
            os.makedirs(qr_dir, exist_ok=True)
            qr_img.save(os.path.join(qr_dir, filename))
            
            # Final commit
            db.session.commit()
            
            flash("New session added successfully!", "success")
            return redirect(url_for('views.sessions', id=new_session.id))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating session: {str(e)}")
            flash("Failed to create session. Please try again.", "error")
            return redirect(url_for('views.sessions'))
        


@views.route('/save-qr/<int:session_id>')
@login_required
def save_qr(session_id):
    session = Session.query.get_or_404(session_id)
    
    try:
        # Create filename-safe version of session name
        safe_name = "".join(c for c in session.name.lower() 
                          if c.isalnum() or c in (' ', '-')).strip().replace(' ', '-')
        filename = f"qr-{safe_name}-{session.id}-{session.qr_code}.png"
        qr_path = os.path.join(current_app.static_folder, 'qrcodes', filename)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url_for('views.scan_session', qr_code=session.qr_code, _external=True))
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(qr_path), exist_ok=True)
        
        # Save image
        img.save(qr_path)
        
        # Set proper permissions
        os.chmod(qr_path, 0o644)
        
        return jsonify({'success': True, 'message': 'QR code generated successfully'})
    
    except Exception as e:
        current_app.logger.error(f"Failed to generate QR for session {session_id}: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500



@views.route('/generate-qr/<qr_code>')
def generate_qr(qr_code):
    try:
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url_for('views.scan_session', qr_code=qr_code, _external=True))
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to memory buffer
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        # Check if download was requested
        if request.args.get('download'):
            return send_file(
                buffer,
                mimetype='image/png',
                as_attachment=True,
                download_name=f"session-{qr_code}.png"
            )
        return send_file(buffer, mimetype='image/png')
        
    except Exception as e:
        current_app.logger.error(f"Failed to generate QR code {qr_code}: {str(e)}")
        abort(404, description="QR code generation failed")         
    


# @views.route('/regenerate-qrcodes')
# @login_required
# def regenerate_qrcodes():
#     try:
#         batch_size = 50  # Process 50 sessions at a time
#         qr_dir = os.path.join(current_app.root_path, 'static', 'qrcodes')
#         os.makedirs(qr_dir, exist_ok=True)
        
#         # Get total count first
#         total_sessions = Session.query.filter(Session.qr_code.isnot(None)).count()
#         processed = 0
        
#         for offset in range(0, total_sessions, batch_size):
#             # Get batch of sessions
#             sessions = Session.query.filter(Session.qr_code.isnot(None)) \
#                                   .offset(offset).limit(batch_size).all()
            
#             for session in sessions:
#                 try:
#                     # Generate the proper check-in URL
#                     checkin_url = url_for('views.scan_session', 
#                                         qr_code=session.qr_code, 
#                                         _external=True)
                    
#                     # Create and save QR code
#                     qr = qrcode.QRCode(
#                         version=1,
#                         error_correction=qrcode.constants.ERROR_CORRECT_L,
#                         box_size=10,
#                         border=4,
#                     )
#                     qr.add_data(checkin_url)
#                     qr.make(fit=True)
#                     qr_img = qr.make_image(fill_color="black", back_color="white")
#                     qr_img.save(os.path.join(qr_dir, f"{session.qr_code}.png"))
                    
#                     processed += 1
                    
#                 except Exception as e:
#                     current_app.logger.error(f"Failed session {session.id}: {str(e)}")
#                     db.session.rollback()
#                     continue
            
#             # Commit after each batch
#             db.session.commit()
#             db.session.close()  # Explicitly close the session
            
#             # Progress feedback
#             current_app.logger.info(f"Processed {processed}/{total_sessions} sessions")
#             time.sleep(0.5)  # Brief pause between batches
        
#         flash(f"Successfully regenerated QR codes for {processed} sessions", "success")
    
#     except Exception as e:
#         db.session.rollback()
#         current_app.logger.error(f"QR regeneration failed: {str(e)}")
#         flash(f"Error regenerating QR codes: {str(e)}", "error")
#     finally:
#         db.session.close()
    
#     return redirect(url_for('views.sessions'))




@views.route('/additem', methods=['POST'])
@csrf.exempt
@login_required
def additem():
    if request.method == 'POST':
        name = request.form.get("addItemName")
        Description = request.form.get("addItemDescription")
        Manufacturer = request.form.get("addItemManufacturer")
        Model = request.form.get("addItemModel")
        custodianunit = request.form.get("addItemcustodianunit")
        Dateofpurchase = request.form.get("addItemDateofpurchase")
        date_object = datetime.strptime(Dateofpurchase, '%Y-%m-%d').date()
        amount = request.form.get("addItemamount")
        new_item = Item(name = name, description = Description,manufacturer = Manufacturer,model=Model,
                            custodian_unit = custodianunit, date_of_purchase = date_object, amount = amount)
        db.session.add(new_item)
        db.session.commit()
        flash("New Item Added Successfully")
        return redirect(url_for('views.items'))
    

@views.route('/adduserstosession', methods=['POST'])
@login_required
def adduserstosession():
    if request.method == 'POST':
        activityname = request.form.get("activityname")
        activitydescription = request.form.get("activitydescription")
        activitydate = request.form.get("activitydate")
        date_object = datetime.strptime(activitydate, '%Y-%m-%d').date()
        new_activity = Session(name = activityname, description = activitydescription, date = date_object)
        db.session.add(new_activity)
        db.session.commit()
        flash("User Added Successfully")
        return redirect(url_for('views.session'))


@views.route('/insert', methods=['POST'])
@csrf.exempt
@login_required
def insert():
    if request.method == 'POST':
        username = request.form.get("username")
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        date_of_birth_ = request.form.get("dateofbirth")
        date_of_birth = get_date_of_birth(date_of_birth_)
        email = request.form.get("email")
        password = request.form.get("password")
        gender = request.form.get("gender")
        phone_no = request.form.get("phone_no")
        home_address = request.form.get("home_address")
        role_id = request.form.get('role_id')

        is_first_timer = 'is_first_timer' in request.form  # Returns True/False
        date_joined_str = request.form.get("date_joined")
        date_joined = datetime.strptime(date_joined_str, '%Y-%m-%d') if date_joined_str else datetime.utcnow()

        # Generate QR code
        qr_data = f"Username: {username}\nEmail: {email}"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer)
        qr_code_bytes = buffer.getvalue()
        ## New
        qr_code_base64 = base64.b64encode(qr_code_bytes).decode('utf-8')
       

        my_data = User(username=username,gender=gender,phone_no=phone_no,home_address=home_address,first_name=firstname,last_name=lastname,date_of_birth=date_of_birth,
                        email=email, qr_code=qr_code_base64, password=generate_password_hash(
            password, method='sha256'),is_first_timer=is_first_timer,date_joined=date_joined)
        
        # Assign role to the user
        if role_id:
            role = Role.query.get(role_id)
            if role:
                my_data.roles.append(role)  # Add the role to the user's roles list

        # Save the user and commit the transaction
        try:
            db.session.add(my_data)
            db.session.commit()

            # Send welcome email with QR code
            email_sent = send_email_with_qr(
                user_email=email,
                username=username,
                attachment=qr_code_bytes,
                is_first_timer=is_first_timer
            )
            if email_sent:
                return jsonify({
                    'status':'success',
                    'message': 'User added successfully. Welcome email with QR code sent.'
                })
            else:
                return jsonify({
                    'status': 'success',
                    'message': 'User added successfully, but failed to send welcome email.'
                })
            
        except IntegrityError as e:
            db.session.rollback()
            error_message = str(e.orig)
    
            if 'user_email_key' in error_message:
                return jsonify({
                    'status': 'error', 
                    'message': 'This email address is already registered. Please use a different email.'
                }), 400
            elif 'user_username_key' in error_message:
                return jsonify({
                    'status': 'error', 
                    'message': 'This username is already taken. Please choose a different username.'
                }), 400
            else:
                return jsonify({
                    'status': 'error', 
                    'message': 'A user with this information already exists.'
                }), 400    

        except Exception as e:
            db.session.rollback()  # Rollback in case of an error
            print(f"Error: {e}")
            return jsonify({'status': 'error', 'message': 'An unexpected error occurred while creating the user. Please try again.'}), 500

        return jsonify({'status': 'success', 'message': 'User added successfully'})


@views.route('/update', methods=['GET', 'POST'])
@csrf.exempt
@login_required
def update():
    if request.method == 'POST':
        my_data = User.query.get(request.form.get('id'))
        my_data.username = request.form['username']
        my_data.email = request.form['email']
        my_data.first_name = request.form['firstname']
        my_data.last_name = request.form['lastname']
        date_of_birth = request.form['dateofbirth']
        my_data.date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
        password = request.form['password']

        my_data.gender = request.form['gender']
        my_data.phone_no = request.form['phone_no']
        my_data.home_address = request.form['home_address']
        my_data.password = generate_password_hash(
            password, method='sha256')
        # db_.session.add(my_data)
        db.session.commit()

        flash("User Updated Successfully")

        return redirect(url_for('views.createusers'))
    

@views.route('/addroletouser/<id>', methods=['GET', 'POST'])    
@login_required   
def addroletouser(id):
    if id:
        # Query to get session id, session name, and count of users for each session
        session_data = db.User.query(User.id, User.username).filter(User.id == id).first()
        return render_template("adduserstosession.html",user=current_user, session_data = session_data)    
    

@views.route('/activity/<id>', methods=['GET', 'POST'])    
@csrf.exempt
@login_required   
def activity(id):
    if id:
        # Query to get session id, session name, and count of users for each session
        session_data = db.session.query(Session.id, Session.name).filter(Session.id == id).first()
        return render_template("adduserstosession.html",user=current_user, session_data = session_data,activity=True)



@views.route('/item/<id>', methods=['GET'])
@csrf.exempt
@login_required 
def item(id):
    # Fetch the selected product details
    product = db.session.query(
        Item.id,
        Item.name,
        Item.description,
        Item.manufacturer,
        Item.model,
        Item.custodian_unit,
        Item.date_of_purchase,
        Item.amount,
        Item.quantity
    ).filter_by(id=id).first()

    if not product:
        return "Product not found", 404

    # Render the template and pass the product data
    return render_template('maintenance.html', product=product,user=current_user)



@views.route('/maintenance/history')
@csrf.exempt
@login_required
def maintenance_history():
    """Render the maintenance history page"""
    # Set context for the left navbar active state
    maintenances = True  # This will highlight the Maintenance sub-menu
    return render_template('maintenances.html', maintenances=True, user=current_user)



@views.route('/api/maintenance/history', methods=['GET'])
@login_required
def api_maintenance_history():
    """API endpoint for maintenance history data"""
    print("DEBUG: API endpoint called!")
    
    try:
        # Get all maintenance records with item details
        maintenance_data = db.session.query(
            Maintenance,
            Item.name.label('item_name'),
            Item.custodian_unit,
            Item.manufacturer,
            Item.model
        ).join(
            Item, Maintenance.item_id == Item.id
        ).order_by(
            Maintenance.date.desc()
        ).all()
        
        # Format data for JSON response
        formatted_data = []
        for maintenance, item_name, custodian_unit, manufacturer, model in maintenance_data:
            formatted_data.append({
                'id': maintenance.id,
                'date': maintenance.date.isoformat() if maintenance.date else None,
                'item_id': maintenance.item_id,
                'item_name': item_name,
                'maintenance_description': maintenance.maintenance_description,
                'maintenance_vendor': maintenance.maintenance_vendor,
                'amount': float(maintenance.amount) if maintenance.amount else 0.0,
                'custodian_unit': custodian_unit,
                'manufacturer': manufacturer,
                'model': model
            })
        
        # Calculate statistics
        total_records = Maintenance.query.count()
        
        total_amount_result = db.session.query(func.sum(Maintenance.amount)).scalar()
        total_amount = float(total_amount_result) if total_amount_result else 0.0
        
        # Count distinct items that have maintenance records
        active_items = db.session.query(Maintenance.item_id).distinct().count()
        
        # Count distinct vendors
        total_vendors = db.session.query(Maintenance.maintenance_vendor).filter(
            Maintenance.maintenance_vendor.isnot(None),
            Maintenance.maintenance_vendor != ''
        ).distinct().count()
        
        # Get filter options
        items = db.session.query(Item.id, Item.name).distinct().order_by(Item.name).all()
        items_list = [{'id': item.id, 'name': item.name} for item in items]
        
        vendors = db.session.query(Maintenance.maintenance_vendor).filter(
            Maintenance.maintenance_vendor.isnot(None),
            Maintenance.maintenance_vendor != ''
        ).distinct().order_by(Maintenance.maintenance_vendor).all()
        vendors_list = [vendor[0] for vendor in vendors if vendor[0]]
        
        custodian_units = db.session.query(Item.custodian_unit).filter(
            Item.custodian_unit.isnot(None),
            Item.custodian_unit != ''
        ).distinct().order_by(Item.custodian_unit).all()
        units_list = [unit[0] for unit in custodian_units if unit[0]]
        
        response_data = {
            'success': True,
            'data': formatted_data,
            'stats': {
                'total_records': total_records,
                'total_amount': total_amount,
                'active_items': active_items,
                'total_vendors': total_vendors
            },
            'filters': {
                'items': items_list,
                'vendors': vendors_list,
                'custodian_units': units_list
            }
        }
        
        print(f"DEBUG: Sending response with {len(formatted_data)} records")
        return jsonify(response_data)
        
    except Exception as e:
        print(f"DEBUG: ERROR occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e),
            'data': [],
            'stats': {},
            'filters': {}
        }), 500


@views.route('/get_product_maintenance/<product_id>/maintenance', methods=['GET', 'POST']) 
@csrf.exempt   
@login_required   
def get_product_maintenance(product_id):
    # Define parameters for server-side processing
    draw = request.form.get('draw')
    start = int(request.form.get('start'))
    length = int(request.form.get('length'))
    search_value = request.form.get('search[value]', '').strip().lower()

    # Query to get the maintenance records for the selected item
    base_query = db.session.query(
        Maintenance.id,
        Maintenance.maintenance_description,
        Maintenance.maintenance_vendor,
        Maintenance.date,
        Maintenance.amount
    ).filter(Maintenance.item_id == product_id)

    # Search functionality
    if search_value:
        base_query = base_query.filter(
            Maintenance.maintenance_description.ilike(f'%{search_value}%') |
            Maintenance.maintenance_vendor.ilike(f'%{search_value}%') |
            func.cast(Maintenance.date, db.String).ilike(f'%{search_value}%')
        )

    # Get the total number of records before and after filtering
    total_records = db.session.query(func.count(Maintenance.id)).filter_by(item_id=product_id).scalar()
    total_filtered_records = base_query.count()

    # Apply pagination
    query = base_query.order_by(Maintenance.date.asc()).offset(start).limit(length)
    maintenance_records = query.all()

    # Prepare the response with edit and delete buttons
    data = []
    
    for record in maintenance_records:
        # Format the date directly (since it's already a date object)
        maintenance_date_str = record.date.strftime('%Y-%m-%d') if record.date else None
        
        data.append({
            'Id': record.id,
            'maintenance_description': record.maintenance_description,
            'maintenance_vendor': record.maintenance_vendor,
            'maintenance_date': maintenance_date_str,
            'maintenance_amount': record.amount,
            'edit_button': f'<button class="btn btn-warning btn-sm edit-btn" data-id="{record.id}">Edit</button>',
            'delete_button': f'<button class="btn btn-danger btn-sm delete-btn" data-id="{record.id}">Delete</button>'
        })

    # Prepare the response
    response = {
        'draw': draw,
        'recordsTotal': total_records,
        'recordsFiltered': total_filtered_records,
        'data': data,
    }

    return jsonify(response)




@views.route('/userdetails/<id>')
@csrf.exempt
@login_required
def userdetails(id):
    user = User.query.get(id)
    if not user:
        flash("User not found")
        return redirect(url_for('home'))
    
    # Get attendance statistics
    attendance_stats = get_user_attendance_stats(id)
    
    # Get recent sessions attended by the user
    recent_sessions = get_recent_user_sessions(id, limit=5)
    
    qr_code_data = None
    
    if user.qr_code:
        try:
            if isinstance(user.qr_code, str):
                # Case 1: Already a data URL
                if user.qr_code.startswith('data:image/png;base64,'):
                    qr_code_data = user.qr_code
                
                # Case 2: Already a base64 string without prefix
                elif is_valid_base64(user.qr_code):
                    qr_code_data = f"data:image/png;base64,{user.qr_code}"
                
                # Case 3: Binary as string (0s and 1s)
                elif all(c in '01' for c in user.qr_code):
                    # Ensure length is multiple of 8
                    padded_binary = user.qr_code.ljust((len(user.qr_code) + 7) // 8 * 8, '0')
                    # Convert binary string to bytes
                    byte_data = int(padded_binary, 2).to_bytes(len(padded_binary) // 8, 'big')
                    # Convert bytes to base64
                    qr_code_data = f"data:image/png;base64,{base64.b64encode(byte_data).decode('utf-8')}"
                
                else:
                    # Unrecognized string format
                    flash("QR code format not recognized", "warning")
            
            elif isinstance(user.qr_code, bytes):
                # Handle binary data
                qr_code_data = f"data:image/png;base64,{base64.b64encode(user.qr_code).decode('utf-8')}"
        
        except Exception as e:
            print(f"QR code conversion error: {e}")
            flash("Unable to display QR code: " + str(e), "warning")
            qr_code_data = None
    
    # Enhance user object with computed statistics
    # You can either add these as attributes to the user object
    user.attendance_count = attendance_stats['total_attendance']
    user.first_timer_count = attendance_stats['first_timer_count']
    user.is_first_timer = attendance_stats['is_first_timer']
    
    return render_template("userdetail.html", 
                         user=user, 
                         recent_sessions=recent_sessions,
                         qr_code_data=qr_code_data,
                         userdetails=True)

def get_user_attendance_stats(user_id):
    """Calculate attendance statistics for a user"""
    
    # Get all attendances for this user
    attendances = Attendance.query.filter_by(user_id=user_id).all()
    
    # Count total attendances
    total_attendance = len(attendances)
    
    # Count how many times the user was marked as first timer
    # Check if 'is_first_timer' field exists in Attendance model
    first_timer_attendances = 0
    if hasattr(Attendance, 'is_first_timer'):
        first_timer_attendances = Attendance.query.filter_by(
            user_id=user_id, 
            is_first_timer=True
        ).count()
    
    # Determine if user is currently a first timer
    # You can adjust this logic based on your business rules
    # Common rules: attendance <= 3 OR joined within last 30 days
    is_first_timer = total_attendance <= 3
    
    return {
        'total_attendance': total_attendance,
        'first_timer_count': first_timer_attendances,
        'is_first_timer': is_first_timer
    }

def get_recent_user_sessions(user_id, limit=5):
    """Get recent sessions attended by the user"""
    
    # Query using SQLAlchemy to join Attendance with Session
    recent_sessions = db.session.query(
        Session.name,
        Session.date.label('session_date'),
        Session.location,
        Attendance.check_in_time
    ).join(
        Attendance, Attendance.session_id == Session.id
    ).filter(
        Attendance.user_id == user_id
    ).order_by(
        Attendance.check_in_time.desc()
    ).limit(limit).all()
    
    # Format the results
    formatted_sessions = []
    for session in recent_sessions:
        formatted_sessions.append({
            'name': session.name,
            'date': session.session_date,
            'location': session.location,
            'checkin_time': session.check_in_time
        })
    
    return formatted_sessions

# Optional: Add a helper function for optimized stats using aggregation
def get_user_stats_optimized(user_id):
    """Get user stats using database aggregation for better performance"""
    
    # Get aggregated stats
    stats = db.session.query(
        func.count(Attendance.id).label('total_attendance'),
        func.sum(case([(Attendance.is_first_timer == True, 1)], else_=0)).label('first_timer_count')
    ).filter(Attendance.user_id == user_id).first()
    
    total_attendance = stats.total_attendance or 0
    first_timer_count = stats.first_timer_count or 0
    
    # Determine first timer status
    is_first_timer = total_attendance <= 3
    
    return {
        'total_attendance': total_attendance,
        'first_timer_count': first_timer_count,
        'is_first_timer': is_first_timer
    }





@views.route('/scan-session/<qr_code>')
@csrf.exempt
def scan_session(qr_code):
    try:
        # Get session from database
        session_obj = Session.query.filter_by(qr_code=qr_code).first()  # Renamed to avoid conflict
        
        if not session_obj:
            flash('Invalid QR code', 'error')
            return redirect(url_for('views.sessions'))
            
        # Check session timing
        now = datetime.now()
        if session_obj.start_time:
            start_dt = datetime.combine(session_obj.date, session_obj.start_time)
            opens = start_dt - timedelta(minutes=session_obj.checkin_opens_minutes)
            closes = start_dt + timedelta(minutes=session_obj.checkin_closes_minutes)
            
            if now < opens:
                flash(f'Check-in opens at {opens.strftime("%I:%M %p")}', 'warning')
                return redirect(url_for('views.sessiondetails', id=session_obj.id))
            elif now > closes:
                flash('Check-in period has ended', 'warning')
                return redirect(url_for('views.sessiondetails', id=session_obj.id))
        
        # Store in Flask session (not SQLAlchemy session)
        from flask import session as flask_session
        flask_session['checkin_session_id'] = session_obj.id
        
        # Check authentication
        if not current_user.is_authenticated:
            flask_session['next'] = url_for('views.user_checkin')
            flash('Please login to complete check-in', 'info')
            return redirect(url_for('login'))  # Adjust to your login route name
            
        return redirect(url_for('views.user_checkin'))
        
    except Exception as e:
        current_app.logger.error(f"QR processing failed: {str(e)}", exc_info=True)
        flash('System error during QR processing', 'error')
        return redirect(url_for('views.sessions'))



@views.route('/user-checkin', methods=['GET', 'POST'])
@csrf.exempt
def user_checkin():
    session_id = session.get('checkin_session_id')
    if not session_id:
        flash('No session selected for check-in', 'error')
        return redirect(url_for('views.sessions'))
    
    current_session = Session.query.get(session_id)
    
    if request.method == 'POST':
        user_identifier = request.form.get('user_qr', '').strip()  # Get and clean input
        
        # Check if input is empty
        if not user_identifier:
            flash('Please scan a QR code or enter an email', 'error')
            return render_template('checkin.html', session=current_session, datetime=datetime, timedelta=timedelta)
        
        # Extract email if the input is in "Username: ... Email: ..." format
        if user_identifier.startswith('Username:') and 'Email:' in user_identifier:
            try:
                # Extract the email portion
                email_part = user_identifier.split('Email:')[1].strip()
                # Clean up any trailing punctuation
                email = email_part.split('.')[0] if email_part.endswith('.') else email_part
                user_identifier = email.strip()
            except (IndexError, AttributeError):
                pass
        
        # Query user by QR code OR email
        user = User.query.filter(
            (User.qr_code == user_identifier) |
            (User.email.ilike(user_identifier))  # Case-insensitive email match
        ).first()
        
        if not user:
            flash('Invalid QR code or email address', 'error')
            return render_template('checkin.html', session=current_session, datetime=datetime, timedelta=timedelta)
        
        # Check for existing attendance
        existing_attendance = Attendance.query.filter_by(
            session_id=session_id,
            user_id=user.id
        ).first()
        
        if existing_attendance:
            flash(f'{user.username} is already checked in for this session', 'warning')
            return render_template('usersessionadd.html', 
                                session=current_session, 
                                user=user, 
                                attendance=existing_attendance,
                                datetime=datetime, 
                                timedelta=timedelta)
        else:
            # Create new attendance record
            new_attendance = Attendance(
                session_id=session_id,
                user_id=user.id,
                check_in_time=datetime.now()
            )
            db.session.add(new_attendance)
            db.session.commit()
            flash(f'Successfully checked in {user.username}', 'success')
            return render_template('usersessionadd.html', 
                                session=current_session, 
                                user=user, 
                                attendance=new_attendance,
                                datetime=datetime, 
                                timedelta=timedelta)
    
    return render_template('checkin.html', session=current_session, datetime=datetime, timedelta=timedelta)

@views.route('/sessiondetails/<int:id>')
@csrf.exempt
@login_required
def sessiondetails(id):
    session = Session.query.get(id)
    if not session:
        flash("Session not found", "error")
        return redirect(url_for('views.sessions'))
    
    qr_code_base64 = None
    if session.qr_code:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(session.qr_code)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()

    # Calculate check-in window times
    checkin_window = {}
    if session.start_time:
        try:
            start_datetime = datetime.combine(session.date, session.start_time)
            opens_time = start_datetime - timedelta(minutes=session.checkin_opens_minutes)
            closes_time = start_datetime + timedelta(minutes=session.checkin_closes_minutes)
            
            checkin_window = {
                'opens': opens_time,
                'closes': closes_time,
                'is_active': datetime.now() >= opens_time and datetime.now() <= closes_time,
                'opens_relative': f"{session.checkin_opens_minutes} mins before",
                'closes_relative': f"{session.checkin_closes_minutes} mins after"
            }
        except Exception as e:
            print(f"Error calculating check-in window: {e}")
    
    return render_template("sessiondetail.html", 
                         session=session,
                         user = current_user,
                         qr_code_base64=qr_code_base64,  # Pass the UUID directly
                         checkin_window=checkin_window,
                         current_time=datetime.now(),sessiondetails = True)



# Helper function to check if a string is valid base64
def is_valid_base64(s):
    try:
        # Add padding if needed
        padding_needed = len(s) % 4
        if padding_needed:
            s += '=' * (4 - padding_needed)
        
        # Try to decode
        base64.b64decode(s)
        return True
    except:
        return False
  

# Helper function to check if a string is valid base64
def is_valid_base64(s):
    try:
        # Add padding if needed
        padding_needed = len(s) % 4
        if padding_needed:
            s += '=' * (4 - padding_needed)
        
        # Try to decode
        base64.b64decode(s)
        return True
    except:
        return False



@views.route('/delete/<id>/', methods=['GET', 'POST'])
@login_required
def delete(id):
    my_data = User.query.get(id)
    db.session.delete(my_data)
    db.session.commit()

    flash("User Deleted Successfully")
    return redirect(url_for('views.createusers'))


@views.route('/sessions', methods=['GET', 'POST'])
@csrf.exempt
@login_required
def sessions():
    all_activity = db.session.query(
        Session.id,
        Session.name,
        Session.description,
        Session.date,
        Session.start_time,
        Session.end_time,
        Session.location,
        Session.status,
        func.coalesce(func.count(Attendance.id), 0).label('attendance_count'),
        Session.max_capacity,
        (Session.max_capacity - func.coalesce(func.count(Attendance.id), 0)).label('remaining_capacity')
    ).outerjoin(
        Attendance, 
        db.and_(
            Attendance.session_id == Session.id,
            Attendance.status == 'present'  # Only count present attendees
        )
    ).group_by(
        Session.id,
        Session.name,
        Session.description,
        Session.date,
        Session.start_time,
        Session.end_time,
        Session.location,
        Session.status,
        Session.max_capacity
    ).order_by(
        Session.date.desc(),
        Session.start_time.desc()
    ).all()
    
    return render_template('session.html', user=current_user, activities=all_activity)




@views.route('/items', methods=['GET', 'POST'])
@csrf.exempt
@login_required
def items():
    all_item = Item.query.all()
    return render_template('item.html', user=current_user, items = all_item)



@views.route('/manageusers', methods=['GET', 'POST'])
@login_required
def manageusers():
    all_user = User.query.with_entities(
        User.id,
        User.username,
        User.first_name,
        User.last_name,
        User.date_of_birth,
        User.email,
        User.phone_no
    )
    return render_template('manageusers.html', user=current_user, users = all_user)



@views.route('/manageinventory', methods=['GET', 'POST'])
@login_required
def manageinventory():
    all_user = User.query.with_entities(
        User.id,
        User.username,
        User.first_name,
        User.last_name,
        User.date_of_birth,
        User.email,
        User.phone_no
    )
    return render_template('manageusers.html', user=current_user, users = all_user)


#paginated function
def get_users(offset=0, per_page=5):
    return User.query.offset(offset).limit(per_page).all()

@views.route('/createusers')
@login_required
def createusers():
    # Get page and per_page from URL parameters with default values
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=5, type=int)
    
    # Calculate the offset for SQL query
    offset = (page - 1) * per_page
    
    # Get total number of users and the subset of users for the current page
    total = User.query.count()
    pagination_users = get_users(offset=offset, per_page=per_page)
    
    # Create the pagination object
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')
    
    # Render the template with users and pagination
    return render_template("createusers.html", user=current_user, users=pagination_users, pagination=pagination)



@views.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'GET':
        return render_template('forgotpassword.html')
    elif request.method == "POST":
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")      

        user = User.query.filter_by(email=email).first()
        if user:           
            if len(email) < 4:
                flash('Email must be greater than 3 characters.', category='error')
            elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password1) < 7:
                flash('Passwords must be atleast 7 characters', category='error')
            else:
                # update user to database
                password =generate_password_hash(password1, method='sha256')
                user.password = password
                db.session.add(user)
                db.session.commit()
                flash('Password Updated Successfuly!', category='success')
                return redirect(url_for('views.login'))
        else:
            flash('Email address not found.', category='error')
    return render_template("forgotpassword.html")


# @views.route('/test')
# @login_required
# def test():
#     if request.method == 'GET':
#         all_products = Product.query.limit(15).all()

#     return render_template("Products.html", user=current_user, products=all_products)


#@views.route('/tesst')
#@login_required
#def tesst():
#    if request.method == 'GET':
#        all_products = TempmsProduct.query.all()
#    return render_template("tesst.html", products = all_products)



def generate_code():
    return str(random.randint(100000, 999999))  # 6-digit code



# Prevalidate users before login
@views.route('/prevalidate', methods=['GET', 'POST'])
def prevalidate():
    if 'pending_user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form['code']
        if code == session.get('validation_code'):
            session['user'] = session.pop('pending_user')
            session.pop('validation_code', None)  # remove used code
            flash('Logged in successfully!', category='success')
            login_user(session['user'], remember=True)
            return redirect(url_for('views.sessions'))
        else:
            return "Invalid validation code"
    return render_template('prevalidate.html')






@views.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('views.login'))


@views.route('/index')
@login_required
def index():
    return render_template("index.html")


def get_date_of_birth(dateofbirth, default_value='1789-01-01'):
    """
    Returns the parsed dateofbirth if it is valid, otherwise returns the default value.

    :param dateofbirth: The date of birth as a string.
    :param default_value: The default value to return if dateofbirth is None or invalid.
    :return: A date object.
    """
    if dateofbirth:
        try:
            return datetime.strptime(dateofbirth, '%Y-%m-%d').date()
        except ValueError as e:
            print(f"Error parsing date: {e}. Returning default value.")
            return datetime.strptime(default_value, '%Y-%m-%d').date()
    else:
        print("Date of birth not provided. Returning default value.")
        return datetime.strptime(default_value, '%Y-%m-%d').date()



def update_all_user_qr_codes():
    """
    Updates all users' QR codes from binary string format to Base64.
    
    This function:
    1. Finds all users with QR codes in binary format (strings of only 0s and 1s)
    2. Converts each binary string to bytes
    3. Encodes those bytes to Base64
    4. Updates the database with the new Base64 format
    
    Returns:
        dict: A summary of the update operation with counts and any errors
    """
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Starting QR code update process")
    
    # Get database connection from Flask app
    try:
        db = current_app.extensions['sqlalchemy'].db.session
    except Exception as e:
        logger.error(f"Failed to get database session: {str(e)}")
        return {"error": "Database connection failed", "details": str(e)}
    
    # Find all users with binary QR codes
    try:
        result = db.execute(text("""
            SELECT Id, qr_code 
            FROM "user" 
            WHERE qr_code ~ '^[01]+$'
        """))
        users = result.fetchall()
        logger.info(f"Found {len(users)} users with binary QR codes")
    except Exception as e:
        logger.error(f"Failed to query user: {str(e)}")
        return {"error": "Query failed", "details": str(e)}
    
    # Process statistics
    total_users = len(users)
    success_count = 0
    failed_count = 0
    failed_users = []
    
    # Process each user
    for user in users:
        user_id = user[0]
        binary_qr = user[1]
        
        try:
            logger.info(f"Processing user ID: {user_id}")
            
            # Make sure the binary string length is a multiple of 8
            remainder = len(binary_qr) % 8
            if remainder != 0:
                padding_needed = 8 - remainder
                binary_qr = binary_qr + '0' * padding_needed
                logger.info(f"Added {padding_needed} bits of padding")
            
            # Convert binary string to bytes
            bytes_data = bytearray()
            for i in range(0, len(binary_qr), 8):
                byte = binary_qr[i:i+8]
                bytes_data.append(int(byte, 2))
            
            # Convert bytes to Base64
            base64_qr = base64.b64encode(bytes_data).decode('utf-8')
            logger.info(f"Successfully converted to Base64. First 30 chars: {base64_qr[:30]}...")
            
            # Update the database
            db.execute(text("""
                UPDATE "user"
                SET qr_code = :new_barcode
                WHERE Id = :user_id
            """), {"new_barcode": base64_qr, "user_id": user_id})
            
            success_count += 1
            logger.info(f"User {user_id} updated successfully")
            
        except Exception as e:
            failed_count += 1
            error_details = {"user_id": user_id, "error": str(e)}
            failed_users.append(error_details)
            logger.error(f"Failed to update user {user_id}: {str(e)}")
    
    # Commit all changes
    try:
        db.commit()
        logger.info("All changes committed to database")
    except Exception as e:
        logger.error(f"Failed to commit changes: {str(e)}")
        return {
            "error": "Failed to commit changes",
            "details": str(e),
            "processed": success_count,
            "failed": failed_count
        }
    
    # Return summary
    result = {
        "total_users": total_users,
        "success_count": success_count,
        "failed_count": failed_count
    }
    
    if failed_count > 0:
        result["failed_users"] = failed_users
    
    logger.info(f"QR code update complete. Summary: {result}")
    return result


@views.route('/admin/update-qr-codes', methods=['GET', 'POST'])
def update_qr_codes_endpoint():
    result = update_all_user_qr_codes()
    return jsonify(result)




@views.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('signup.html')
    elif request.method == "POST":
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        email = request.form.get("email")
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        dateofbirth = request.form.get("date_of_birth")
        date_of_birth = get_date_of_birth(dateofbirth)
        gender = request.form.get("gender")
        phone_no = request.form.get("phone_no")
        home_address = request.form.get("home_address")

        is_first_timer = request.form.get('is_first_timer') == 'on'  # Returns True/False
        date_joined = request.form.get("date_joined") or datetime.utcnow()

        # Generate QR code
        qr_data = f"Username: {username}\nEmail: {email}"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer)
        qr_code_bytes = buffer.getvalue()
        ## New
        qr_code_base64 = base64.b64encode(qr_code_bytes).decode('utf-8')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(username) < 2:
            flash('Username must be greater than 1 characters.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Passwords must be atleast 7 characters', category='error')
        else:
            # add user to database
            new_user = User(
                email=email,
                first_name=firstname,
                last_name=lastname,
                date_of_birth=date_of_birth,
                qr_code=qr_code_base64,
                password=generate_password_hash(password1, method='sha256'),
                username=username,
                gender= gender,
                phone_no= phone_no,
                home_address= home_address,
                is_first_timer= is_first_timer,
                date_joined = date_joined
            )
            db.session.add(new_user)
            db.session.commit()          
            login_user(new_user, remember=True)

            # Generate QR code base64 string
            #qr_code_base64 = get_qr_code(username)

            # Send the email and log the result
            email_sent = send_email_with_qr(new_user.email, new_user.username, qr_code_bytes, is_first_timer= is_first_timer)
            #email_sent = send_test_email(new_user.email)
            if email_sent:
                flash('Registration successful! A QR code has been sent to your email.', 'success')
            else:
                flash('Registration successful! However, we could not send a QR code to your email.', 'warning')

            return redirect(url_for('views.login'))  # Adjust this to your actual login route

    return render_template("signup.html", user=current_user)





# Function to get QR code in base64
def get_qr_code(username):
    user = User.query.filter_by(username=username).first()
    if not user or not user.qr_code:
        return None
    
    # If already properly formatted
    if user.qr_code.startswith('data:image'):
        return user.qr_code
    
    # Ensure proper base64 data URL format
    return f"data:image/png;base64,{user.qr_code}"


def convert_to_base64(qr_code_data):
    if qr_code_data:
        return base64.b64encode(qr_code_data).decode('utf-8')
    return None

@views.route('/show_qr_code', methods=['GET', 'POST']) 
def show_qr_code(username):
    qr_code_data = get_qr_code(username)
    base64_encoded_data = convert_to_base64(qr_code_data)
    return render_template('show_qr_code.html', base64_encoded_data=base64_encoded_data)


# Function to generate QR Code
def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.Error_CORRECT_L, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img

# Function to update user model with QR code
def update_user_qr_code(user):
    qr_code_data = f"User ID: {user.id}"  # Example data, you can customize this
    img = generate_qr_code(qr_code_data)
    buffer = BytesIO()
    img.save(buffer)
    user.qr_code = buffer.getvalue()
    db.session.commit()

# Route to generate QR codes for all users
@views.route('/generate_qr_codes/<id>/', methods=['GET', 'POST'])
def generate_qr_codes():
    user = User.query.get(id)
    update_user_qr_code(user)
    flash("QR Code successfully generated")
    return redirect(url_for('views.createusers'))  # Redirect to index page after generating QR codes    

# Superset stuffs
@views.route("/guest_token", methods=["GET"])
def guest_token():
    # Embed the Superset dashboard using an iframe
    superset_url = "https://superset.westus2.cloudapp.azure.com:8088/api/v1/security/login"
    payload = {"password": "Sleektech@2375#",
               "provider": "db",
               "refresh": True,
               "username": "admin"
               }
    response = requests.post(superset_url, json=payload)
    # the acc_token is a json, which holds access_token and refresh_token
    if response.status_code != 200:
        return str(response.status_code)
    access_token = response.json()['access_token']

    # no get a guest token
    api_url_for_guesttoken = "https://superset.westus2.cloudapp.azure.com:8088/api/v1/security/guest_token"
    payload = {}
    data = json.dumps({
        "user": {
            "username": "admin",
            "first_name": "Admin",
            "last_name": "Admin"
        },

        "resources": [{
            "type": "dashboard",
            "id": "13"
        }],
        "rls": []
    })

    # now this is the crucial part: add the specific auth-header
    response = requests.post(api_url_for_guesttoken, data=data, headers={
                             "Authorization": f"Bearer {access_token}", 'Accept': 'application/json', 'Content-Type': 'application/json'})

    if response == None:
        return "None response error"
    # Set the authentication token
    auth_token = jsonify(response.json()['token'])

    # Set the Superset API endpoint and dashboard ID
    api_url = "https://superset.westus2.cloudapp.azure.com:8088/api/v1/dashboard"
    dashboard_id = 13

    # Set the headers with the authentication token
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    # Send a GET request to retrieve the dashboard
    response_ = requests.get(f"{api_url}/{dashboard_id}", headers={
                             "Authorization": f"Bearer {access_token}", 'Accept': 'application/json', 'Content-Type': 'application/json'})

    if response_ != None:
        response_content = response_.content
        data = json.loads(response_content)
        # Parse the JSON response
        # Convert the parsed JSON to an HTML table using json2html
        html_table = json2html.convert(json=data)
        if html_table != None:
            return html_table
        


from flask import jsonify
from sqlalchemy import func, extract, case, and_
from datetime import datetime, timedelta
from collections import defaultdict

@views.route('/api/analytics/dashboard')
@login_required
def get_dashboard_data():
    """Analytics dashboard endpoint - Simplified for date filters only"""
    try:
        print("=" * 50)
        print("ANALYTICS DASHBOARD - DATE FILTERS ONLY")
        print("=" * 50)
        
        # Get date parameters only
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        print(f"Received dates - start: {start_date}, end: {end_date}")
        
        # Parse dates with validation
        parsed_start_date = None
        parsed_end_date = None
        
        # Parse start_date
        if start_date:
            try:
                parsed_start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                print(f"Parsed start_date: {parsed_start_date}")
            except ValueError:
                print(f"Warning: Invalid start_date format '{start_date}'. Expected YYYY-MM-DD")
        
        # Parse end_date
        if end_date:
            try:
                parsed_end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                print(f"Parsed end_date: {parsed_end_date}")
            except ValueError:
                print(f"Warning: Invalid end_date format '{end_date}'. Expected YYYY-MM-DD")
        
        # Set default dates if not provided (last 30 days)
        if not parsed_start_date or not parsed_end_date:
            print("Setting default dates (last 30 days)")
            parsed_end_date = datetime.now().date()
            parsed_start_date = parsed_end_date - timedelta(days=30)
        
        # Ensure start_date is before or equal to end_date
        if parsed_start_date > parsed_end_date:
            print(f"Warning: start_date ({parsed_start_date}) > end_date ({parsed_end_date}), swapping")
            parsed_start_date, parsed_end_date = parsed_end_date, parsed_start_date
        
        print(f"Final dates for filtering - start: {parsed_start_date}, end: {parsed_end_date}")
        
        # Convert to string format for consistency
        start_date_str = parsed_start_date.strftime('%Y-%m-%d')
        end_date_str = parsed_end_date.strftime('%Y-%m-%d')
        
        # Start with base queries
        user_query = User.query
        session_query = Session.query
        attendance_query = Attendance.query
        item_query = Item.query
        maintenance_query = Maintenance.query
        
        # Apply date filters to relevant queries
        # 1. Sessions - filter by date
        session_query = session_query.filter(
            Session.date >= parsed_start_date,
            Session.date <= parsed_end_date
        )
        
        # 2. Attendance - filter through session join
        # Get session IDs within date range first
        session_ids_in_range = [s.id for s in session_query.with_entities(Session.id).all()]
        
        if session_ids_in_range:
            attendance_query = attendance_query.filter(
                Attendance.session_id.in_(session_ids_in_range)
            )
        else:
            # If no sessions in date range, return empty query
            attendance_query = attendance_query.filter(False)
        
        # 3. Maintenance - optional date filtering (uncomment if needed)
        # maintenance_query = maintenance_query.filter(
        #     Maintenance.maintenance_date >= parsed_start_date,
        #     Maintenance.maintenance_date <= parsed_end_date
        # )
        
        # Debug: Show query counts
        print(f"User count: {user_query.count()}")
        print(f"Sessions in date range: {session_query.count()}")
        print(f"Attendance records: {attendance_query.count()}")
        print(f"Items count: {item_query.count()}")
        print(f"Maintenance records: {maintenance_query.count()}")
        
        # Calculate KPIs
        kpis = calculate_filtered_kpis(
            user_query, session_query, attendance_query, 
            item_query, maintenance_query
        )
        
        # Get chart data
        print("Getting chart data...")
        try:
            # First, get all charts normally with the filtered date range
            charts = get_filtered_chart_data(
                user_query, session_query, attendance_query,
                item_query, maintenance_query,
                start_date_str, end_date_str
            )
            
            # ================ FIX FOR MEMBER GROWTH ================
            # Override member growth to show FULL history regardless of date filter
            print("=" * 50)
            print("FIX: Overriding member growth with full history")
            print("=" * 50)
            
            # Get the earliest user date for full history
            earliest_user = User.query.filter(User.date_joined.isnot(None)).order_by(User.date_joined).first()
            
            if earliest_user and earliest_user.date_joined:
                # Use the actual earliest user join date
                history_start = earliest_user.date_joined.strftime('%Y-%m-%d')
                print(f"Earliest user joined: {history_start}")
            else:
                # Fallback to a reasonable default
                history_start = '2023-01-01'
                print(f"No earliest user found, using fallback: {history_start}")
            
            # Get current date as end date
            current_end = datetime.now().strftime('%Y-%m-%d')
            print(f"Using full date range: {history_start} to {current_end}")
            
            # Get full history member growth data
            full_member_growth = get_member_growth_chart(
                user_query,  # Use the base user query
                history_start,
                current_end
            )
            
            # Log what we got
            print(f"Full member growth data - Days: {len(full_member_growth.get('labels', []))}")
            if full_member_growth.get('labels'):
                print(f"Date range: {full_member_growth['labels'][0]} to {full_member_growth['labels'][-1]}")
                print(f"Final cumulative: {full_member_growth['cumulative'][-1] if full_member_growth['cumulative'] else 0}")
            
            # Replace the member growth data in the charts
            if 'members' not in charts:
                charts['members'] = {}
            
            charts['members']['member_growth'] = full_member_growth
            print("Member growth successfully overridden with full history")
            # ================ END OF FIX ================
            
            print("Chart data retrieved successfully")
            
        except Exception as chart_error:
            print(f"Error in chart data: {chart_error}")
            import traceback
            traceback.print_exc()
            # Set empty charts with guaranteed structure
            charts = {
                'overview': {
                    'age_distribution': {'labels': [], 'values': []},
                    'attendance_trend': {'labels': [], 'values': []},
                    'gender_distribution': {'labels': [], 'values': []},
                    'inventory_status': {'labels': [], 'values': []},
                    'maintenance_timeline': []
                },
                'members': {
                    'member_growth': {'labels': [], 'values': [], 'cumulative': []},
                    'member_categories': {'labels': [], 'values': []}
                },
                'attendance': {
                    'session_performance': {'labels': [], 'values': []},
                    'checkin_methods': {'labels': [], 'values': []}
                },
                'inventory': {
                    'inventory_value': {'labels': [], 'values': []},
                    'inventory_category': {'labels': [], 'values': []}
                },
                'maintenance': {
                    'maintenance_cost': {'labels': [], 'values': []},
                    'maintenance_status': {'labels': [], 'values': []}
                }
            }
        
        # Get table data
        tables = get_filtered_table_data(
            user_query, session_query, attendance_query,
            item_query, maintenance_query
        )
        
        # Prepare the response
        response_data = {
            'kpis': kpis,
            'charts': charts,
            'tables': tables,
            'success': True,
            'meta': {
                'start_date': start_date_str,
                'end_date': end_date_str,
                'date_range_used': f"{start_date_str} to {end_date_str}",
                'member_growth_note': 'Showing full history from earliest user to present'
            }
        }
        
        print("=" * 50)
        print("ANALYTICS DASHBOARD - SUCCESS")
        print(f"Member growth labels: {len(charts['members']['member_growth'].get('labels', []))}")
        print("=" * 50)
        
        return jsonify(response_data)
        
    except Exception as e:
        print("=" * 50)
        print("ERROR IN ANALYTICS DASHBOARD")
        print("=" * 50)
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to load analytics data'
        }), 500

    # app.py - Add these filter endpoints
@views.route('/api/analytics/filters/sessions')
@login_required
def get_session_filters():
    """Get all sessions for filter dropdown"""
    sessions = Session.query.order_by(Session.date.desc()).limit(100).all()
    
    return jsonify([{
        'id': session.id,
        'name': session.name,
        'date': session.date.strftime('%Y-%m-%d') if session.date else None,
        'location': session.location
    } for session in sessions])


@views.route('/api/test-member-growth-only')
@login_required
def test_member_growth_only():
    """Test ONLY member growth chart to isolate the error"""
    try:
        start_date = request.args.get('start_date', '2023-01-01')
        end_date = request.args.get('end_date', '2025-12-31')
        
        print(f"Testing member growth with dates: {start_date} to {end_date}")
        
        # Call only the member growth function
        result = get_member_growth_chart(User.query, start_date, end_date)
        
        return jsonify({
            'success': True,
            'member_growth': result,
            'dates_used': {
                'start': start_date,
                'end': end_date
            }
        })
    except Exception as e:
        print(f"ERROR in test: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500


@views.route('/api/analytics/filters/roles')
@login_required
def get_role_filters():
    """Get all roles for filter dropdown"""
    roles = Role.query.order_by(Role.name).all()
    
    return jsonify([{
        'id': role.id,
        'name': role.name,
        'description': role.description
    } for role in roles])

@views.route('/api/analytics/filters/inventory-categories')
@login_required
def get_inventory_category_filters():
    """Get unique inventory categories from items"""
    # Get distinct categories from items (you might need to adjust this based on your model)
    categories = db.session.query(
        Item.custodian_unit.distinct().label('category')
    ).filter(Item.custodian_unit.isnot(None)).all()
    
    # Also get from manufacturer/model for more categories
    manufacturers = db.session.query(
        Item.manufacturer.distinct().label('category')
    ).filter(Item.manufacturer.isnot(None)).all()
    
    all_categories = set()
    
    # Add custodian units
    for cat in categories:
        if cat.category:
            all_categories.add(cat.category)
    
    # Add manufacturers
    for man in manufacturers:
        if man.category:
            all_categories.add(man.category)
    
    # Convert to list of dicts
    category_list = [{'name': cat} for cat in sorted(all_categories)]
    
    return jsonify(category_list)

@views.route('/api/analytics/filters/age-groups')
@login_required
def get_age_group_filters():
    """Get predefined age groups"""
    age_groups = [
        {'id': 'child', 'name': 'Child (0-12)'},
        {'id': 'teen', 'name': 'Teen (13-19)'},
        {'id': 'young_adult', 'name': 'Young Adult (20-35)'},
        {'id': 'adult', 'name': 'Adult (36-60)'},
        {'id': 'senior', 'name': 'Senior (60+)'}
    ]
    return jsonify(age_groups)

@views.route('/api/analytics/filters/genders')
@login_required
def get_gender_filters():
    """Get unique genders from users"""
    genders = db.session.query(
        User.gender.distinct().label('gender')
    ).filter(User.gender.isnot(None)).all()
    
    gender_list = [{'id': gender.gender, 'name': gender.gender} for gender in genders if gender.gender]
    
    return jsonify(gender_list)



# analytics_filters.py - Complete filter application functions

from datetime import datetime, timedelta
from sqlalchemy import func, or_, and_, extract
from dateutil.relativedelta import relativedelta

def apply_user_filters(query, member_types, role_ids):
    """Apply filters to user query"""
    conditions = []
    
    # Apply member type filters
    if member_types:
        member_conditions = []
        
        for mtype in member_types:
            if mtype == 'first_timer':
                member_conditions.append(User.is_first_timer == True)
            elif mtype == 'returning':
                member_conditions.append(User.is_first_timer == False)
            elif mtype == 'regular':
                # Users with more than 5 attendances
                subquery = db.session.query(Attendance.user_id)\
                    .group_by(Attendance.user_id)\
                    .having(func.count(Attendance.id) > 5)\
                    .subquery()
                member_conditions.append(User.id.in_(subquery))
        
        if member_conditions:
            conditions.append(or_(*member_conditions))
    
    # Apply role filters
    if role_ids:
        role_conditions = []
        for role_id in role_ids:
            role_conditions.append(User.roles.any(Role.id == int(role_id)))
        
        if role_conditions:
            conditions.append(or_(*role_conditions))
    
    # Apply all conditions
    if conditions:
        query = query.filter(and_(*conditions))
    
    return query

def apply_session_filters(query, session_ids, start_date, end_date):
    """Apply filters to session query"""
    conditions = []
    
    # Filter by session IDs
    if session_ids:
        conditions.append(Session.id.in_([int(sid) for sid in session_ids]))
    
    # Filter by date range
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            conditions.append(Session.date.between(start, end))
        except ValueError:
            pass
    
    # Apply conditions
    if conditions:
        query = query.filter(and_(*conditions))
    
    return query

def apply_attendance_filters(query, session_ids=None, start_date=None, end_date=None):
    """Apply filters to attendance query - FIXED duplicate join issue"""
    # Apply session_id filters
    if session_ids:
        query = query.filter(Attendance.session_id.in_(session_ids))
    
    # Apply date filters
    has_date_filter = start_date or end_date
    
    if has_date_filter:
        # Only join once, check if already joined
        already_joined = False
        
        # Check if session is already joined (for complex queries)
        # This is a simplified check - you might need to adjust based on your actual query structure
        query_str = str(query)
        if 'JOIN session' in query_str or 'INNER JOIN session' in query_str:
            already_joined = True
        
        if not already_joined:
            query = query.join(Session, Attendance.session_id == Session.id)
        
        # Apply date filters
        if start_date:
            start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
            query = query.filter(Session.date >= start_date_obj)
        
        if end_date:
            end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(Session.date <= end_date_obj)
    
    return query

def apply_item_filters(query, categories):
    """Apply filters to item query"""
    if categories:
        category_conditions = []
        
        for category in categories:
            # Search in custodian_unit, manufacturer, or model
            category_conditions.append(Item.custodian_unit.ilike(f'%{category}%'))
            category_conditions.append(Item.manufacturer.ilike(f'%{category}%'))
            category_conditions.append(Item.model.ilike(f'%{category}%'))
        
        if category_conditions:
            query = query.filter(or_(*category_conditions))
    
    return query

def apply_maintenance_filters(query, statuses, start_date, end_date):
    """Apply filters to maintenance query"""
    conditions = []
    
    # Filter by status (you'll need to define how to determine status)
    if statuses:
        status_conditions = []
        
        for status in statuses:
            if status == 'good':
                # Maintenance done within last 6 months
                six_months_ago = datetime.now() - timedelta(days=180)
                status_conditions.append(Maintenance.date >= six_months_ago)
            elif status == 'due_soon':
                # Maintenance done 6-9 months ago
                nine_months_ago = datetime.now() - timedelta(days=270)
                six_months_ago = datetime.now() - timedelta(days=180)
                status_conditions.append(
                    and_(
                        Maintenance.date <= six_months_ago,
                        Maintenance.date >= nine_months_ago
                    )
                )
            elif status == 'overdue':
                # Maintenance done more than 9 months ago
                nine_months_ago = datetime.now() - timedelta(days=270)
                status_conditions.append(Maintenance.date <= nine_months_ago)
            elif status == 'in_progress':
                # You might need a status field in Maintenance model
                # For now, we'll use date in future as "scheduled"
                status_conditions.append(Maintenance.date > datetime.now())
        
        if status_conditions:
            conditions.append(or_(*status_conditions))
    
    # Filter by date range
    if start_date and end_date:
        try:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            end = datetime.strptime(end_date, '%Y-%m-%d')
            conditions.append(Maintenance.date.between(start, end))
        except ValueError:
            pass
    
    # Apply conditions
    if conditions:
        query = query.filter(and_(*conditions))
    
    return query



def get_attendance_trend_chart(attendance_query, start_date, end_date):
    """Get attendance trend data"""
    print(f"\n{'='*60}")
    print("DEBUG get_attendance_trend_chart START")
    print(f"start_date: {start_date} (type: {type(start_date)})")
    print(f"end_date: {end_date} (type: {type(end_date)})")
    
    # Initialize variables
    labels = []
    values = []
    
    # Check if we have date range
    if start_date and end_date:
        print(f"Dates provided: {start_date} to {end_date}")
        try:
            print(f"Parsing dates...")
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            days_diff = (end - start).days
            
            print(f"Parsed start: {start}, end: {end}")
            print(f"days_diff: {days_diff}")
            
            # Check what's in attendance_query BEFORE any operations
            print(f"\nChecking attendance_query...")
            total_records = attendance_query.count()
            print(f"Total attendance records in query: {total_records}")
            
            if total_records == 0:
                print("WARNING: attendance_query has ZERO records!")
                # Let's check what filters were applied
                print("Raw SQL of attendance_query:")
                print(str(attendance_query))
            else:
                # Check a sample of what's in the query
                sample = attendance_query.limit(3).all()
                print(f"Sample attendance records ({len(sample)}):")
                for i, att in enumerate(sample):
                    print(f"  Record {i}: session_id={att.session_id}, user_id={att.user_id}")
            
            if days_diff <= 30:
                print("\nUsing daily data logic (≤ 30 days)...")
                
                # First, check if we can even join with sessions
                print("Checking if sessions exist...")
                session_count = Session.query.count()
                print(f"Total sessions in database: {session_count}")
                
                if session_count > 0:
                    # Try to execute the query step by step
                    print("Executing daily trend query...")
                    
                    # Build query step by step to debug
                    query = attendance_query.join(Session, Session.id == Attendance.session_id)
                    print(f"After join - query has {query.count()} records")
                    
                    query = query.group_by(func.date(Session.date))
                    print(f"After group_by - about to execute...")
                    
                    trend_data = query.order_by(func.date(Session.date))\
                        .with_entities(
                            func.date(Session.date).label('date'),
                            func.count(Attendance.id).label('count')
                        ).all()
                    
                    print(f"Daily trend_data fetched: {len(trend_data)} records")
                    
                    if trend_data:
                        for i, d in enumerate(trend_data[:5]):
                            print(f"  Record {i}: date={d.date}, count={d.count}")
                        
                        labels = [d.date.strftime('%b %d') for d in trend_data]
                        values = [d.count for d in trend_data]
                    else:
                        print("No data returned from daily trend query!")
                        
                        # Debug: Check what sessions have attendance
                        print("Checking sessions with attendance...")
                        sessions_with_attendance = Session.query\
                            .join(Attendance, Session.id == Attendance.session_id)\
                            .group_by(Session.id)\
                            .with_entities(
                                Session.id,
                                Session.name,
                                Session.date,
                                func.count(Attendance.id).label('attendance_count')
                            )\
                            .order_by(Session.date)\
                            .limit(5)\
                            .all()
                        
                        print(f"Sessions with attendance ({len(sessions_with_attendance)}):")
                        for sess in sessions_with_attendance:
                            print(f"  Session {sess.id}: {sess.name} on {sess.date} - {sess.attendance_count} attendees")
                else:
                    print("No sessions found in database!")
                
            else:
                print("\nUsing weekly data logic (> 30 days)...")
                
                # Similar debugging for weekly
                print("Executing weekly trend query...")
                trend_data = attendance_query\
                    .join(Session, Session.id == Attendance.session_id)\
                    .group_by(func.extract('year', Session.date), func.extract('week', Session.date))\
                    .order_by(func.extract('year', Session.date), func.extract('week', Session.date))\
                    .with_entities(
                        func.extract('year', Session.date).label('year'),
                        func.extract('week', Session.date).label('week'),
                        func.count(Attendance.id).label('count')
                    ).all()
                
                print(f"Weekly trend_data fetched: {len(trend_data)} records")
                
                if trend_data:
                    for i, d in enumerate(trend_data[:5]):
                        print(f"  Record {i}: year={d.year}, week={d.week}, count={d.count}")
                    
                    labels = [f'Week {d.week}' for d in trend_data]
                    values = [d.count for d in trend_data]
                else:
                    print("No data returned from weekly trend query!")
        
        except Exception as e:
            print(f"\nERROR in attendance trend calculation: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("WARNING: No date range provided to get_attendance_trend_chart!")
    
    print(f"\nReturning chart data:")
    print(f"  Labels count: {len(labels)}")
    print(f"  Values count: {len(values)}")
    print(f"  Labels: {labels}")
    print(f"  Values: {values}")
    print("="*60)
    
    return {
        'labels': labels,
        'values': values
    }


def get_gender_distribution_chart(user_query):
    """Get gender distribution data for charts"""
    # Execute the gender distribution query
    gender_data = user_query\
        .group_by(User.gender)\
        .with_entities(
            User.gender,
            func.count(User.id).label('count')
        ).all()
    
    # Map gender values to labels, handling None/empty values
    gender_map = {}
    for gd in gender_data:
        if gd.gender:
            gender_map[gd.gender] = gd.count
        else:
            # Group unspecified genders together
            gender_map["Not Specified"] = gender_map.get("Not Specified", 0) + gd.count
    
    return {
        'labels': list(gender_map.keys()),
        'values': list(gender_map.values())
    }

def get_age_distribution_chart(user_query):
    """Get age distribution data"""
    # Calculate age groups
    today = datetime.now().date()
    
    # Define age groups
    age_groups = {
        'child': (0, 12),
        'teen': (13, 19),
        'young_adult': (20, 35),
        'adult': (36, 60),
        'senior': (61, 150)
    }
    
    # Get all users with date_of_birth
    users_with_dob = user_query.filter(User.date_of_birth.isnot(None)).all()
    
    # Count by age group
    counts = {group: 0 for group in age_groups.keys()}
    
    for user in users_with_dob:
        if user.date_of_birth:
            age = today.year - user.date_of_birth.year - (
                (today.month, today.day) < (user.date_of_birth.month, user.date_of_birth.day)
            )
            
            for group, (min_age, max_age) in age_groups.items():
                if min_age <= age <= max_age:
                    counts[group] += 1
                    break
    
    return {
        'labels': ['Child (0-12)', 'Teen (13-19)', 'Young Adult (20-35)', 'Adult (36-60)', 'Senior (60+)'],
        'values': [counts['child'], counts['teen'], counts['young_adult'], counts['adult'], counts['senior']]
    }

def get_inventory_status_chart(item_query, maintenance_query):
    """Get inventory status data"""
    # Get items that need maintenance
    six_months_ago = datetime.now() - timedelta(days=180)
    
    # Count items with recent maintenance
    items_with_recent_maintenance = item_query\
        .filter(Item.maintenance.any(Maintenance.date >= six_months_ago.date()))\
        .count()
    
    # Count items without recent maintenance
    items_without_recent_maintenance = item_query\
        .filter(~Item.maintenance.any(Maintenance.date >= six_months_ago.date()))\
        .count()
    
    # Count items that have never had maintenance
    items_never_maintained = item_query\
        .filter(~Item.maintenance.any())\
        .count()
    
    return {
        'labels': ['Good', 'Needs Attention', 'Requires Maintenance'],
        'values': [
            items_with_recent_maintenance,
            items_without_recent_maintenance - items_never_maintained,
            items_never_maintained
        ]
    }

def get_maintenance_timeline_data(maintenance_query):
    """Get maintenance timeline data - FIXED VERSION"""
    
    # Get recent maintenance activities with item details
    timeline_data = maintenance_query\
        .join(Item, Item.id == Maintenance.item_id)\
        .order_by(Maintenance.date.desc())\
        .limit(10)\
        .all()
    
    result = []
    current_datetime = get_current_datetime()
    
    for maintenance in timeline_data:
        if not maintenance.date:
            continue
        
        # Use your helper function
        last_maintenance_dt = ensure_datetime(maintenance.date)
        next_due = safe_date_add(last_maintenance_dt, days=180)
        days_until = days_between(current_datetime, next_due)
        
        result.append({
            'item_name': maintenance.item.name if maintenance.item else 'Unknown',
            'description': maintenance.maintenance_description or (maintenance.item.description if maintenance.item else ''),
            'last_maintenance': ensure_date(maintenance.date).strftime('%b %d, %Y'),
            'next_due': ensure_date(next_due).strftime('%b %d, %Y'),
            'days_until': days_until
        })
    
    return result


def get_maintenance_status_chart(maintenance_query):
    """Get maintenance status breakdown - FIXED VERSION"""
    
    current_date = get_current_date()
    
    # Get all items that have maintenance records
    items_with_maintenance = Item.query\
        .filter(Item.maintenance.any())\
        .all()
    
    status_counts = {
        'good': 0,      # Maintenance within last 6 months
        'due_soon': 0,  # Maintenance 6-9 months ago
        'overdue': 0,   # Maintenance more than 9 months ago
        'never': 0      # No maintenance ever
    }
    
    for item in items_with_maintenance:
        # Get most recent maintenance
        latest_maintenance = Maintenance.query\
            .filter_by(item_id=item.id)\
            .order_by(Maintenance.date.desc())\
            .first()
        
        if latest_maintenance and latest_maintenance.date:
            maintenance_date = ensure_date(latest_maintenance.date)
            days_since = days_between(maintenance_date, current_date)
            
            if days_since <= 180:
                status_counts['good'] += 1
            elif days_since <= 270:
                status_counts['due_soon'] += 1
            else:
                status_counts['overdue'] += 1
        else:
            status_counts['never'] += 1
    
    return {
        'labels': ['Up to Date', 'Due Soon', 'Overdue', 'No Maintenance'],
        'values': [
            status_counts['good'],
            status_counts['due_soon'],
            status_counts['overdue'],
            status_counts['never']
        ],
        'colors': ['#10b981', '#f59e0b', '#ef4444', '#6b7280']
    }


# Safe Chart Data
def safe_chart_data(func, *args, **kwargs):
    """Safely get chart data, returning empty structure on error"""
    empty_result = {'labels': [], 'values': []}
    
    try:
        result = func(*args, **kwargs)
        return result
    except Exception as e:
        print(f"Chart function error in {func.__name__}: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return empty_result


def get_filtered_table_data(user_query, session_query, attendance_query, item_query, maintenance_query):
    """Get all table data with applied filters"""
    return {
        'overview': {
            'first_timers': get_recent_first_timers(user_query),
            'sessions': get_recent_sessions(session_query, attendance_query),
            'active_members': get_active_members_table(user_query, attendance_query)
        },
        'members': {
            'first_timers': get_first_timers_table(user_query),
            'active_members': get_active_members_table(user_query, attendance_query)
        },
        'attendance': {
            'sessions': get_sessions_table(session_query, attendance_query)
        },
        'inventory': {
            'high_value_items': get_high_value_items_table(item_query),
            'attention_items': get_attention_items_table(item_query, maintenance_query)
        },
        'maintenance': {
            'recent_maintenance': get_recent_maintenance_table(maintenance_query),
            'upcoming_maintenance': get_upcoming_maintenance_table(maintenance_query)
        }
    }

def get_recent_first_timers(user_query):
    """Get recent first timers for table"""
    first_timers = user_query\
        .filter_by(is_first_timer=True)\
        .order_by(User.date_joined.desc())\
        .limit(10)\
        .all()
    
    result = []
    for user in first_timers:
        # Get attendance count
        attendance_count = Attendance.query.filter_by(user_id=user.id).count()
        
        result.append({
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'date_joined': user.date_joined,
            'attendance_count': attendance_count
        })
    
    return result

def get_recent_sessions(session_query, attendance_query):
    """Get recent sessions for table"""
    sessions = session_query\
        .order_by(Session.date.desc())\
        .limit(10)\
        .all()
    
    result = []
    for session in sessions:
        # Get attendance count for this session
        attendance_count = attendance_query\
            .filter_by(session_id=session.id)\
            .count()
        
        result.append({
            'name': session.name,
            'date': session.date,
            'location': session.location,
            'attendance': attendance_count,
            'capacity': session.max_capacity or 0
        })
    
    return result


 # analytics_charts.py - Complete chart and table data functions

from datetime import datetime, timedelta
from sqlalchemy import func, extract, desc, asc
import calendar


def get_member_growth_chart(user_query, start_date, end_date):
    """Get member growth over time using date_joined field"""
    try:
        print("=" * 60)
        print("DEBUG: get_member_growth_chart")
        print(f"DEBUG: Received start_date: {start_date}, end_date: {end_date}")
        
        # Convert to datetime if needed
        if isinstance(start_date, str):
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
        if isinstance(end_date, str):
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        
        # CRITICAL FIX: Ensure we have a proper date range
        if not end_date:
            end_date = datetime.now()
        if not start_date:
            start_date = end_date - timedelta(days=30)
        
        # Convert to date objects for comparison
        start_date_date = start_date.date() if hasattr(start_date, 'date') else start_date
        end_date_date = end_date.date() if hasattr(end_date, 'date') else end_date
        
        print(f"DEBUG: Using date range: {start_date_date} to {end_date_date}")
        print(f"DEBUG: Days in range: {(end_date_date - start_date_date).days + 1}")
        
        # Get all users ordered by date_joined
        all_users = user_query.filter(User.date_joined.isnot(None)).order_by(User.date_joined).all()
        
        # Count users before start date
        users_before = 0
        users_by_day = {}
        
        for user in all_users:
            user_date = user.date_joined.date()
            if user_date < start_date_date:
                users_before += 1
            elif start_date_date <= user_date <= end_date_date:
                users_by_day[user_date] = users_by_day.get(user_date, 0) + 1
        
        print(f"DEBUG: Users before range: {users_before}")
        print(f"DEBUG: Users in range: {sum(users_by_day.values())}")
        print(f"DEBUG: Users by day: {users_by_day}")
        
        # Generate data for EVERY day in the range
        labels = []
        values = []
        cumulative = []
        running_total = users_before
        
        current_date = start_date_date
        while current_date <= end_date_date:
            date_str = current_date.strftime('%Y-%m-%d')
            day_count = users_by_day.get(current_date, 0)
            
            labels.append(date_str)
            values.append(day_count)
            running_total += day_count
            cumulative.append(running_total)
            
            current_date += timedelta(days=1)
        
        print(f"DEBUG: Generated {len(labels)} days of data")
        print(f"DEBUG: First 5 labels: {labels[:5]}")
        print(f"DEBUG: First 5 values: {values[:5]}")
        print(f"DEBUG: First 5 cumulative: {cumulative[:5]}")
        
        return {
            'labels': labels,
            'values': values,
            'cumulative': cumulative
        }
        
    except Exception as e:
        print(f"ERROR in get_member_growth_chart: {e}")
        import traceback
        traceback.print_exc()
        return {'labels': [], 'values': [], 'cumulative': []}
    

def get_member_categories_chart(user_query):
    """Return member categories in flat structure expected by frontend"""
    
    # Get gender distribution
    gender_counts = user_query.with_entities(
        User.gender, func.count(User.id)
    ).group_by(User.gender).all()
    
    # Get status distribution (first timer vs returning)
    total_users = user_query.count()
    first_timers = user_query.filter_by(is_first_timer=True).count()
    returning = total_users - first_timers
    
    # Create flat structure combining both dimensions
    labels = []
    values = []
    
    # Add gender data
    gender_map = {'M': 'Male', 'F': 'Female', 'O': 'Other'}
    for gender, count in gender_counts:
        if gender in gender_map:
            labels.append(gender_map[gender])
            values.append(count)
    
    # Add status data
    labels.append('First Timers')
    values.append(first_timers)
    labels.append('Returning')
    values.append(returning)
    
    return {
        'labels': labels,
        'values': values
    }

def get_session_performance_chart(session_query, attendance_query):
    """Get top performing sessions"""
    # Get top 10 sessions by attendance
    top_sessions = session_query\
        .outerjoin(Attendance, Session.id == Attendance.session_id)\
        .group_by(Session.id)\
        .order_by(func.count(Attendance.id).desc())\
        .limit(10)\
        .with_entities(
            Session.name,
            Session.date,
            func.count(Attendance.id).label('attendance'),
            Session.max_capacity
        ).all()
    
    labels = []
    attendance_data = []
    capacity_data = []
    
    for session in top_sessions:
        # Truncate long session names
        name = session.name
        if len(name) > 20:
            name = name[:17] + '...'
        
        labels.append(f"{name}\n{session.date.strftime('%b %d')}")
        attendance_data.append(session.attendance)
        capacity_data.append(session.max_capacity or 0)
    
    return {
        'labels': labels,
        'attendance': attendance_data,
        'capacity': capacity_data
    }

def get_checkin_methods_chart(attendance_query):
    """Get check-in methods distribution"""
    checkin_data = attendance_query\
        .group_by(Attendance.check_in_method)\
        .with_entities(
            Attendance.check_in_method,
            func.count(Attendance.id).label('count')
        ).all()
    
    # Map check-in methods to readable labels
    method_labels = {
        'qr_scan': 'QR Code Scan',
        'admin_add': 'Admin Added',
        'manual': 'Manual Entry',
        'self_checkin': 'Self Check-in'
    }
    
    labels = []
    values = []
    
    for data in checkin_data:
        if data.check_in_method:
            label = method_labels.get(data.check_in_method, data.check_in_method)
            labels.append(label)
            values.append(data.count)
    
    # Fill in missing methods with 0
    all_methods = ['QR Code Scan', 'Admin Added', 'Manual Entry', 'Self Check-in']
    for method in all_methods:
        if method not in labels:
            labels.append(method)
            values.append(0)
    
    return {
        'labels': labels,
        'values': values,
        'colors': ['#667eea', '#10b981', '#f59e0b', '#8b5cf6']
    }

def get_inventory_value_chart(item_query, start_date, end_date):
    """Get inventory value over time"""
    labels = []
    values = []
    
    if not start_date or not end_date:
        # Default to last 12 months
        end_date_obj = datetime.now().date()
        start_date_obj = end_date_obj - timedelta(days=365)
    else:
        start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    try:
        # Group by month of purchase
        value_data = item_query\
            .filter(Item.date_of_purchase.between(start_date_obj, end_date_obj))\
            .group_by(func.extract('year', Item.date_of_purchase), func.extract('month', Item.date_of_purchase))\
            .order_by(func.extract('year', Item.date_of_purchase), func.extract('month', Item.date_of_purchase))\
            .with_entities(
                func.extract('year', Item.date_of_purchase).label('year'),
                func.extract('month', Item.date_of_purchase).label('month'),
                func.sum(Item.amount * Item.quantity).label('total_value')
            ).all()
        
        for data in value_data:
            month_num = int(data.month) if data.month else 1
            year_num = int(data.year) if data.year else datetime.now().year
            labels.append(f"{calendar.month_abbr[month_num]} {year_num}")
            values.append(float(data.total_value or 0))
    
    except Exception as e:
        print(f"Error in inventory value chart: {e}")
    
    return {
        'labels': labels,
        'values': values
    }


def get_inventory_category_chart(item_query):
    """Get inventory distribution by category"""
    # Group by custodian_unit (or you could use manufacturer/model)
    category_data = item_query\
        .filter(Item.custodian_unit.isnot(None))\
        .group_by(Item.custodian_unit)\
        .order_by(func.sum(Item.amount * Item.quantity).desc())\
        .with_entities(
            Item.custodian_unit,
            func.count(Item.id).label('item_count'),
            func.sum(Item.amount * Item.quantity).label('total_value')
        ).all()
    
    labels = []
    item_counts = []
    values = []
    
    for data in category_data:
        if data.custodian_unit:
            labels.append(data.custodian_unit)
            item_counts.append(data.item_count)
            values.append(float(data.total_value or 0))
    
    # If no custodian_unit data, try manufacturer
    if not labels:
        manufacturer_data = item_query\
            .filter(Item.manufacturer.isnot(None))\
            .group_by(Item.manufacturer)\
            .order_by(func.sum(Item.amount * Item.quantity).desc())\
            .with_entities(
                Item.manufacturer,
                func.count(Item.id).label('item_count'),
                func.sum(Item.amount * Item.quantity).label('total_value')
            ).all()
        
        for data in manufacturer_data:
            if data.manufacturer:
                labels.append(data.manufacturer)
                item_counts.append(data.item_count)
                values.append(float(data.total_value or 0))
    
    return {
        'labels': labels[:10],  # Top 10 only
        'item_counts': item_counts[:10],
        'values': values[:10]
    }

def get_maintenance_cost_chart(maintenance_query, start_date, end_date):
    """Get maintenance cost over time"""
    labels = []
    values = []
    
    if not start_date or not end_date:
        # Default to last 12 months
        end_date_obj = datetime.now().date()
        start_date_obj = end_date_obj - timedelta(days=365)
    else:
        start_date_obj = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date_obj = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    try:
        # Group by month
        cost_data = maintenance_query\
            .filter(Maintenance.date.between(start_date_obj, end_date_obj))\
            .group_by(func.extract('year', Maintenance.date), func.extract('month', Maintenance.date))\
            .order_by(func.extract('year', Maintenance.date), func.extract('month', Maintenance.date))\
            .with_entities(
                func.extract('year', Maintenance.date).label('year'),
                func.extract('month', Maintenance.date).label('month'),
                func.sum(Maintenance.amount).label('total_cost')
            ).all()
        
        for data in cost_data:
            month_num = int(data.month) if data.month else 1
            year_num = int(data.year) if data.year else datetime.now().year
            labels.append(f"{calendar.month_abbr[month_num]} {year_num}")
            values.append(float(data.total_cost or 0))
    
    except Exception as e:
        print(f"Error in maintenance cost chart: {e}")
    
    return {
        'labels': labels,
        'values': values
    }


# Returns safe defaults
def get_safe_chart_data(query_func, *args, **kwargs):
    """Wrapper to ensure chart functions always return safe data"""
    try:
        return query_func(*args, **kwargs)
    except Exception as e:
        print(f"Chart data error: {e}")
        # Return safe empty data structure
        return {
            'labels': [],
            'values': []
        }



def get_maintenance_status_chart(maintenance_query):
    """Get maintenance status breakdown"""
    six_months_ago = datetime.now() - timedelta(days=180)
    nine_months_ago = datetime.now() - timedelta(days=270)
    
    # Get all items that have maintenance records
    items_with_maintenance = Item.query\
        .filter(Item.maintenance.any())\
        .all()
    
    status_counts = {
        'good': 0,      # Maintenance within last 6 months
        'due_soon': 0,  # Maintenance 6-9 months ago
        'overdue': 0,   # Maintenance more than 9 months ago
        'never': 0      # No maintenance ever
    }
    
    for item in items_with_maintenance:
        # Get most recent maintenance
        latest_maintenance = Maintenance.query\
            .filter_by(item_id=item.id)\
            .order_by(Maintenance.date.desc())\
            .first()
        
        if latest_maintenance:
            days_since = (datetime.now() - latest_maintenance.date).days
            
            if days_since <= 180:
                status_counts['good'] += 1
            elif days_since <= 270:
                status_counts['due_soon'] += 1
            else:
                status_counts['overdue'] += 1
        else:
            status_counts['never'] += 1
    
    return {
        'labels': ['Up to Date', 'Due Soon', 'Overdue', 'No Maintenance'],
        'values': [
            status_counts['good'],
            status_counts['due_soon'],
            status_counts['overdue'],
            status_counts['never']
        ],
        'colors': ['#10b981', '#f59e0b', '#ef4444', '#6b7280']
    }

# ==================== TABLE DATA FUNCTIONS ====================

def get_first_timers_table(user_query):
    """Get first timers for table display"""
    first_timers = user_query\
        .filter_by(is_first_timer=True)\
        .order_by(User.date_joined.desc())\
        .limit(20)\
        .all()
    
    table_data = []
    for user in first_timers:
        # Get attendance info
        attendance_count = Attendance.query.filter_by(user_id=user.id).count()
        last_attendance = Attendance.query\
            .filter_by(user_id=user.id)\
            .order_by(Attendance.check_in_time.desc())\
            .first()
        
        # Determine status
        if attendance_count >= 3:
            status = 'converted'
            status_text = 'Converted'
            status_class = 'success'
        elif attendance_count >= 1:
            status = 'attending'
            status_text = 'Attending'
            status_class = 'warning'
        else:
            status = 'new'
            status_text = 'New'
            status_class = 'secondary'
        
        table_data.append({
            'id': user.id,
            'name': f"{user.first_name} {user.last_name}",
            'email': user.email,
            'phone': user.phone_no,
            'joined': user.date_joined.strftime('%b %d, %Y') if user.date_joined else '',
            'attendance_count': attendance_count,
            'last_attendance': last_attendance.check_in_time.strftime('%b %d, %Y') if last_attendance else 'Never',
            'status': status,
            'status_text': status_text,
            'status_class': status_class
        })
    
    return table_data

def get_active_members_table(user_query, attendance_query):
    """Get most active members by attendance"""
    # Get users with their attendance counts
    active_members = user_query\
        .join(Attendance, User.id == Attendance.user_id)\
        .group_by(User.id)\
        .order_by(func.count(Attendance.id).desc())\
        .limit(20)\
        .with_entities(
            User.id,
            User.first_name,
            User.last_name,
            User.email,
            func.count(Attendance.id).label('attendance_count'),
            func.max(Attendance.check_in_time).label('last_active')
        ).all()
    
    table_data = []
    for member in active_members:
        # Calculate attendance rate (if we have total sessions)
        total_sessions = Session.query.count()
        attendance_rate = round((member.attendance_count / total_sessions * 100), 1) if total_sessions > 0 else 0
        
        table_data.append({
            'id': member.id,
            'name': f"{member.first_name} {member.last_name}",
            'email': member.email,
            'attendance_count': member.attendance_count,
            'last_active': member.last_active.strftime('%b %d, %Y') if member.last_active else 'Never',
            'attendance_rate': f"{attendance_rate}%",
            'engagement': get_engagement_level(member.attendance_count)
        })
    
    return table_data

def get_engagement_level(attendance_count):
    """Determine engagement level based on attendance count"""
    if attendance_count >= 20:
        return {'text': 'Very High', 'class': 'success'}
    elif attendance_count >= 10:
        return {'text': 'High', 'class': 'info'}
    elif attendance_count >= 5:
        return {'text': 'Medium', 'class': 'warning'}
    else:
        return {'text': 'Low', 'class': 'secondary'}


def get_sessions_table(session_query, attendance_query):
    """Get sessions for table display"""
    sessions = session_query\
        .order_by(Session.date.desc())\
        .limit(20)\
        .all()
    
    table_data = []
    current_date = datetime.now().date()  # Get current date
    
    for session in sessions:
        # Get attendance count for this session
        attendance_count = attendance_query\
            .filter_by(session_id=session.id)\
            .count()
        
        # Calculate occupancy rate
        capacity = session.max_capacity or 0
        occupancy_rate = round((attendance_count / capacity * 100), 1) if capacity > 0 else 0
        
        # Determine status
        if session.date < current_date:
            status = 'completed'
            status_text = 'Completed'
            status_class = 'secondary'
        elif session.date == current_date:
            status = 'today'
            status_text = 'Today'
            status_class = 'info'
        else:
            status = 'upcoming'
            status_text = 'Upcoming'
            status_class = 'success'
        
        table_data.append({
            'id': session.id,
            'name': session.name,
            'description': session.description,
            'date': session.date.strftime('%b %d, %Y'),
            'time': f"{session.start_time.strftime('%I:%M %p') if session.start_time else ''} - {session.end_time.strftime('%I:%M %p') if session.end_time else ''}",
            'location': session.location,
            'attendance': attendance_count,
            'capacity': capacity,
            'occupancy_rate': f"{occupancy_rate}%",
            'status': status,
            'status_text': status_text,
            'status_class': status_class
        })
    
    return table_data



def get_high_value_items_table(item_query):
    """Get high value inventory items - FIXED VERSION"""
    
    high_value_items = item_query\
        .order_by((Item.amount * Item.quantity).desc())\
        .limit(20)\
        .all()
    
    table_data = []
    current_datetime = get_current_datetime()
    
    for item in high_value_items:
        total_value = float(item.amount * item.quantity) if item.amount and item.quantity else 0
        
        # Get maintenance status
        latest_maintenance = Maintenance.query\
            .filter_by(item_id=item.id)\
            .order_by(Maintenance.date.desc())\
            .first()
        
        if latest_maintenance and latest_maintenance.date:
            # FIX: Use ensure_datetime on latest_maintenance.date
            maintenance_date = ensure_datetime(latest_maintenance.date)
            days_since = days_between(maintenance_date, current_datetime)
            
            if days_since <= 180:
                maintenance_status = 'good'
                status_text = 'Good'
                status_class = 'success'
            elif days_since <= 270:
                maintenance_status = 'due_soon'
                status_text = 'Due Soon'
                status_class = 'warning'
            else:
                maintenance_status = 'overdue'
                status_text = 'Overdue'
                status_class = 'danger'
        else:
            maintenance_status = 'never'
            status_text = 'No Maintenance'
            status_class = 'secondary'
        
        table_data.append({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'manufacturer': item.manufacturer,
            'model': item.model,
            'category': item.custodian_unit or 'Uncategorized',
            'purchase_date': ensure_date(item.date_of_purchase).strftime('%b %d, %Y') if item.date_of_purchase else '',
            'quantity': item.quantity,
            'unit_price': float(item.amount) if item.amount else 0,
            'total_value': total_value,
            'maintenance_status': maintenance_status,
            'maintenance_status_text': status_text,
            'maintenance_status_class': status_class,
            'last_maintenance': ensure_date(latest_maintenance.date).strftime('%b %d, %Y') if latest_maintenance and latest_maintenance.date else 'Never'
        })
    
    return table_data

def get_attention_items_table(item_query, maintenance_query):
    """Get items needing attention - COMPLETELY FIXED VERSION"""
    
    # Get all items
    all_items = item_query.all()
    
    items_needing_attention = []
    current_datetime = get_current_datetime()
    
    for item in all_items:
        # Get most recent maintenance
        latest_maintenance = Maintenance.query\
            .filter_by(item_id=item.id)\
            .order_by(Maintenance.date.desc())\
            .first()
        
        if not latest_maintenance:
            # Item never had maintenance
            priority = 'high'
            days_since = None
            status = 'No Maintenance'
            status_class = 'danger'
        else:
            if not latest_maintenance.date:
                # If maintenance exists but has no date
                priority = 'medium'
                days_since = None
                status = 'Unknown Date'
                status_class = 'warning'
            else:
                # FIX: Use ensure_datetime
                maintenance_date = ensure_datetime(latest_maintenance.date)
                days_since = days_between(maintenance_date, current_datetime)
                
                if days_since > 270:
                    priority = 'high'
                    status = 'Overdue'
                    status_class = 'danger'
                elif days_since > 180:
                    priority = 'medium'
                    status = 'Due Soon'
                    status_class = 'warning'
                else:
                    continue  # Skip items with recent maintenance
        
        items_needing_attention.append({
            'item': item,
            'latest_maintenance': latest_maintenance,
            'days_since': days_since,
            'priority': priority,
            'status': status,
            'status_class': status_class
        })
    
    # Sort by priority and days since
    items_needing_attention.sort(key=lambda x: (
        0 if x['priority'] == 'high' else 1 if x['priority'] == 'medium' else 2,
        x['days_since'] if x['days_since'] is not None else 9999
    ))
    
    # Convert to table format
    table_data = []
    for item_data in items_needing_attention[:20]:
        item = item_data['item']
        
        # Format last maintenance date
        last_maintenance_str = 'Never'
        if item_data['latest_maintenance'] and item_data['latest_maintenance'].date:
            last_maintenance_str = ensure_date(item_data['latest_maintenance'].date).strftime('%b %d, %Y')
        
        table_data.append({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'last_maintenance': last_maintenance_str,
            'days_since': item_data['days_since'] if item_data['days_since'] is not None else 'N/A',
            'priority': item_data['priority'],
            'status': item_data['status'],
            'status_class': item_data['status_class'],
            'estimated_cost': estimate_maintenance_cost(item)
        })
    
    return table_data


def estimate_maintenance_cost(item):
    """Estimate maintenance cost based on item value"""
    item_value = float(item.amount * item.quantity) if item.amount and item.quantity else 0
    
    if item_value > 10000:
        return '$500-$1000'
    elif item_value > 5000:
        return '$250-$500'
    elif item_value > 1000:
        return '$100-$250'
    elif item_value > 500:
        return '$50-$100'
    else:
        return '$20-$50'

def get_recent_maintenance_table(maintenance_query):
    """Get recent maintenance activities"""
    recent_maintenance = maintenance_query\
        .join(Item, Item.id == Maintenance.item_id)\
        .order_by(Maintenance.date.desc())\
        .limit(20)\
        .with_entities(
            Maintenance.id,
            Maintenance.date,
            Maintenance.maintenance_description,
            Maintenance.maintenance_vendor,
            Maintenance.amount,
            Item.name.label('item_name'),
            Item.description.label('item_description')
        ).all()
    
    table_data = []
    for maintenance in recent_maintenance:
        # Determine if maintenance was preventive or corrective
        description = maintenance.maintenance_description.lower()
        if any(word in description for word in ['prevent', 'routine', 'scheduled', 'regular']):
            type = 'preventive'
            type_text = 'Preventive'
            type_class = 'info'
        elif any(word in description for word in ['repair', 'fix', 'broken', 'damage', 'issue']):
            type = 'corrective'
            type_text = 'Corrective'
            type_class = 'warning'
        else:
            type = 'other'
            type_text = 'Other'
            type_class = 'secondary'
        
        table_data.append({
            'id': maintenance.id,
            'item_name': maintenance.item_name,
            'item_description': maintenance.item_description,
            'date': maintenance.date.strftime('%b %d, %Y'),
            'description': maintenance.maintenance_description,
            'vendor': maintenance.maintenance_vendor or 'Internal',
            'cost': float(maintenance.amount) if maintenance.amount else 0,
            'type': type,
            'type_text': type_text,
            'type_class': type_class
        })
    
    return table_data


def get_upcoming_maintenance_table(maintenance_query):
    """Get upcoming maintenance schedule"""
    # Get items and their last maintenance
    items_with_maintenance = Item.query\
        .filter(Item.maintenance.any())\
        .all()
    
    upcoming_maintenance = []
    current_datetime = datetime.now()  # Get current datetime
    
    for item in items_with_maintenance:
        # Get most recent maintenance
        latest_maintenance = Maintenance.query\
            .filter_by(item_id=item.id)\
            .order_by(Maintenance.date.desc())\
            .first()
        
        if latest_maintenance:
            # Convert to datetime if it's a date
            last_maintenance_dt = latest_maintenance.date
            if isinstance(last_maintenance_dt, date):
                last_maintenance_dt = datetime.combine(last_maintenance_dt, datetime.min.time())
            
            next_due_date = last_maintenance_dt + timedelta(days=180)
            days_until = (next_due_date - current_datetime).days
            
            if days_until <= 30:
                upcoming_maintenance.append({
                    'item': item,
                    'last_maintenance': latest_maintenance,
                    'next_due_date': next_due_date,
                    'days_until': days_until
                })
    
    # Sort by days until (ascending)
    upcoming_maintenance.sort(key=lambda x: x['days_until'])
    
    # Convert to table format
    table_data = []
    for item_data in upcoming_maintenance[:20]:
        item = item_data['item']
        
        # Determine priority
        if item_data['days_until'] <= 7:
            priority = 'high'
            priority_text = 'High'
            priority_class = 'danger'
        elif item_data['days_until'] <= 14:
            priority = 'medium'
            priority_text = 'Medium'
            priority_class = 'warning'
        else:
            priority = 'low'
            priority_text = 'Low'
            priority_class = 'info'
        
        table_data.append({
            'id': item.id,
            'name': item.name,
            'description': item.description,
            'last_maintenance': item_data['last_maintenance'].date.strftime('%b %d, %Y'),
            'next_due': item_data['next_due_date'].strftime('%b %d, %Y'),
            'days_until': item_data['days_until'],
            'priority': priority,
            'priority_text': priority_text,
            'priority_class': priority_class,
            'estimated_cost': estimate_maintenance_cost(item)
        })
    
    return table_data   


def calculate_filtered_kpis(user_query, session_query, attendance_query, item_query, maintenance_query):
    """Calculate all KPIs with applied filters"""
    
    # Get basic counts
    total_users = user_query.count()
    first_timers = user_query.filter_by(is_first_timer=True).count()
    returning_users = total_users - first_timers
    
    # Gender counts
    male_count = user_query.filter_by(gender='Male').count()
    female_count = user_query.filter_by(gender='Female').count()
    other_count = user_query.filter(
        User.gender.isnot(None),
        User.gender.notin_(['Male', 'Female'])
    ).count()
    
    # Session and attendance metrics
    total_sessions = session_query.count()
    upcoming_sessions = session_query.filter(Session.date >= datetime.now().date()).count()
    completed_sessions = session_query.filter(Session.date < datetime.now().date()).count()
    
    # Attendance calculations
    total_attendances = attendance_query.count()
    unique_attendees = attendance_query.with_entities(Attendance.user_id).distinct().count()
    
    # Calculate average attendance per session
    avg_attendance_per_session = 0
    if total_sessions > 0:
        avg_attendance_per_session = round(total_attendances / total_sessions, 1)
    
    # Calculate attendance rate (unique attendees / total users)
    attendance_rate = 0
    if total_users > 0:
        attendance_rate = round((unique_attendees / total_users) * 100, 1)
    
    # Inventory metrics
    total_items = item_query.count()
    
    # Calculate total inventory value
    inventory_value_result = db.session.query(
        func.sum(Item.amount * Item.quantity)
    ).filter(Item.id.in_([item.id for item in item_query.all()])).scalar()
    inventory_value = float(inventory_value_result) if inventory_value_result else 0.0
    
    # Items needing maintenance
    six_months_ago = datetime.now() - timedelta(days=180)
    items_needing_maintenance = 0
    for item in item_query.all():
        recent_maintenance = Maintenance.query.filter(
            Maintenance.item_id == item.id,
            Maintenance.date >= six_months_ago
        ).first()
        if not recent_maintenance:
            items_needing_maintenance += 1
    
    # Maintenance metrics
    total_maintenance_records = maintenance_query.count()
    
    # Calculate total maintenance cost
    maintenance_cost_result = db.session.query(
        func.sum(Maintenance.amount)
    ).filter(Maintenance.id.in_([m.id for m in maintenance_query.all()])).scalar()
    maintenance_cost = float(maintenance_cost_result) if maintenance_cost_result else 0.0
    
    # Average maintenance cost per item
    avg_maintenance_cost = 0
    if total_items > 0:
        avg_maintenance_cost = round(maintenance_cost / total_items, 2)
    
    # Calculate growth metrics (compared to previous period)
    # For now, we'll use placeholders. You might want to implement actual comparisons
    today = datetime.now()
    one_month_ago = today - timedelta(days=30)
    
    # New members in last month
    new_members_month = user_query.filter(User.date_joined >= one_month_ago).count()
    
    # New first timers in last month
    new_first_timers_month = user_query.filter(
        User.is_first_timer == True,
        User.date_joined >= one_month_ago
    ).count()
    
    # Attendance in last month
    last_month_attendance = attendance_query.join(Session).filter(
        Session.date >= one_month_ago.date()
    ).count()
    
    # Calculate trends (simplified - you might want more sophisticated calculations)
    member_growth_trend = 0
    if total_users > 0:
        member_growth_trend = round((new_members_month / total_users) * 100, 1)
    
    attendance_trend = 0
    if total_attendances > 0:
        attendance_trend = round((last_month_attendance / total_attendances) * 100, 1)
    
    # Engagement score (simplified calculation)
    engagement_score = 0
    if total_users > 0 and total_sessions > 0:
        # Average sessions attended per user
        avg_sessions_per_user = total_attendances / total_users
        # Normalize to a 0-100 scale (assuming 10+ sessions is perfect engagement)
        engagement_score = min(100, round((avg_sessions_per_user / 10) * 100, 1))
    
    # Return all KPIs
    return {
        # User KPIs
        'total_users': total_users,
        'first_timers': first_timers,
        'returning_users': returning_users,
        'male_count': male_count,
        'female_count': female_count,
        'other_count': other_count,
        'new_members': new_members_month,
        'member_growth': member_growth_trend,
        
        # Gender percentages
        'male_percent': round((male_count / total_users * 100), 1) if total_users > 0 else 0,
        'female_percent': round((female_count / total_users * 100), 1) if total_users > 0 else 0,
        'first_timer_percent': round((first_timers / total_users * 100), 1) if total_users > 0 else 0,
        
        # Session KPIs
        'session_count': total_sessions,
        'upcoming_sessions': upcoming_sessions,
        'completed_sessions': completed_sessions,
        'active_sessions': upcoming_sessions,  # Alias for consistency
        
        # Attendance KPIs
        'total_attendances': total_attendances,
        'unique_attendees': unique_attendees,
        'avg_attendance': attendance_rate,
        'avg_attendance_per_session': avg_attendance_per_session,
        'attendance_trend': attendance_trend,
        'last_month_attendance': last_month_attendance,
        
        # Inventory KPIs
        'total_items': total_items,
        'inventory_value': inventory_value,
        'items_needing_maintenance': items_needing_maintenance,
        'good_items': total_items - items_needing_maintenance,
        'attention_items': items_needing_maintenance,
        'maintenance_items': items_needing_maintenance,  # Alias
        
        # Maintenance KPIs
        'total_maintenance': total_maintenance_records,
        'maintenance_cost': maintenance_cost,
        'avg_maintenance_cost': avg_maintenance_cost,
        'pending_maintenance': items_needing_maintenance,
        
        # Engagement and Conversion
        'engagement_score': engagement_score,
        'conversion_rate': calculate_conversion_rate(user_query),
        'retention_rate': calculate_retention_rate(user_query, attendance_query),
        
        # Quick Stats (for the overview cards)
        'member_progress': min(100, round((total_users / 1000) * 100)),  # Assuming 1000 member target
        'attendance_progress': min(100, attendance_rate),
        'first_timer_progress': min(100, round((first_timers / total_users * 100))) if total_users > 0 else 0,
        'engagement_progress': engagement_score,
        
        # Additional calculated fields
        'avg_duration': calculate_avg_session_duration(session_query),
        'peak_time': calculate_peak_attendance_time(attendance_query),
        'best_day': calculate_best_attended_day(attendance_query),
        'retention_rate_percent': calculate_retention_rate(user_query, attendance_query)
    }

def calculate_conversion_rate(user_query):
    """Calculate first-timer to regular conversion rate"""
    # Get first timers who attended more than 3 sessions
    first_timers = user_query.filter_by(is_first_timer=True).all()
    
    if not first_timers:
        return 0
    
    converted_count = 0
    for user in first_timers:
        attendance_count = Attendance.query.filter_by(user_id=user.id).count()
        if attendance_count >= 3:
            converted_count += 1
    
    return round((converted_count / len(first_timers)) * 100, 1)

def calculate_retention_rate(user_query, attendance_query):
    """Calculate member retention rate (users who attended in last 30 days)"""
    total_users = user_query.count()
    if total_users == 0:
        return 0
    
    thirty_days_ago = datetime.now() - timedelta(days=30)
    
    # Count users with attendance in last 30 days
    active_users = attendance_query\
        .filter(Attendance.check_in_time >= thirty_days_ago)\
        .with_entities(Attendance.user_id)\
        .distinct()\
        .count()
    
    return round((active_users / total_users) * 100, 1)

def calculate_avg_session_duration(session_query):
    """Calculate average session duration"""
    sessions_with_times = session_query.filter(
        Session.start_time.isnot(None),
        Session.end_time.isnot(None)
    ).all()
    
    if not sessions_with_times:
        return "N/A"
    
    total_minutes = 0
    for session in sessions_with_times:
        if session.start_time and session.end_time:
            # Calculate duration in minutes
            start_dt = datetime.combine(datetime.now().date(), session.start_time)
            end_dt = datetime.combine(datetime.now().date(), session.end_time)
            duration = (end_dt - start_dt).total_seconds() / 60
            total_minutes += duration
    
    avg_minutes = round(total_minutes / len(sessions_with_times), 0)
    return f"{int(avg_minutes)} min"

def calculate_peak_attendance_time(attendance_query):
    """Calculate peak attendance time"""
    # Group by hour of check-in
    attendance_by_hour = attendance_query\
        .filter(Attendance.check_in_time.isnot(None))\
        .group_by(func.extract('hour', Attendance.check_in_time))\
        .order_by(func.count(Attendance.id).desc())\
        .with_entities(
            func.extract('hour', Attendance.check_in_time).label('hour'),
            func.count(Attendance.id).label('count')
        ).first()
    
    if not attendance_by_hour:
        return "N/A"
    
    hour = int(attendance_by_hour.hour)
    time_str = f"{hour % 12 or 12}:00 {'AM' if hour < 12 else 'PM'}"
    return time_str

def calculate_best_attended_day(attendance_query):
    """Calculate best attended day of week"""
    # Group by day of week
    attendance_by_day = attendance_query\
        .join(Session, Session.id == Attendance.session_id)\
        .group_by(func.extract('dow', Session.date))\
        .order_by(func.count(Attendance.id).desc())\
        .with_entities(
            func.extract('dow', Session.date).label('day_num'),
            func.count(Attendance.id).label('count')
        ).first()
    
    if not attendance_by_day:
        return "N/A"
    
    day_map = {
        1: 'Sunday',
        2: 'Monday',
        3: 'Tuesday',
        4: 'Wednesday',
        5: 'Thursday',
        6: 'Friday',
        7: 'Saturday'
    }
    
    return day_map.get(int(attendance_by_day.day_num), 'N/A')    



def get_filtered_chart_data(user_query, session_query, attendance_query, item_query, maintenance_query, start_date=None, end_date=None):
    """Get all chart data with applied filters"""
    print("=" * 60)
    print("DEBUG get_filtered_chart_data START")
    print(f"DEBUG: Dates received - start_date: {start_date}, end_date: {end_date}")
    print(f"DEBUG: user_query has {user_query.count()} users")
    print(f"DEBUG: attendance_query has {attendance_query.count()} attendances")
    print("=" * 60)
    
    # Define empty chart structure
    empty_chart = {'labels': [], 'values': [], 'cumulative': []} 
    empty_section = {
        'attendance_trend': empty_chart.copy(),
        'gender_distribution': empty_chart.copy(),
        'age_distribution': empty_chart.copy(),
        'inventory_status': empty_chart.copy(),
        'maintenance_timeline': []
    }
    
    charts = {
        'overview': empty_section.copy(),
        'members': {
            'member_growth': empty_chart.copy(),
            'member_categories': empty_chart.copy()
        },
        'attendance': {
            'session_performance': empty_chart.copy(),
            'checkin_methods': empty_chart.copy()
        },
        'inventory': {
            'inventory_value': empty_chart.copy(),
            'inventory_category': empty_chart.copy()
        },
        'maintenance': {
            'maintenance_cost': empty_chart.copy(),
            'maintenance_status': empty_chart.copy()
        }
    }
    
    try:
        print("DEBUG: Getting overview charts...")
        
        # Attendance trend chart
        try:
            print("  Getting attendance trend...")
            attendance_trend_data = get_attendance_trend_chart(
                attendance_query, start_date, end_date
            )
            charts['overview']['attendance_trend'] = attendance_trend_data
            print(f"  Attendance trend: {len(attendance_trend_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in attendance trend: {e}")
            charts['overview']['attendance_trend'] = empty_chart.copy()
        
        # Gender distribution chart
        try:
            print("  Getting gender distribution...")
            gender_data = get_gender_distribution_chart(user_query)
            charts['overview']['gender_distribution'] = gender_data
            print(f"  Gender distribution: {len(gender_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in gender distribution: {e}")
            charts['overview']['gender_distribution'] = empty_chart.copy()
        
        # Age distribution chart
        try:
            print("  Getting age distribution...")
            age_data = get_age_distribution_chart(user_query)
            charts['overview']['age_distribution'] = age_data
            print(f"  Age distribution: {len(age_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in age distribution: {e}")
            charts['overview']['age_distribution'] = empty_chart.copy()
        
        # Inventory status chart
        try:
            print("  Getting inventory status...")
            inventory_status_data = get_inventory_status_chart(item_query, maintenance_query)
            charts['overview']['inventory_status'] = inventory_status_data
            print(f"  Inventory status: {len(inventory_status_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in inventory status: {e}")
            charts['overview']['inventory_status'] = empty_chart.copy()
        
        # Maintenance timeline
        try:
            print("  Getting maintenance timeline...")
            maintenance_timeline_data = get_maintenance_timeline_data(maintenance_query)
            charts['overview']['maintenance_timeline'] = maintenance_timeline_data
            print(f"  Maintenance timeline: {len(maintenance_timeline_data)} items")
        except Exception as e:
            print(f"  ERROR in maintenance timeline: {e}")
            charts['overview']['maintenance_timeline'] = []
        
        print("\nDEBUG: Getting member charts...")
        
        # Member growth chart
        try:
            print("  Getting member growth...")
            # IMPORTANT FIX: Use date_joined instead of created_at
            member_growth_data = get_member_growth_chart(user_query, start_date, end_date)
            print(f"  Member growth raw data: {member_growth_data}")
            print(f"  Member growth labels: {member_growth_data.get('labels', [])[:5]}")
            print(f"  Member growth values: {member_growth_data.get('values', [])[:5]}")
            print(f"  Member growth cumulative: {member_growth_data.get('cumulative', [])[:5]}")
            
            # Store in members section
            charts['members']['member_growth'] = member_growth_data
            # OPTION B: Also store in overview section for simpler frontend access
            charts['overview']['member_growth'] = member_growth_data
            
            print(f"  Member growth: {len(member_growth_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in member growth: {e}")
            import traceback
            traceback.print_exc()
            empty = {'labels': [], 'values': [], 'cumulative': []}
            charts['members']['member_growth'] = empty
            charts['overview']['member_growth'] = empty
        
        # Member categories chart
        try:
            print("  Getting member categories...")
            member_categories_data = get_member_categories_chart(user_query)
            print(f"  Member categories data: {member_categories_data}")
            
            # Store in members section
            charts['members']['member_categories'] = member_categories_data
            # OPTION B: Also store in overview section
            charts['overview']['member_categories'] = member_categories_data
            
            print(f"  Member categories: {len(member_categories_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in member categories: {e}")
            empty = {'labels': [], 'values': []}
            charts['members']['member_categories'] = empty
            charts['overview']['member_categories'] = empty
        
        print("\nDEBUG: Getting attendance charts...")
        
        # Session performance chart
        try:
            print("  Getting session performance...")
            session_performance_data = get_session_performance_chart(session_query, attendance_query)
            charts['attendance']['session_performance'] = session_performance_data
            print(f"  Session performance: {len(session_performance_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in session performance: {e}")
            charts['attendance']['session_performance'] = empty_chart.copy()
        
        # Checkin methods chart
        try:
            print("  Getting checkin methods...")
            checkin_methods_data = get_checkin_methods_chart(attendance_query)
            charts['attendance']['checkin_methods'] = checkin_methods_data
            print(f"  Checkin methods: {len(checkin_methods_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in checkin methods: {e}")
            charts['attendance']['checkin_methods'] = empty_chart.copy()
        
        print("\nDEBUG: Getting inventory charts...")
        
        # Inventory value chart
        try:
            print("  Getting inventory value...")
            inventory_value_data = get_inventory_value_chart(item_query, start_date, end_date)
            charts['inventory']['inventory_value'] = inventory_value_data
            print(f"  Inventory value: {len(inventory_value_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in inventory value: {e}")
            charts['inventory']['inventory_value'] = empty_chart.copy()
        
        # Inventory category chart
        try:
            print("  Getting inventory category...")
            inventory_category_data = get_inventory_category_chart(item_query)
            charts['inventory']['inventory_category'] = inventory_category_data
            print(f"  Inventory category: {len(inventory_category_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in inventory category: {e}")
            charts['inventory']['inventory_category'] = empty_chart.copy()
        
        print("\nDEBUG: Getting maintenance charts...")
        
        # Maintenance cost chart
        try:
            print("  Getting maintenance cost...")
            maintenance_cost_data = get_maintenance_cost_chart(maintenance_query, start_date, end_date)
            charts['maintenance']['maintenance_cost'] = maintenance_cost_data
            print(f"  Maintenance cost: {len(maintenance_cost_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in maintenance cost: {e}")
            charts['maintenance']['maintenance_cost'] = empty_chart.copy()
        
        # Maintenance status chart
        try:
            print("  Getting maintenance status...")
            maintenance_status_data = get_maintenance_status_chart(maintenance_query)
            charts['maintenance']['maintenance_status'] = maintenance_status_data
            print(f"  Maintenance status: {len(maintenance_status_data.get('labels', []))} labels")
        except Exception as e:
            print(f"  ERROR in maintenance status: {e}")
            charts['maintenance']['maintenance_status'] = empty_chart.copy()
        
        # Add summary debug
        print("\n" + "=" * 60)
        print("DEBUG: FINAL CHARTS SUMMARY")
        print(f"Overview - member_growth: {len(charts['overview'].get('member_growth', {}).get('labels', []))} labels")
        print(f"Overview - member_categories: {len(charts['overview'].get('member_categories', {}).get('labels', []))} labels")
        print(f"Members - member_growth: {len(charts['members']['member_growth'].get('labels', []))} labels")
        print(f"Members - member_categories: {len(charts['members']['member_categories'].get('labels', []))} labels")
        print("=" * 60)
        
        return charts
        
    except Exception as e:
        print(f"\nCRITICAL ERROR in get_filtered_chart_data: {e}")
        import traceback
        traceback.print_exc()
        print("=" * 60)
        
        # Return empty structure on critical error
        return {
            'overview': {
                'attendance_trend': {'labels': [], 'values': []},
                'gender_distribution': {'labels': [], 'values': []},
                'age_distribution': {'labels': [], 'values': []},
                'inventory_status': {'labels': [], 'values': []},
                'maintenance_timeline': [],
                'member_growth': {'labels': [], 'values': [], 'cumulative': []},  # Added
                'member_categories': {'labels': [], 'values': []}  # Added
            },
            'members': {
                'member_growth': {'labels': [], 'values': [], 'cumulative': []},
                'member_categories': {'labels': [], 'values': []}
            },
            'attendance': {
                'session_performance': {'labels': [], 'values': []},
                'checkin_methods': {'labels': [], 'values': []}
            },
            'inventory': {
                'inventory_value': {'labels': [], 'values': []},
                'inventory_category': {'labels': [], 'values': []}
            },
            'maintenance': {
                'maintenance_cost': {'labels': [], 'values': []},
                'maintenance_status': {'labels': [], 'values': []}
            }
        }
    
# Add helper functions for date handling
# date_helpers.py (update with all functions)
from datetime import datetime, date, timedelta

@views.route('/api/debug-user-dates')
@login_required
def debug_user_dates():
    """Check what date_joined values actually exist"""
    try:
        users = User.query.all()
        
        date_joined_info = []
        null_count = 0
        old_dates = []
        
        for user in users:
            if user.date_joined is None:
                null_count += 1
                date_joined_info.append({
                    'id': user.id,
                    'username': user.username,
                    'date_joined': None,
                    'status': 'NULL'
                })
            else:
                date_str = user.date_joined.strftime('%Y-%m-%d %H:%M:%S')
                date_joined_info.append({
                    'id': user.id,
                    'username': user.username,
                    'date_joined': date_str,
                    'status': 'Has value'
                })
                if user.date_joined.year < 2025:  # Adjust this year as needed
                    old_dates.append({
                        'id': user.id,
                        'username': user.username,
                        'date_joined': date_str
                    })
        
        return jsonify({
            'success': True,
            'total_users': len(users),
            'null_date_joined': null_count,
            'old_dates_count': len(old_dates),
            'old_dates': old_dates[:10],  # First 10 old dates
            'sample_users': date_joined_info[:20],  # First 20 users
            'has_date_joined_field': hasattr(User, 'date_joined')
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500



@views.route('/api/test-date-joined')
@login_required
def test_date_joined():
    """Test date_joined field and member growth"""
    try:
        # Get date parameters
        start_date = request.args.get('start_date', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
        end_date = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))
        
        # Parse dates
        start = datetime.strptime(start_date, '%Y-%m-%d')
        end = datetime.strptime(end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        
        # Query users by date_joined
        users_in_range = User.query.filter(
            User.date_joined >= start,
            User.date_joined <= end
        ).order_by(User.date_joined).all()
        
        # Get all users for total count
        total_users = User.query.count()
        
        # Get users before start date
        users_before = User.query.filter(User.date_joined < start).count()
        
        # Group by date
        users_by_day = {}
        for user in users_in_range:
            day = user.date_joined.date().isoformat()
            users_by_day[day] = users_by_day.get(day, 0) + 1
        
        return jsonify({
            'success': True,
            'debug_info': {
                'total_users': total_users,
                'users_in_date_range': len(users_in_range),
                'users_before_start': users_before,
                'start_date': start_date,
                'end_date': end_date,
                'users_by_day': users_by_day,
                'sample_users': [
                    {
                        'id': u.id,
                        'username': u.username,
                        'date_joined': u.date_joined.isoformat() if u.date_joined else None
                    } for u in users_in_range[:5]  # First 5 users
                ]
            },
            'member_growth': {
                'labels': list(users_by_day.keys()),
                'values': list(users_by_day.values()),
                'cumulative': []  # You can calculate this if needed
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

def ensure_datetime(dt_obj):
    """Ensure an object is a datetime (not date) - your existing function"""
    if isinstance(dt_obj, datetime):
        return dt_obj
    elif isinstance(dt_obj, date):
        return datetime.combine(dt_obj, datetime.min.time())
    else:
        return datetime.now()

def ensure_date(dt_obj):
    """Ensure an object is a date (not datetime) - your existing function"""
    if isinstance(dt_obj, date):
        return dt_obj
    elif isinstance(dt_obj, datetime):
        return dt_obj.date()
    else:
        return datetime.now().date()

def days_between(date1, date2):
    """Safe days calculation between two date/datetime objects - your existing function"""
    date1_dt = ensure_datetime(date1)
    date2_dt = ensure_datetime(date2)
    return (date2_dt - date1_dt).days

# Additional helper functions to add
def get_current_datetime():
    """Get current datetime for consistent use"""
    return datetime.now()

def get_current_date():
    """Get current date for consistent use"""
    return datetime.now().date()

def safe_date_add(dt_obj, days=0):
    """Safely add days to a date/datetime object"""
    dt = ensure_datetime(dt_obj)
    return dt + timedelta(days=days)

def safe_date_subtract(dt_obj, days=0):
    """Safely subtract days from a date/datetime object"""
    dt = ensure_datetime(dt_obj)
    return dt - timedelta(days=days)

def is_before(dt1, dt2):
    """Check if dt1 is before dt2 (handles mixed types)"""
    dt1_clean = ensure_datetime(dt1)
    dt2_clean = ensure_datetime(dt2)
    return dt1_clean < dt2_clean

def is_after(dt1, dt2):
    """Check if dt1 is after dt2 (handles mixed types)"""
    dt1_clean = ensure_datetime(dt1)
    dt2_clean = ensure_datetime(dt2)
    return dt1_clean > dt2_clean

def date_to_string(dt_obj, format='%b %d, %Y'):
    """Safely convert date/datetime to string"""
    if not dt_obj:
        return ''
    dt = ensure_datetime(dt_obj)
    return dt.strftime(format)




@views.route('/api/test-basic')
@login_required
def test_basic():
    """Test basic analytics without filters"""
    try:
        # Test basic counts
        user_count = User.query.count()
        session_count = Session.query.count()
        item_count = Item.query.count()
        
        return jsonify({
            'success': True,
            'users': user_count,
            'sessions': session_count,
            'items': item_count,
            'message': 'Basic counts working'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


@views.route('/api/test-filters')
@login_required
def test_filters():
    """Test each filter type individually"""
    results = {}
    
    # Test 1: Date filter
    try:
        start_date = '2024-01-01'
        end_date = '2024-12-31'
        
        session_query = Session.query
        session_query = apply_session_filters(session_query, [], start_date, end_date)
        sessions_with_date = session_query.count()
        
        results['date_filter'] = {
            'success': True,
            'sessions_count': sessions_with_date
        }
    except Exception as e:
        results['date_filter'] = {
            'success': False,
            'error': str(e)
        }
    
    # Test 2: Session filter
    try:
        session_ids = []
        # Get first session ID if exists
        first_session = Session.query.first()
        if first_session:
            session_ids = [str(first_session.id)]
        
        session_query = Session.query
        session_query = apply_session_filters(session_query, session_ids, None, None)
        sessions_with_id = session_query.count()
        
        results['session_filter'] = {
            'success': True,
            'sessions_count': sessions_with_id,
            'session_id': session_ids[0] if session_ids else None
        }
    except Exception as e:
        results['session_filter'] = {
            'success': False,
            'error': str(e)
        }
    
    # Test 3: Member type filter
    try:
        user_query = User.query
        user_query = apply_user_filters(user_query, ['first_timer'], [])
        first_timers = user_query.count()
        
        results['member_filter'] = {
            'success': True,
            'first_timers': first_timers
        }
    except Exception as e:
        results['member_filter'] = {
            'success': False,
            'error': str(e)
        }
    
    return jsonify(results)


@views.route('/api/sessions', methods=['GET'])
def get_sessions():
    try:
        # Query sessions from your database
        sessions = Session.query.order_by(Session.name).all()
        
        # Format into list of dictionaries
        sessions_data = [{"id": session.id, "name": session.name} for session in sessions]
        
        return jsonify(sessions_data)
    
    except Exception as e:
        print(f"Error fetching sessions: {e}")
        return jsonify({"error": "Failed to fetch sessions"}), 500



@views.route('/api/test/attendance-trend')
@login_required
def test_attendance_trend():
    """Test endpoint for attendance trend chart"""
    try:
        # Get some test dates
        from datetime import datetime, timedelta
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=30)
        
        # Get unfiltered attendance query
        attendance_query = Attendance.query
        
        print("\n" + "="*60)
        print("DIRECT TEST of get_attendance_trend_chart")
        print("="*60)
        
        # Call the function
        result = get_attendance_trend_chart(
            attendance_query,
            start_date.strftime('%Y-%m-%d'),
            end_date.strftime('%Y-%m-%d')
        )
        
        return jsonify({
            'success': True,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'result': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500        