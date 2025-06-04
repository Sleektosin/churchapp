#from crypt import methods
#from crypt import methods
#from crypt import methods
import json
import random
from PIL import Image
import qrcode
import base64
from tabnanny import check
from io import BytesIO
from flask import Flask
from datetime import timedelta
from unicodedata import category
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
import requests
from .models import User, Session,session_users, Role,Item, Maintenance 
from website import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from flask_login import LoginManager
import os
from flask import send_from_directory
from sqlalchemy.ext.automap import automap_base
from . import create_app, mail, api
from flask_paginate import Pagination, get_page_args
from flask_sqlalchemy import SQLAlchemy
from json2html import json2html
import urllib.parse
import html, re
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




@views.route('/addUsersToSession/<id>',methods=['GET', 'POST'])  
def addUsersToSession_handler(id):
    if id:
        returned_qr_code = request.form.get('qr_code')
        email = extract_user_info(returned_qr_code)
        user = User.query.filter_by(email=email).first()
        session = Session.query.get(id)
        if user:
            existing_entry = db.session.query(session_users).filter_by(session_id=session.id, user_id=user.id).first()
            if not existing_entry:
                stmt = session_users.insert().values(
                    session_id=session.id,
                    user_id=user.id,
                    date=datetime.now()
                )
                db.session.execute(stmt)
                db.session.commit()
                flash('User added to session successfully!', 'success')
            else:
                flash('User is already in this session.', 'error')
        else:
            flash('User not found.', 'error')

    return render_template('adduserstosession.html', user=current_user, session_data=session)
        

# adding maintenance to product
@views.route('/addMaintenanceToProduct/<id>', methods=['POST'])  
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
    if request.method == 'GET':
        return render_template("login.html")
    
    # POST handling
    email = request.form.get("email")
    password = request.form.get("password")        

    try:
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email does not exist.', category='error')
            return render_template("login.html", user=current_user)
        
        if check_password_hash(user.password, password):
            # get random code for user's authentication
            code = generate_code()
            session['pending_user'] = user.username
            session['validation_code'] = code
            #send_login_validation_email(user.email,user.username, code)  # Send code to user's email
            flash('Logged in successfully!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.sessions'))
            # return redirect(url_for('views.prevalidate'))
        else:
            # Never reveal whether password was wrong vs email doesn't exist
            flash('Invalid credentials', category='error')
            return render_template("login.html", user=current_user)
            
    except OperationalError as e:
        # Handle database connection error
        flash('Database connection error. Please try again later.', category='error')
        return render_template("login.html", user=current_user)


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
    
    for result in results:
        date_str = result.session_date # already a string
        if date_str not in data:
            data[date_str] = {'male': 0, 'female': 0}
        data[date_str][result.user_gender] = result.user_count

    # Convert the data to JSON
    data_json = json.dumps(data)
    return render_template("home.html", user=current_user, user_count = user_count, 
                           session_count = session_count, male_count = male_count,
                             female_count = female_count,data = data_json)


@views.route('/home')
@login_required
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
def itemdelete(id):
    my_data = Item.query.get(id)
    if my_data:
        db.session.delete(my_data)
        db.session.commit()
        return jsonify({"message": "Item Deleted Successfully"}), 200
    else:
        return jsonify({"message": "Item Not Found"}), 404        




# Route to delete session
@views.route('/maintenancdelete/<id>/', methods=['POST'])
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
        session_users.c.date.label('added_date')
        ).join(session_users).filter(session_users.c.session_id == session_id)

    # Apply search filter
    if search_value:
        base_query = base_query.filter(
            (User.username.ilike(f'%{search_value}%')) | 
            (User.email.ilike(f'%{search_value}%')) |
            func.cast(session_users.c.date, db.String).like(f'%{search_value}%')
        )

    # Get the total number of records before filtering
    total_records = base_query.count()

    # Apply pagination
    paginated_query = base_query.offset(start).limit(length)

    # Fetch filtered data
    items = paginated_query.all()

    # Prepare data for DataTables response
    data = []
    nigeria_tz = pytz.timezone('Africa/Lagos')
    for item in items:
        if item.added_date:
            # Check if added_date is already a datetime object
            if isinstance(item.added_date, datetime):
                added_date_utc = pytz.utc.localize(item.added_date)
            else:
                # If added_date is a date object, convert it to a datetime object
                added_date_datetime = datetime.combine(item.added_date, time.min)
                added_date_utc = pytz.utc.localize(added_date_datetime)
        
            # Convert the UTC datetime to Nigeria time zone
            added_date_nigeria = added_date_utc.astimezone(nigeria_tz)
            
            # Format the datetime to a string
            added_date_str = added_date_nigeria.strftime('%Y-%m-%d %H:%M:%S')
        else:
            added_date_str = None
        data.append({
            'Id': item.id,
            'username': item.username,
            'email': item.email,
            'added_date': added_date_str,
            'update_button': '<button class="btn btn-primary btn-sm">Update</button>',
            'delete_button': '<button class="btn btn-danger btn-sm">Delete</button>',
        })

    response = {
        'draw': draw,
        'recordsTotal': total_records,
        'recordsFiltered': total_records if not search_value else len(items),
        'data': data,
    }

    return jsonify(response)


@views.route('/get_roles', methods=['GET'])
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
def update_session_data():
    try:
        # Get form data from the AJAX request
        editactivitySessionId = request.form.get('session_id')
        editactivityName = request.form.get('editactivityName')
        editactivityDescription = request.form.get('editactivityDescription')
        editactivitydate = request.form.get('editactivitydate')
  
        # Convert the date_of_birth from string to Python date object
        if editactivitydate:
            try:
                # Adjust format string according to the date format received, e.g., "%Y-%m-%d" for "2024-09-12"
                editactivitydate = datetime.strptime(editactivitydate, "%Y-%m-%d").date()
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Invalid date format'}), 400

        # Find the user by ID
        session = Session.query.get(editactivitySessionId)

        if session:
            # Update the user's details
            session.name = editactivityName
            session.description = editactivityDescription
            session.date = editactivitydate
            # Commit the changes to the database
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Session data updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': 'Session not found'}), 404

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return jsonify({'status': 'error', 'message': str(e)}), 500



@views.route('/update_item_data', methods=['POST'])
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





@views.route('/get_items_data', methods=['POST','GET'])
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

    # Base query to get session data
    base_query = db.session.query(
        Session.id,
        Session.name,
        Session.description,
        Session.date,
        func.coalesce(func.count(session_users.c.user_id), 0).label('user_count')
    ).outerjoin(session_users).group_by(Session.id)

    # Apply search filter
    if search_value:
        base_query = base_query.filter(
    or_(
        Session.name.ilike(f'%{search_value}%'),
        Session.description.ilike(f'%{search_value}%'),
        func.cast(Session.date, db.String).ilike(f'%{search_value}%')
        )
    )   

    # Get the total number of records before filtering
    total_records = db.session.query(func.count(Session.id)).scalar()

    # Get the total number of filtered records
    total_filtered_records = base_query.count()

    # Apply pagination and sort by date (newest first)
    query = base_query.order_by(Session.date.desc()).offset(start).limit(length)  # <-- Changed to date.desc()

    # Fetch filtered data
    items = query.all()

    # Prepare data for DataTables response
    data = []
    for item in items:
        data.append({
            'Id': item.id,
            'name': item.name,
            'description': item.description,
            'date': item.date.strftime('%Y-%m-%d'),  # Format date if needed
            'user_count': item.user_count,
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


@views.route('/get_sessions_summary_data', methods=['POST','GET'])
def get_sessions_summary_data():
    # Define parameters for server-side processing
    draw = request.form.get('draw')
    start = int(request.form.get('start'))
    length = int(request.form.get('length'))
    search_value = request.form.get('search[value]').strip().lower()

    # Base query to get session data
    base_query = db.session.query(
        Session.date,
        Session.name,
        func.coalesce(func.count(session_users.c.user_id), 0).label('user_count')
    ).outerjoin(session_users).group_by(Session.id)

    # Apply search filter
    if search_value:
        base_query = base_query.filter(
            Session.name.like(f'%{search_value}%') |
            Session.description.like(f'%{search_value}%') |
            func.cast(Session.date, db.String).like(f'%{search_value}%')
        )

    # Get the total number of records before filtering
    total_records = db.session.query(func.count(Session.id)).scalar()

    # Get the total number of filtered records
    total_filtered_records = base_query.count()

    # Apply pagination and sort by date (newest first)
    query = base_query.order_by(Session.date.desc()).offset(start).limit(length)  # <-- Changed to date.desc()

    # Fetch filtered data
    items = query.all()

    # Prepare data for DataTables response
    data = []
    for item in items:
        data.append({
            'date': item.date.strftime('%Y-%m-%d'),  # Format date if needed
            'name': item.name,
            'user_count': item.user_count,
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
@login_required
def addsession():
    if request.method == 'POST':
        activityname = request.form.get("activityname")
        activitydescription = request.form.get("activitydescription")
        activitydate = request.form.get("activitydate")
        date_object = datetime.strptime(activitydate, '%Y-%m-%d').date()
        new_activity = Session(name = activityname, description = activitydescription, date = date_object)
        db.session.add(new_activity)
        db.session.commit()
        flash("New Activity Added Successfully")
        return redirect(url_for('views.sessions'))
    


@views.route('/additem', methods=['POST'])
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
@login_required   
def activity(id):
    if id:
        # Query to get session id, session name, and count of users for each session
        session_data = db.session.query(Session.id, Session.name).filter(Session.id == id).first()
        return render_template("adduserstosession.html",user=current_user, session_data = session_data,activity=True)



@views.route('/item/<id>', methods=['GET'])
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




@views.route('/get_product_maintenance/<product_id>/maintenance', methods=['GET', 'POST'])    
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
@login_required
def userdetails(id):
    user = User.query.get(id)
    if not user:
        flash("User not found")
        return redirect(url_for('home'))
    
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
    
    return render_template("userdetail.html", 
                        user=user, 
                        qr_code_data=qr_code_data,userdetails=True)

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
@login_required
def sessions():
    all_activity = db.session.query(
    Session.id,
    Session.name,
    Session.description,
    Session.date,
    func.coalesce(func.count(session_users.c.user_id),0).label('user_count')
).outerjoin(session_users).group_by(Session.id, Session.name, Session.description, Session.date).all()
    return render_template('session.html', user=current_user, activities = all_activity)




@views.route('/items', methods=['GET', 'POST'])
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
