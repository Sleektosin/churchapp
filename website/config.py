import os

class Config(object):
    
    SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
    MAIL_FROM_EMAIL = os.getenv('MAIL_FROM_EMAIL')



    