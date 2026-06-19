# website/webauthn_config.py
import os

RP_ID = 'localhost'
RP_NAME = 'Church Attendance System'
CHALLENGE_TIMEOUT = 60000

if os.environ.get('RENDER'):
    RP_ID = 'churchapp-8ael.onrender.com'
    ORIGIN = 'https://churchapp-8ael.onrender.com'
else:
    ORIGIN = 'http://localhost:5000'  # Changed to localhost