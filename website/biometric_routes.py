# website/biometric_routes.py
from flask import Blueprint, request, jsonify
from .models import db, User, WebAuthnCredential, Session, Attendance
from .webauthn_config import RP_ID, RP_NAME, ORIGIN, CHALLENGE_TIMEOUT
import base64
import json
from datetime import datetime

# Import webauthn library
from webauthn import generate_registration_options, verify_registration_response
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)

# Create the Blueprint
biometric_bp = Blueprint('biometric', __name__)

# Store challenges temporarily (use Redis in production)
pending_registrations = {}


# Test endpoint
@biometric_bp.route('/api/biometric/ping', methods=['GET'])
def ping():
    return jsonify({
        'success': True,
        'message': 'Biometric API is online!',
        'routes': [
            '/api/biometric/register/begin (POST)',
            '/api/biometric/register/complete (POST)',
            '/api/biometric/status/<user_id> (GET)',
            '/api/biometric/remove/<user_id>/<credential_id> (DELETE)',
            '/api/biometric/auth/begin (POST)',
            '/api/biometric/auth/complete/<session_id> (POST)',
        ]
    })


@biometric_bp.route('/api/biometric/register/begin', methods=['POST'])
def start_enrollment():
    """Step 1: Start biometric enrollment"""
    import sys
    
    try:
        data = request.json
        user_id = data.get('user_id')
        
        print("\n" + "="*50)
        print("🔍 WEBAUTHN CONFIG DEBUG")
        print(f"RP_ID: '{RP_ID}'")
        print(f"RP_NAME: '{RP_NAME}'")
        print(f"ORIGIN: '{ORIGIN}'")
        print(f"Request Host: '{request.host}'")
        print(f"Request Origin: '{request.headers.get('Origin')}'")
        print(f"User ID: {user_id}")
        print("="*50 + "\n")
        sys.stdout.flush()
        
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        print(f"📝 Generating registration options...")
        sys.stdout.flush()
        
        registration_options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=str(user.id).encode(),
            user_name=user.username,
            user_display_name=f"{user.first_name} {user.last_name}",
            attestation='none',
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment='platform',
                user_verification=UserVerificationRequirement.REQUIRED,
                resident_key='required',
            ),
            timeout=CHALLENGE_TIMEOUT,
        )
        
        print(f"✅ Registration options generated")
        sys.stdout.flush()
        
        pending_registrations[user.id] = registration_options.challenge
        
        public_key_options = {
            'rp': {'name': RP_NAME, 'id': RP_ID},
            'user': {
                'id': base64.b64encode(str(user.id).encode()).decode(),
                'name': user.username,
                'displayName': f"{user.first_name} {user.last_name}"
            },
            'challenge': base64.b64encode(registration_options.challenge).decode(),
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},
                {'type': 'public-key', 'alg': -257},
            ],
            'timeout': CHALLENGE_TIMEOUT,
            'excludeCredentials': [],
            'authenticatorSelection': {
                'authenticatorAttachment': 'platform',
                'userVerification': 'required',
                'residentKey': 'required',
            },
            'attestation': 'none',
        }
        
        return jsonify({'success': True, 'options': public_key_options})
        
    except Exception as e:
        print(f"❌ ERROR in start_enrollment: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        return jsonify({'error': f'Failed to start enrollment: {str(e)}'}), 500


@biometric_bp.route('/api/biometric/register/complete', methods=['POST'])
def complete_enrollment():
    """Step 2: Complete biometric enrollment"""
    import sys
    
    try:
        data = request.json
        print(f"\n📦 Complete enrollment data received:")
        print(f"  User ID: {data.get('user_id')}")
        sys.stdout.flush()
        
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get stored challenge
        challenge = pending_registrations.get(user.id)
        if not challenge:
            return jsonify({'error': 'No pending enrollment found. Please start again.'}), 400
        
        print(f"  Stored challenge length: {len(challenge)}")
        sys.stdout.flush()
        
        # Decode base64 values to bytes
        raw_id_bytes = base64.b64decode(data.get('rawId'))
        client_data_json_bytes = base64.b64decode(data.get('response', {}).get('clientDataJSON'))
        attestation_object_bytes = base64.b64decode(data.get('response', {}).get('attestationObject'))
        
        # Create the response object
        attestation_response = AuthenticatorAttestationResponse(
            attestation_object=attestation_object_bytes,
            client_data_json=client_data_json_bytes,
        )
        
        # Create the credential
        credential = RegistrationCredential(
            id=data.get('id'),
            raw_id=raw_id_bytes,
            response=attestation_response,
            type='public-key'
        )
        
        print(f"  Verifying registration...")
        sys.stdout.flush()
        
        # Verify the registration
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )
        
        print(f"✅ Verification successful")
        sys.stdout.flush()
        
        # ✅ FIX: Base64 encode and strip padding (=)
        if isinstance(verification.credential_id, bytes):
            credential_id_b64 = base64.b64encode(verification.credential_id).decode('utf-8').rstrip('=')
        else:
            credential_id_b64 = str(verification.credential_id).rstrip('=')
        
        print(f"  Credential ID (stripped): {credential_id_b64[:50]}...")
        sys.stdout.flush()
        
        # ✅ FIX: Also strip padding from public key
        if isinstance(verification.credential_public_key, bytes):
            public_key_encoded = base64.b64encode(verification.credential_public_key).decode('utf-8').rstrip('=')
        else:
            public_key_encoded = str(verification.credential_public_key).rstrip('=')
        
        # Store the credential with stripped base64 (no padding)
        new_credential = WebAuthnCredential(
            user_id=user.id,
            credential_id=credential_id_b64,
            public_key=json.dumps({
                'public_key': public_key_encoded,
                'sign_count': verification.sign_count
            }),
            sign_count=verification.sign_count,
            device_name=data.get('device_name', 'Unknown Device')
        )
        
        db.session.add(new_credential)
        db.session.commit()
        
        # Clear challenge
        del pending_registrations[user.id]
        
        print(f"✅ Credential stored in database (without padding)")
        sys.stdout.flush()
        
        return jsonify({
            'success': True,
            'message': 'Fingerprint enrolled successfully!',
            'device_name': new_credential.device_name
        })
        
    except Exception as e:
        print(f"❌ Complete enrollment error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        db.session.rollback()
        return jsonify({'error': f'Enrollment failed: {str(e)}'}), 500


@biometric_bp.route('/api/biometric/status/<int:user_id>', methods=['GET'])
def check_biometric_status(user_id):
    """Check if user has biometric enrolled"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    credentials = WebAuthnCredential.query.filter_by(user_id=user_id).all()
    
    return jsonify({
        'has_biometric': len(credentials) > 0,
        'devices': [
            {
                'id': cred.id,
                'device_name': cred.device_name,
                'created_at': cred.created_at.isoformat(),
                'last_used': cred.last_used_at.isoformat()
            } for cred in credentials
        ]
    })


@biometric_bp.route('/api/biometric/remove/<int:user_id>/<int:credential_id>', methods=['DELETE'])
def remove_biometric(user_id, credential_id):
    """Remove a biometric credential"""
    credential = WebAuthnCredential.query.filter_by(
        id=credential_id, 
        user_id=user_id
    ).first()
    
    if not credential:
        return jsonify({'error': 'Credential not found'}), 404
    
    device_name = credential.device_name
    db.session.delete(credential)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Biometric for {device_name} removed successfully'
    })


# ============================================================
# NEW: FINGERPRINT AUTHENTICATION FOR SESSION CHECK-IN
# ============================================================

@biometric_bp.route('/api/biometric/auth/begin', methods=['POST'])
def biometric_auth_begin():
    """Start fingerprint authentication for session check-in"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'Session ID required'}), 400
        
        # Get all enrolled credentials
        all_credentials = WebAuthnCredential.query.all()
        
        if not all_credentials:
            return jsonify({
                'success': False,
                'error': 'No users have enrolled fingerprints yet'
            }), 404
        
        from webauthn import generate_authentication_options
        
        # Build allowCredentials with proper base64 IDs
        allow_credentials = []
        for cred in all_credentials:
            try:
                base64.b64decode(cred.credential_id)
                allow_credentials.append({'type': 'public-key', 'id': cred.credential_id})
            except:
                encoded = base64.b64encode(cred.credential_id.encode() if isinstance(cred.credential_id, str) else cred.credential_id).decode()
                allow_credentials.append({'type': 'public-key', 'id': encoded})
        
        authentication_options = generate_authentication_options(
            rp_id=RP_ID,
            timeout=CHALLENGE_TIMEOUT,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        
        pending_registrations[f"auth_{session_id}"] = {
            'challenge': authentication_options.challenge,
            'session_id': session_id
        }
        
        options_dict = {
            'challenge': base64.b64encode(authentication_options.challenge).decode(),
            'timeout': CHALLENGE_TIMEOUT,
            'rpId': RP_ID,
            'allowCredentials': allow_credentials,
            'userVerification': 'required',
        }
        
        return jsonify({
            'success': True,
            'options': options_dict,
            'enrolled_users_count': len(all_credentials)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@biometric_bp.route('/api/biometric/auth/complete/<int:session_id>', methods=['POST'])
def biometric_auth_complete(session_id):
    """Complete fingerprint authentication and add user to session"""
    import sys
    
    try:
        data = request.json
        credential_id = data.get('credential_id')
        
        print(f"\n" + "="*50)
        print(f"🔍 AUTH COMPLETE DEBUG")
        print(f"="*50)
        print(f"  Session ID from URL: {session_id}")
        print(f"  Credential ID received: {credential_id[:40] if credential_id else 'None'}...")
        print(f"  All pending auth keys: {[k for k in pending_registrations.keys() if 'auth_' in str(k)]}")
        print(f"  Looking for key: auth_{session_id}")
        print(f"  Key exists: {f'auth_{session_id}' in pending_registrations}")
        sys.stdout.flush()
        
        # Get stored challenge
        challenge_data = pending_registrations.get(f"auth_{session_id}")
        
        if not challenge_data:
            print(f"  ❌ Challenge NOT FOUND for auth_{session_id}")
            print(f"  Available keys: {list(pending_registrations.keys())}")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'No pending authentication. Please start again.'
            }), 400
        
        print(f"  ✅ Challenge found!")
        print(f"  Stored session ID in challenge: {challenge_data.get('session_id')}")
        sys.stdout.flush()
        
        # Find the credential in database
        print(f"\n  🔎 Looking up credential in database...")
        stored_credential = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        
        if not stored_credential:
            print(f"  ❌ Credential NOT FOUND in database")
            print(f"  Searching for credential_id: {credential_id[:40]}...")
            
            # Print all credentials in DB for debugging
            all_creds = WebAuthnCredential.query.all()
            print(f"  Total credentials in DB: {len(all_creds)}")
            for i, cred in enumerate(all_creds):
                print(f"    {i+1}. User {cred.user_id}: {cred.credential_id[:40]}...")
            sys.stdout.flush()
            
            return jsonify({
                'success': False,
                'error': 'Fingerprint not recognized. Have you enrolled?'
            }), 404
        
        user = stored_credential.user
        print(f"  ✅ Found user: {user.first_name} {user.last_name} (ID: {user.id})")
        sys.stdout.flush()
        
        # Get the session
        print(f"\n  📋 Looking up session {session_id}...")
        session_obj = Session.query.get(session_id)
        
        if not session_obj:
            print(f"  ❌ Session NOT FOUND")
            sys.stdout.flush()
            return jsonify({'success': False, 'error': 'Session not found'}), 404
        
        print(f"  ✅ Session found: {session_obj.name}")
        sys.stdout.flush()
        
        # Check if already checked in
        existing = Attendance.query.filter_by(user_id=user.id, session_id=session_id).first()
        
        if existing:
            print(f"  ⚠️ User already checked in")
            sys.stdout.flush()
            return jsonify({
                'success': True,
                'already_checked_in': True,
                'message': f'{user.first_name} {user.last_name} is already checked in!',
                'user': user.to_dict()
            })
        
        # Check capacity
        if session_obj.max_capacity:
            current_count = Attendance.query.filter_by(session_id=session_id).count()
            print(f"  Current attendance: {current_count}/{session_obj.max_capacity}")
            if current_count >= session_obj.max_capacity:
                print(f"  ❌ Session at full capacity")
                sys.stdout.flush()
                return jsonify({'success': False, 'error': 'Session is at full capacity'}), 400
        
        # Add attendance
        print(f"  ✅ Adding user to session...")
        new_attendance = Attendance(
            user_id=user.id,
            session_id=session_id,
            check_in_time=datetime.utcnow(),
            status='present'
        )
        db.session.add(new_attendance)
        stored_credential.last_used_at = datetime.utcnow()
        stored_credential.sign_count = (stored_credential.sign_count or 0) + 1
        db.session.commit()
        
        # Clear challenge
        del pending_registrations[f"auth_{session_id}"]
        
        print(f"  🎉 SUCCESS! {user.first_name} {user.last_name} checked in!")
        print(f"="*50 + "\n")
        sys.stdout.flush()
        
        return jsonify({
            'success': True,
            'message': f'{user.first_name} {user.last_name} checked in successfully!',
            'user': user.to_dict()
        })
        
    except Exception as e:
        print(f"  ❌ EXCEPTION: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        db.session.rollback()
        return jsonify({'error': f'Server error: {str(e)}'}), 500
    

@biometric_bp.route('/api/biometric/list-routes', methods=['GET'])
def list_all_routes():
    """List all registered routes in this blueprint"""
    import flask
    routes = []
    for rule in flask.current_app.url_map.iter_rules():
        if 'biometric' in rule.rule:
            routes.append({
                'route': rule.rule,
                'methods': list(rule.methods),
                'endpoint': rule.endpoint
            })
    return jsonify({'biometric_routes': routes})
