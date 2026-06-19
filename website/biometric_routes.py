# website/biometric_routes.py
from flask import Blueprint, request, jsonify
from .models import db, User, WebAuthnCredential
from .webauthn_config import RP_ID, RP_NAME, ORIGIN, CHALLENGE_TIMEOUT
import base64
import json

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


# Test endpoint - add this temporarily
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
        ]
    })



@biometric_bp.route('/api/biometric/register/begin', methods=['POST'])
def start_enrollment():
    """Step 1: Start biometric enrollment"""
    import sys
    
    try:
        data = request.json
        user_id = data.get('user_id')
        
        # ======== DEBUG: Print all config values ========
        print("\n" + "="*50)
        print("🔍 WEBAUTHN CONFIG DEBUG")
        print(f"RP_ID: '{RP_ID}'")
        print(f"RP_NAME: '{RP_NAME}'")
        print(f"ORIGIN: '{ORIGIN}'")
        print(f"Request Host: '{request.host}'")
        print(f"Request Origin: '{request.headers.get('Origin')}'")
        print(f"Request URL: '{request.url}'")
        print(f"Request base_url: '{request.base_url}'")
        print(f"User ID: {user_id}")
        print("="*50 + "\n")
        sys.stdout.flush()
        # =================================================
        
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        print(f"📝 Generating registration options...")
        sys.stdout.flush()
        
        # Generate registration options
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
        
        # Store challenge
        pending_registrations[user.id] = registration_options.challenge
        
        # Format for frontend
        public_key_options = {
            'rp': {
                'name': RP_NAME,
                'id': RP_ID
            },
            'user': {
                'id': base64.b64encode(str(user.id).encode()).decode(),
                'name': user.username,
                'displayName': f"{user.first_name} {user.last_name}"
            },
            'challenge': base64.b64encode(registration_options.challenge).decode(),
            'pubKeyCredParams': [
                {'type': 'public-key', 'alg': -7},   # ES256
                {'type': 'public-key', 'alg': -257},  # RS256
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
        
        print(f"✅ Returning options to frontend")
        print(f"   RP ID in options: '{public_key_options['rp']['id']}'")
        print(f"   Origin expected: '{ORIGIN}'")
        sys.stdout.flush()
        
        return jsonify({
            'success': True,
            'options': public_key_options
        })
        
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
        print(f"  Credential ID: {data.get('id', '')[:50]}...")
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
        
        # For webauthn 2.8.0, use AuthenticatorAttestationResponse
        from webauthn.helpers.structs import (
            RegistrationCredential,
            AuthenticatorAttestationResponse,
        )
        
        # Create the response object properly
        attestation_response = AuthenticatorAttestationResponse(
            attestation_object=attestation_object_bytes,
            client_data_json=client_data_json_bytes,
        )
        
        # Create the credential
        credential = RegistrationCredential(
            id=data.get('id'),
            raw_id=raw_id_bytes,
            response=attestation_response,  # Use the object, not a dict
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
        print(f"  Credential ID: {verification.credential_id}")
        sys.stdout.flush()
        
        # Store the credential
        new_credential = WebAuthnCredential(
            user_id=user.id,
            credential_id=verification.credential_id,
            public_key=json.dumps({
                'public_key': base64.b64encode(verification.credential_public_key).decode(),
                'sign_count': verification.sign_count
            }),
            sign_count=verification.sign_count,
            device_name=data.get('device_name', 'Unknown Device')
        )
        
        db.session.add(new_credential)
        db.session.commit()
        
        # Clear challenge
        del pending_registrations[user.id]
        
        print(f"✅ Credential stored in database")
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