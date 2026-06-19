// biometric.js
class BiometricAuth {
    constructor() {
        this.isSupported = this.checkSupport();
    }

    checkSupport() {
        return window.PublicKeyCredential !== undefined;
    }

    async registerBiometric(userId) {
        if (!this.isSupported) {
            throw new Error('Biometric authentication not supported on this device');
        }

        try {
            // Step 1: Get registration options from server
            const response = await fetch('/api/biometric/register/begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });

            const data = await response.json();
            if (!data.success) throw new Error(data.error);

            // Step 2: Create credentials using platform authenticator
            const options = this.prepareRegistrationOptions(data.options);
            const credential = await navigator.credentials.create({
                publicKey: options
            });

            // Step 3: Send credential to server
            const credentialData = {
                id: credential.id,
                rawId: this.arrayBufferToBase64(credential.rawId),
                response: {
                    attestationObject: this.arrayBufferToBase64(
                        credential.response.attestationObject
                    ),
                    clientDataJSON: this.arrayBufferToBase64(
                        credential.response.clientDataJSON
                    ),
                },
                type: credential.type,
                device_name: this.getDeviceName()
            };

            const verifyResponse = await fetch('/api/biometric/register/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ...credentialData, user_id: userId })
            });

            const verifyData = await verifyResponse.json();
            if (!verifyData.success) throw new Error(verifyData.error);

            return verifyData;
        } catch (error) {
            throw error;
        }
    }

    async authenticateAndAddToSession(sessionId) {
        if (!this.isSupported) {
            throw new Error('Biometric authentication not supported on this device');
        }

        try {
            // Step 1: Get authentication options from server
            const response = await fetch('/api/biometric/auth/begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionId })
            });

            const data = await response.json();
            if (!data.success) throw new Error(data.error);

            // Step 2: Get credential using platform authenticator
            const options = this.prepareAuthenticationOptions(data.options);
            const assertion = await navigator.credentials.get({
                publicKey: options
            });

            // Step 3: Send assertion to server
            const assertionData = {
                id: assertion.id,
                rawId: this.arrayBufferToBase64(assertion.rawId),
                response: {
                    authenticatorData: this.arrayBufferToBase64(
                        assertion.response.authenticatorData
                    ),
                    clientDataJSON: this.arrayBufferToBase64(
                        assertion.response.clientDataJSON
                    ),
                    signature: this.arrayBufferToBase64(
                        assertion.response.signature
                    ),
                    userHandle: assertion.response.userHandle ? 
                        this.arrayBufferToBase64(assertion.response.userHandle) : null,
                },
                type: assertion.type,
                session_id: sessionId
            };

            const verifyResponse = await fetch('/api/biometric/auth/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(assertionData)
            });

            const verifyData = await verifyResponse.json();
            if (!verifyData.success) throw new Error(verifyData.error);

            return verifyData;
        } catch (error) {
            throw error;
        }
    }

    prepareRegistrationOptions(options) {
        return {
            rp: options.rp,
            user: {
                id: this.base64ToArrayBuffer(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName,
            },
            challenge: this.base64ToArrayBuffer(options.challenge),
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            authenticatorSelection: {
                authenticatorAttachment: 'platform', // Use built-in biometric
                userVerification: 'required',
                residentKey: 'preferred',
            },
            attestation: options.attestation,
        };
    }

    prepareAuthenticationOptions(options) {
        return {
            challenge: this.base64ToArrayBuffer(options.challenge),
            timeout: options.timeout,
            rpId: options.rpId,
            allowCredentials: options.allowCredentials.map(cred => ({
                type: cred.type,
                id: this.base64ToArrayBuffer(cred.id),
            })),
            userVerification: 'required',
        };
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        bytes.forEach(byte => binary += String.fromCharCode(byte));
        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    getDeviceName() {
        const ua = navigator.userAgent;
        const platform = navigator.platform;
        if (/iPhone/.test(ua)) return 'iPhone';
        if (/iPad/.test(ua)) return 'iPad';
        if (/Android/.test(ua)) return 'Android Device';
        if (/Windows/.test(ua)) return 'Windows PC';
        if (/Mac/.test(ua)) return 'Mac';
        return `${platform} - Unknown`;
    }
}

// Usage example:
const biometricAuth = new BiometricAuth();

// Register biometric for a user
async function enrollBiometric(userId) {
    try {
        const result = await biometricAuth.registerBiometric(userId);
        alert('Biometric enrolled successfully!');
    } catch (error) {
        alert('Enrollment failed: ' + error.message);
    }
}

// Add user to session via biometric
async function addToSessionViaBiometric(sessionId) {
    try {
        const result = await biometricAuth.authenticateAndAddToSession(sessionId);
        alert(result.message);
        // Update UI with user info
    } catch (error) {
        alert('Authentication failed: ' + error.message);
    }
}