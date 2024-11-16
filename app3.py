from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2 import PasswordHasher
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from os import urandom
import logging
import os
import base64

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Flask Setup
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_FILE_DIR'] = './.flask_session/'
app.config['SESSION_COOKIE_SECURE'] = False
Session(app)

class EmptyForm(FlaskForm):
    pass

csrf = CSRFProtect(app)

# Database setup
DB_FILE = "secure_chat.db"

# Password Hashing
ph = PasswordHasher()

def hash_password(password):
    return ph.hash(password)

def verify_password(password_hash, password):
    try:
        return ph.verify(password_hash, password)
    except Exception:
        return False

# Get DB connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_FILE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


#def encrypt_with_aes(message, shared_secret):
#    """Encrypt a message using AES-GCM"""
#    try:
#        key = b64decode(key)
#        # Ensure that the shared secret is the correct length (e.g., 32 bytes for AES-256)
#        nonce = get_random_bytes(16)
#        cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)
#        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
#        encrypted_data = b64encode(nonce + tag + ciphertext).decode()
#        return encrypted_data
#    except Exception as e:
#        logging.error(f"Encryption failed: {str(e)}")
#        raise ValueError(f"Encryption failed: {str(e)}")
#
#
#        
#def decrypt_with_aes(data, key):
#    """Decrypt data using AES-GCM"""
#    try:
#        data = b64decode(data)
#        key = b64decode(key)
#        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
#        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
#        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
#        return decrypted.decode()
#    except Exception as e:
#        logging.error(f"Decryption failed: {str(e)}")
#        raise ValueError(f"Decryption failed: {str(e)}")

def encrypt_with_aes(message, shared_secret):
    """Encrypt a message using AES-GCM"""
    try:
        # Ensure that the shared secret is the correct length (e.g., 32 bytes for AES-256)
        shared_secret = shared_secret[:32]  # Truncate to 256-bit length if needed
        shared_secret = b64decode(shared_secret)  # Decode shared secret if it's base64-encoded

        nonce = get_random_bytes(16)  # Generate a nonce
        cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())  # Ensure message is bytes
        encrypted_data = b64encode(nonce + tag + ciphertext).decode()  # Combine and encode the result
        return encrypted_data
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")


def decrypt_with_aes(data, shared_secret):
    """Decrypt data using AES-GCM"""
    try:
        # Ensure that the shared secret is the correct length (e.g., 32 bytes for AES-256)
        shared_secret = shared_secret[:32]  # Truncate to 256-bit length if needed
        shared_secret = b64decode(shared_secret)  # Decode shared secret if it's base64-encoded

        data = b64decode(data)  # Decode the encrypted data
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]  # Extract nonce, tag, and ciphertext

        cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify
        return decrypted.decode()  # Return the decrypted message as string
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

# X3DH Key Exchange Function
def perform_x3dh_exchange(private_key_str, recipient_public_key_str):
    private_key_bytes = base64.b64decode(private_key_str)
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    
    recipient_public_key_bytes = base64.b64decode(recipient_public_key_str)
    recipient_public_key = x25519.X25519PublicKey.from_public_bytes(recipient_public_key_bytes)
    
    shared_secret = private_key.exchange(recipient_public_key)
    return shared_secret

# Double Ratchet Key Derivation
def derive_ratchet_key(shared_secret, counter):
    """Derive a new key using shared secret and counter for Double Ratchet"""
    kdf = PBKDF2HMAC(
        algorithm='sha256', 
        salt=shared_secret, 
        length=32, 
        iterations=100000, 
        backend=default_backend()
    )
    return kdf.derive(counter.to_bytes(16, 'big'))

def update_ratchet_keys(shared_secret, counter):
    """Updates the ratchet key for the next message"""
    return derive_ratchet_key(shared_secret, counter)

# Sesame Key Management for Multiple Devices
def create_sesame_session_key(shared_secret, device_identifier):
    """Create a unique session key for each device using shared secret and device identifier"""
    kdf = PBKDF2HMAC(
        algorithm='sha256',
        salt=device_identifier.encode(),
        length=32,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)


# EdDSA & VRF (XEdDSA & VXEdDSA)
def generate_ed25519_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    private_b64 = base64.b64encode(private_bytes).decode('utf-8')
    public_b64 = base64.b64encode(public_bytes).decode('utf-8')
    
    return private_b64, public_b64


# Sign Message using VRF (EdDSA with Verifiable Random Function)
def sign_message_vrf(message, private_key):
    """Sign a message and return the VRF output"""
    signature = private_key.sign(message.encode())
    vrf_output = private_key.public_key().verifiable_random_function(message.encode())
    return signature, vrf_output

# Verify VRF Signature
def verify_signature_vrf(signature, vrf_output, message, public_key):
    """Verify a signature with VRF"""
    try:
        public_key.verify(signature, message.encode())
        # You can verify the VRF output here as needed.
        return True
    except Exception:
        return False

def sign_message(message, private_key_str):
    private_key_bytes = base64.b64decode(private_key_str)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(message.encode())
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(message, signature_b64, public_key_str):
    signature = base64.b64decode(signature_b64)
    public_key_bytes = base64.b64decode(public_key_str)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    
    try:
        public_key.verify(signature, message.encode())
        return True
    except Exception:
        return False

# Routes for Login and Chat
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session and "private_key" in session:
        return redirect(url_for("chat"))

    form = EmptyForm()
    if request.method == "POST" and form.validate_on_submit():
        username = request.form["username"]
        password = request.form["password"]
        
        try:
            db = get_db()
            c = db.cursor()
            c.execute("SELECT password_hash, private_key FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            
            if user and verify_password(user[0], password):
                session.clear()
                session["username"] = username
                session.permanent = True

                try:
                    private_key = decrypt_private_key(user[1], password)
                    private_key_b64 = b64encode(private_key).decode('utf-8')
                    session["private_key"] = private_key_b64
                    flash("Login successful!", "success")
                except Exception as e:
                    session.clear()
                    flash(f"Failed to decrypt private key: {str(e)}", "error")
                    return redirect(url_for("login"))
                
                return redirect(url_for("chat"))
            else:
                flash("Invalid username or password!", "error")
        except Exception as e:
            flash(f"Login error: {str(e)}", "error")
            
    return render_template("login.html", form=form)


@app.route("/chat", methods=["GET", "POST"])
def chat():
    if "username" not in session:
        flash("Please login first!", "error")
        return redirect(url_for("login"))
        
    if "private_key" not in session:
        flash("Session expired. Please login again!", "error")
        return redirect(url_for("login"))

    form = EmptyForm()
    db = get_db()
    c = db.cursor()

    try:
        c.execute("SELECT username FROM users WHERE username != ?", (session["username"],))
        users = c.fetchall()

        if request.method == "POST" and form.validate_on_submit():
            recipient = request.form.get("recipient")
            message = request.form.get("message")

            if not recipient or not message:
                flash("Both recipient and message are required!", "error")
                return redirect(url_for("chat"))

            try:
                c.execute("SELECT public_key FROM users WHERE username = ?", (recipient,))
                recipient_key_row = c.fetchone()

                if not recipient_key_row:
                    flash("Recipient not found!", "error")
                    return redirect(url_for("chat"))

                shared_secret = perform_x3dh_exchange(session["private_key"], recipient_key_row[0])
                encrypted_message = encrypt_with_aes(message, b64encode(shared_secret).decode())

                c.execute("""
                    INSERT INTO messages (sender, recipient, message)
                    VALUES (?, ?, ?)
                """, (session["username"], recipient, encrypted_message))
                db.commit()
                flash("Message sent successfully!", "success")
            except Exception as e:
                flash(f"Error sending message: {str(e)}", "error")

        # Fetch and decrypt messages
        c.execute("""
            SELECT sender, recipient, message, timestamp
            FROM messages
            WHERE sender = ? OR recipient = ?
            ORDER BY timestamp DESC
        """, (session["username"], session["username"]))
        messages = c.fetchall()

        decrypted_messages = []
        for msg in messages:
            try:
                other_user = msg["recipient"] if msg["sender"] == session["username"] else msg["sender"]
                c.execute("SELECT public_key FROM users WHERE username = ?", (other_user,))
                other_user_key = c.fetchone()

                shared_secret = perform_x3dh_exchange(session["private_key"], other_user_key[0])
                decrypted_message = decrypt_with_aes(msg["message"], b64encode(shared_secret).decode())

                decrypted_messages.append({
                    "sender": msg["sender"],
                    "recipient": msg["recipient"],
                    "message": decrypted_message,
                    "timestamp": msg["timestamp"]
                })

            except Exception as e:
                logging.error(f"Message decryption error: {str(e)}")
                decrypted_messages.append({
                    "sender": msg["sender"],
                    "recipient": msg["recipient"],
                    "message": f"[Message Error: {str(e)}]",
                    "timestamp": msg["timestamp"]
                })

        return render_template("chat.html", users=users, messages=decrypted_messages, form=form)

    except Exception as e:
        flash(f"Error in chat: {str(e)}", "error")
        return redirect(url_for("login"))



import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def encrypt_private_key(private_key_bytes, password):
    """Encrypt private key using a key derived from password."""
    # Derive encryption key from password
    encryption_key, salt = derive_key_from_password(password)
    
    # Encrypt the private key
    cipher = AES.new(encryption_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_bytes)
    
    # Combine salt + nonce + tag + ciphertext
    encrypted_data = salt + cipher.nonce + tag + ciphertext
    return b64encode(encrypted_data).decode()



def decrypt_private_key(encrypted_private_key, password):
    """Decrypt private key using a key derived from password."""
    try:
        # Decode the base64 data
        encrypted_data = b64decode(encrypted_private_key)
        
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        tag = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]
        
        # Derive the same encryption key from password
        encryption_key, _ = derive_key_from_password(password, salt)
        
        logging.debug(f"Decryption attempt with salt: {salt}, nonce: {nonce}")
        
        # Decrypt the data
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Return the decrypted private key as binary data (or base64)
        logging.debug(f"Successfully decrypted private key.")
        
        return decrypted_data  # Return as binary data

    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        raise ValueError(f"Failed to decrypt private key: {str(e)}")



def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive an encryption key from password using PBKDF2."""
    if salt is None:
        salt = urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt


@app.route("/register", methods=["GET", "POST"])
def register():
    if "username" in session:
        return redirect(url_for("chat"))

    form = EmptyForm()
    if request.method == "POST" and form.validate_on_submit():
        reg_username = request.form["username"]
        reg_password = request.form["password"]

        try:
            db = get_db()
            c = db.cursor()
            c.execute("SELECT username FROM users WHERE username = ?", (reg_username,))
            if c.fetchone():
                flash("Username already exists!", "error")
            else:
                private_key, public_key = generate_x3dh_key_pair()
                # Encrypt private key with password-derived key
                encrypted_private_key = encrypt_private_key(
                    b64decode(private_key), 
                    reg_password
                )

                c.execute("""
                    INSERT INTO users (username, password_hash, private_key, public_key)
                    VALUES (?, ?, ?, ?)
                """, (
                    reg_username,
                    hash_password(reg_password),
                    encrypted_private_key,
                    public_key
                ))
                db.commit()
                flash("Account created successfully! Please login.", "success")
                return redirect(url_for("login"))

        except Exception as e:
            flash(f"Registration error: {str(e)}", "error")

    return render_template("register.html", form=form)



@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("encryption_key", None)
    session.pop("private_key", None)
    return redirect(url_for("login"))


# Reset Database Functionality
def reset_database():
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()
        g.pop('db', None)

    try:
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
    except Exception as e:
        raise Exception(f"Failed to delete database file: {str(e)}")

    try:
        db = sqlite3.connect(DB_FILE)
        c = db.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                private_key TEXT,
                public_key TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT,
                recipient TEXT,
                message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()
        db.close()
    except Exception as e:
        raise Exception(f"Failed to recreate database: {str(e)}")

# X3DH Key Exchange for generating private-public key pairs
def generate_x3dh_key_pair():
    """Generate a new X25519 key pair with proper encoding"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    private_b64 = base64.b64encode(private_bytes).decode('utf-8')
    public_b64 = base64.b64encode(public_bytes).decode('utf-8')
    
    return private_b64, public_b64

@app.route("/reset", methods=["POST"])
def reset():
    if "username" not in session:
        return redirect(url_for("login"))
    
    try:
        reset_database()
        session.clear()
        flash("All data has been completely reset!", "success")
    except Exception as e:
        flash(f"Reset failed: {str(e)}", "error")
    
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)

