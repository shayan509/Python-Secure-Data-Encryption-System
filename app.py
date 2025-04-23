import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'fernet_key' not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.fernet_key)

if 'is_locked' not in st.session_state:
    st.session_state.is_locked = False

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

def hash_passkey(passkey):
    """Hash the passkey using SHA-256"""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    """Encrypt the input text using Fernet"""
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    """Decrypt the encrypted text using Fernet"""
    return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()

def handle_login():
    """Handle the login process"""
    if st.session_state.password == "admin123":
        st.session_state.failed_attempts = 0
        st.session_state.is_locked = False
        st.session_state.authenticated = True
        st.session_state.nav_choice = "Retrieve Data"
        st.rerun()

# Main UI
st.title("🔒 Secure Data Encryption System")

# Navigation using session state
if 'nav_choice' not in st.session_state:
    st.session_state.nav_choice = "Home"

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, key='nav_select')

# Update navigation if changed
if choice != st.session_state.nav_choice:
    st.session_state.nav_choice = choice
    st.rerun()

if st.session_state.nav_choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.markdown("""
    ### How to use:
    1. Go to **Store Data** to encrypt and save your information
    2. Use **Retrieve Data** to decrypt your stored information
    3. You have 3 attempts to enter the correct passkey
    """)

elif st.session_state.nav_choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            try:
                encrypted_text = encrypt_data(user_data)
                hashed_passkey = hash_passkey(passkey)
                st.session_state.stored_data[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Data stored securely!")
                st.code(encrypted_text, language="text")
                st.info("👆 Save this encrypted text to retrieve your data later")
            except Exception as e:
                st.error(f"⚠️ Encryption failed: {str(e)}")
        else:
            st.error("⚠️ Both fields are required!")

elif st.session_state.nav_choice == "Retrieve Data":
    if st.session_state.is_locked and not st.session_state.authenticated:
        st.warning("🔒 You are locked out. Please login first.")
        st.session_state.nav_choice = "Login"
        st.rerun()
    else:
        st.subheader("🔍 Retrieve Your Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                entry = st.session_state.stored_data.get(encrypted_text)
                if entry:
                    hashed_passkey = hash_passkey(passkey)
                    if entry["passkey"] == hashed_passkey:
                        try:
                            decrypted_text = decrypt_data(encrypted_text)
                            st.session_state.failed_attempts = 0
                            st.success("✅ Decryption successful!")
                            st.write("Decrypted Data:")
                            st.code(decrypted_text, language="text")
                        except Exception as e:
                            st.error(f"⚠️ Decryption failed: {str(e)}")
                    else:
                        st.session_state.failed_attempts += 1
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                        
                        if st.session_state.failed_attempts >= 3:
                            st.warning("🔒 Too many failed attempts! Redirecting to Login...")
                            st.session_state.is_locked = True
                            st.session_state.authenticated = False
                            st.session_state.nav_choice = "Login"
                            st.rerun()
                else:
                    st.error("❌ Encrypted data not found!")
            else:
                st.error("⚠️ Both fields are required!")

elif st.session_state.nav_choice == "Login":
    st.subheader("🔑 Login")
    
    # Only show the warning if the user has been locked out
    if st.session_state.is_locked:
        st.warning("You have been locked out due to too many failed attempts.")
    
    # Use a key for the password input to store it in session state
    st.text_input("Enter Master Password:", type="password", key="password", on_change=handle_login)
    
    # Add a login button that triggers the same callback
    if st.button("Login", on_click=handle_login):
        pass
