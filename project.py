import streamlit as st
import mysql.connector
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
import string
import re
from streamlit.runtime.scriptrunner import RerunException

def setup_database():
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="1234",
        database="vault_db"
    )
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            master_key VARCHAR(255) NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INT PRIMARY KEY AUTO_INCREMENT,
            website VARCHAR(255),
            username VARCHAR(255),
            secret_password TEXT
        )
    """)
    connection.commit()
    return connection, cursor

def secure_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, stored_hash):
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

def create_key(main_password):
    key_deriver = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt_',
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(key_deriver.derive(main_password.encode('utf-8')))
    return Fernet(key)

def hide_password(password, cipher):
    return cipher.encrypt(password.encode('utf-8')).decode('utf-8')

def reveal_password(hidden_password, cipher):
    try:
        return cipher.decrypt(hidden_password.encode('utf-8')).decode('utf-8')
    except:
        return "Could not reveal password"

def make_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def validate_master_password(password):
    if not password:
        return False, "Password cannot be empty."
    if not password[0].isupper():
        return False, "Password must start with a capital letter"
    if len(re.findall(r"[0-9]", password)) < 3:
        return False, "Password must contain at least 3 numbers"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least 1 special character"
    return True, ""

def rerun():
    raise RerunException(None)

def main():
    st.set_page_config(page_title="Easy Password Keeper", page_icon="🔒")
    st.title("🔒 Easy Password Keeper")

    if 'is_logged_in' not in st.session_state:
        st.session_state.is_logged_in = False
    if 'cipher' not in st.session_state:
        st.session_state.cipher = None
    if 'website_input' not in st.session_state:
        st.session_state.website_input = ""
    if 'username_input' not in st.session_state:
        st.session_state.username_input = ""
    if 'password_input' not in st.session_state:
        st.session_state.password_input = ""

    connection, cursor = setup_database()
    cursor.execute("SELECT id, master_key FROM users LIMIT 1")
    user = cursor.fetchone()
    main_password = user[1] if user else None

    if not main_password and not st.session_state.is_logged_in:
        st.subheader("Set Up Your Main Password")
        new_password = st.text_input("Create Main Password", type="password")
        confirm_password = st.text_input("Confirm Main Password", type="password")
        if st.button("Save Main Password"):
            if new_password == confirm_password and new_password:
                valid, message = validate_master_password(new_password)
                if valid:
                    hashed = secure_password(new_password)
                    cursor.execute("INSERT INTO users (master_key) VALUES (%s)", (hashed.decode(),))
                    connection.commit()
                    st.success("Main password saved! Please log in.")
                else:
                    st.error(message)
            else:
                st.error("Passwords don't match or are empty.")

    elif not st.session_state.is_logged_in:
        st.subheader("Log In")
        entered_password = st.text_input("Main Password", type="password")
        if st.button("Log In"):
            if main_password and check_password(entered_password, main_password):
                st.session_state.is_logged_in = True
                st.session_state.cipher = create_key(entered_password)
                st.success("Logged in successfully!")
            else:
                st.error("Wrong password or no user found.")

    else:
        st.subheader("Your Passwords")
        if st.button("Log Out"):
            st.session_state.is_logged_in = False
            st.session_state.cipher = None
            st.success("Logged out successfully!")
            rerun()

        tab1, tab2, tab3 = st.tabs(["See Passwords", "Add Password", "Generate Password"])

        with tab1:
            st.write("Your Saved Passwords")
            cursor.execute("SELECT id, website, username, secret_password FROM passwords")
            entries = cursor.fetchall()
            if entries:
                for entry in entries:
                    id, website, username, hidden_password = entry
                    revealed = reveal_password(hidden_password, st.session_state.cipher)
                    with st.expander(f"{website} - {username}"):
                        st.write(f"Password: {revealed}")
                        if st.button("Delete", key=f"delete_{id}"):
                            cursor.execute("DELETE FROM passwords WHERE id=%s", (id,))
                            connection.commit()
                            st.success(f"Deleted {website} entry.")
                            rerun()
            else:
                st.info("No passwords saved yet.")

        with tab2:
            st.write("Add a New Password")
            website = st.text_input("Website", value=st.session_state.website_input)
            username = st.text_input("Username", value=st.session_state.username_input)
            password = st.text_input("Password", type="password", value=st.session_state.password_input)
            st.session_state.website_input = website
            st.session_state.username_input = username
            st.session_state.password_input = password
            if st.button("Save Password"):  
                if not st.session_state.cipher:
                    st.error("You must log in first!")
                elif website and username and password:
                    hidden = hide_password(password, st.session_state.cipher)
                    cursor.execute(
                        "INSERT INTO passwords (website, username, secret_password) VALUES (%s, %s, %s)",
                        (website, username, hidden)
                    )
                    connection.commit()
                    st.success("Password saved successfully!")
                    st.session_state.website_input = ""
                    st.session_state.username_input = ""
                    st.session_state.password_input = ""
                else:
                    st.error("Please fill in all fields.")

        with tab3:
            st.write("Generate a Strong Password")
            length = st.slider("Password Length", 8, 32, 12)
            if st.button("Generate"):
                new_password = make_password(length)
                st.write(f"Generated Password: `{new_password}`")
                st.info("Copy this password and add it in the 'Add Password' tab.")

    connection.close()

if __name__ == "__main__":
    main()