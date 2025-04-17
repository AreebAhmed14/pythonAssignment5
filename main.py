import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64

# Initialize session state for stored_data and key if they don't exist
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'cipher' not in st.session_state:
    st.session_state.cipher = Fernet(Fernet.generate_key())

def hashpass(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(passkey):
    hashpasskey = hashlib.sha256(passkey.encode()).hexdigest()
    if hashpasskey in st.session_state.stored_data:
        return st.session_state.cipher.decrypt(st.session_state.stored_data[hashpasskey]["encrypted_text"].encode()).decode()
    return None



st.title("SECURE AND LOCKED YOUR DATA 🔒")

menu = ["Home","Store Data","Retrive Data"]
choose = st.sidebar.selectbox("Navigation ",menu)

if choose == "Home" :
    st.subheader("Welcome to the Areebii secure 🏠 ")
    st.write("securely store and retrieve data using unique passkeys.")

elif choose == "Store Data" :
    st.subheader("Store Data 📂")
    normal_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Save"):
        if normal_data and passkey:
            hashpasskey = hashpass(passkey)
            encryptdata = encrypt_data(normal_data)
            st.session_state.stored_data[hashpasskey] = {"encrypted_text": encryptdata, "passkey": hashpasskey}
            st.success("Data stored successfully!")
        else:
            st.warning("Both field is required.")

elif choose == "Retrive Data" :
    st.subheader("Retrive Data 📂")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Retrive"):
        if passkey:
            decrypted_data = decrypt_data(passkey)
            if decrypted_data:
                st.success(f"Decrypted data: {decrypted_data}")
            else:
                st.error("No data found for this passkey.")
        else:
            st.warning("Please enter passkey.")
            

