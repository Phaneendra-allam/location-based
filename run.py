import streamlit as st
import geopy.distance
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import geocoder
import base64


def encrypt_message_aes(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    encrypted_message_with_iv = base64.b64encode(iv + encrypted_message).decode('utf-8')
    return encrypted_message_with_iv

def decrypt_message_aes(key, encrypted_message_with_iv):
    encrypted_data = base64.b64decode(encrypted_message_with_iv)
    iv = encrypted_data[:AES.block_size]
    encrypted_message = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode('utf-8')
    return decrypted_message

def get_current_location():
    g = geocoder.ip('me')
    return g.latlng


def is_within_offices(current_location, office_locations, radius_km):
    for office in office_locations:
        distance = geopy.distance.distance(current_location, office).km
        if distance <= radius_km:
            return True, office
    return False, None



st.title("Advanced Location-Based Encryption System")
st.markdown("""
This app restricts access to an encrypted message based on your current location.
To decrypt the message, your location must match one of the selected office locations.
We use AES encryption for added security.
""")


st.subheader("Step 1: Define Office Locations")
office1 = st.text_input("Office 1 (latitude, longitude)", "12.971598, 77.594566")  
office2 = st.text_input("Office 2 (latitude, longitude)", "28.704060, 77.102493")  
office3 = st.text_input("Office 3 (latitude, longitude)", "19.076090, 72.877426")  

radius_km = st.slider("Select the allowed radius (km)", min_value=0.1, max_value=10.0, value=1.0, step=0.1)
st.write(f"Allowed radius for decryption: {radius_km} km")


st.subheader("Step 2: Encrypt Your Message")
key = get_random_bytes(16) 
secret_message = st.text_input("Enter the secret message to encrypt", "This is a confidential message.")
encrypted_message = encrypt_message_aes(key, secret_message)
st.write("Encrypted Message:", encrypted_message)


st.subheader("Step 3: Verify Your Location")
if st.button("Get Current Location"):
    current_location = get_current_location()
    st.write("Your Current Location:", current_location)

    
    office_locations = [
        tuple(map(float, office1.split(','))),
        tuple(map(float, office2.split(','))),
        tuple(map(float, office3.split(',')))
    ]

    
    access_granted, matched_office = is_within_offices(current_location, office_locations, radius_km)

    if access_granted:
        st.success(f"Access Granted! You are within the allowed radius of Office at {matched_office}.")
        decrypted_message = decrypt_message_aes(key, encrypted_message)
        st.write("Decrypted Message:", decrypted_message)
    else:
        st.error("Access Denied! You are not within the allowed location.")


