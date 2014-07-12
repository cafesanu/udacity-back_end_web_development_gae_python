import re
import string
import random
import hashlib

from google.appengine.ext import db
from datastore_classes import User
from secret import *

#Regex to vaildate user sign-up info is correct
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def user_key(name = 'default'):
    r"""
        user ket for the datastore
    """
    return db.Key.from_path('users', name)

def make_salt():
    r"""
        create random salt 
    """
    s = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.sample(s,5))

def hash_password(username, password, salt=make_salt()):
    r"""
        hash password using sha256 with the salt and the secret string
    """
    hash = hashlib.sha256(username + password + secret_str + salt).hexdigest()
    return '%s%s' % (hash, salt)

def verify_password(username, password, hash):
    r"""
        check paswsword is valid
    """
    salt = hash[-5:]
    newHash = hash_password(username, password, secret_str, salt)
    return newH == hash

def verify_cookie(cookie_value_str):
    r"""
        verify cookie  is valid by comparing the hashed password in cookie with the one stored in db
    """
    cookie_value = cookie_value_str.split('|')
    if len(cookie_value) == 2:
        user_id = cookie_value[0]
        hash_value = cookie_value[1]

        key = db.Key.from_path('User', int(user_id), parent=user_key())
        user = User.get(key)
        if user:
            return hash_value == user.password

def is_valid_username(username):
    r"""
        verify sign-up name could be a valid username string based on regex
    """
    return USER_RE.match(username)

def is_valid_password(password):
    r"""
        verify sign-up password could be a valid password string based on regex
    """
    return PASSWORD_RE.match(password)

def is_valid_email(email):
    r"""
        verify sign-up email could be a valid email string based on regex
    """
    return EMAIL_RE.match(email)

def does_user_exist(username):
    r"""
        verify user already exist
    """
    q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
    return q.count()

def verify_credential(username, password):
    r"""
        verify userlogin info is correct
    """
    q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
    if q.count() == 1:
        user = q.get()
        salt = user.password[-5:]
        hash_pwd = hash_password(username, password, salt)
        return hash_pwd == user.password

def get_username(handler):
    r"""
        get username from cookie
    """
    user_id_cookie_str = handler.request.cookies.get('users')
    user = None
    if user_id_cookie_str:
        if verify_cookie( user_id_cookie_str ):
            user_id = user_id_cookie_str.split('|')[0]
            key = db.Key.from_path('User', int(user_id), parent=user_key())
            user = User.get(key).username
    return user

def is_user_logged_in(handler):
    r"""
        verify user is logged in by verifying cookie
    """
    users_cookie_str = handler.request.cookies.get('users')
    if users_cookie_str:
        if verify_cookie( users_cookie_str ):
            return True