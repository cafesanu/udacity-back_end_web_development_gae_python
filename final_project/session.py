import re
import string
import random
import hashlib

from google.appengine.ext import db
from datastore_classes import User
from secret import *

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

"""
	Different methods helping with session related logic,
	method names are self documented
"""

def user_key(name = 'default'):
    return db.Key.from_path('users', name)

def make_salt():
    s = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.sample(s,5))

def hash_password(username, password, salt=make_salt()):
    hash = hashlib.sha256(username + password + secret_str + salt).hexdigest()
    return '%s%s' % (hash, salt)

def verify_password(username, password, hash):
    salt = hash[-5:]
    newHash = hash_password(username, password, secret_str, salt)
    return newH == hash

def verify_cookie(cookie_value_str):
    cookie_value = cookie_value_str.split('|')
    if len(cookie_value) == 2:
        user_id = cookie_value[0]
        hash_value = cookie_value[1]

        key = db.Key.from_path('User', int(user_id), parent=user_key())
        user = User.get(key)
        if user:
        	return hash_value == user.password

def is_valid_username(username):
    return USER_RE.match(username)

def is_valid_password(password):
    return PASSWORD_RE.match(password)

def is_valid_email(email):
    return EMAIL_RE.match(email)

def does_user_exist(username):
    q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
    return q.count()

def verify_credential(username, password):
    q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
    if q.count() == 1:
        user = q.get()
        salt = user.password[-5:]
        hash_pwd = hash_password(username, password, salt)
        return hash_pwd == user.password

def get_username(handler):
    user_id_cookie_str = handler.request.cookies.get('users')
    user = None
    if user_id_cookie_str:
        if verify_cookie( user_id_cookie_str ):
            user_id = user_id_cookie_str.split('|')[0]
            key = db.Key.from_path('User', int(user_id), parent=user_key())
            user = User.get(key).username
	return user

def is_user_logged_in(handler):
    users_cookie_str = handler.request.cookies.get('users')
    if users_cookie_str:
        if verify_cookie( users_cookie_str ):
        	return True