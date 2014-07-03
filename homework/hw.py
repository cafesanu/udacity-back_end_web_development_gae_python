import webapp2
import re
import cgi

import jinja2
import os
import mathfuncs

import random
import string
import hashlib

import json
import logging
import calendar
import time

from google.appengine.ext import db
from google.appengine.api import memcache

#****************************************************************************
#**                               Initialize jinja                                    **
#****************************************************************************
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#****************************************************************************
#**                        Unit 2a - Class Handler                        **
#****************************************************************************
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#****************************************************************************
#**                               Index                                    **
#****************************************************************************

class IndexHandler(Handler):
    def get(self):        
        self.render("index.html")
#****************************************************************************
#**               Unit 1 - Homework 1: Hello World                         **
#****************************************************************************

class Unit1HelloUdacityHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Hello, Udacity!")

#****************************************************************************
#**                     Unit 2 - Homework 1: Rot13                         **
#****************************************************************************
rot13_main = """
<form method="post">
    What is your Birthday?
    <br>
    <textarea rows="10" cols="50" name="text">%(text)s</textarea>
    <br>
    <input type="submit">
</form>
"""

alphabet   = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
alphabet13 = ['n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','l','m']
lower_letters = dict(zip(alphabet, alphabet13))
upper_letters = dict(zip([x.upper() for x in alphabet], [x.upper() for x in alphabet13]))

def rot13_char(c): 
    if c in lower_letters:
        return lower_letters.get(c)
    elif c in upper_letters:
        return upper_letters.get(c)
    else:
        return c

def rot13(str):
    str_list = list(str)
    str_list = list(map(rot13_char, str_list))
    return cgi.escape(''.join(str_list), quote=True)

class Unit2Rot13Handler(webapp2.RequestHandler):
    def write_rot13_main(self, text=""):
            self.response.out.write(rot13_main % {"text": text})
    def get(self):
        self.write_rot13_main()
    def post(self):
        text = self.request.get('text')
        self.write_rot13_main(rot13(text))

# #****************************************************************************
# #**               Unit 2 - Homework 2: Signup Verification                 **
# #** Commenting this since I will be using thios for unit 4 - cookies       **
# #****************************************************************************

# signup_welcome = """
# <!DOCTYPE html>

# <html>
#   <head>
#     <title>Unit 2 Signup</title>
#   </head>

#   <body>
#     <h2>Welcome,%(username)s!</h2>
#   </body>
# </html>
# """

# USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
# PASSWORD_RE = re.compile(r"^.{3,20}$")
# EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

# def is_valid_username(username):
#     return USER_RE.match(username)

# def is_valid_password(password):
#     return PASSWORD_RE.match(password)

# def is_valid_email(email):
#     return EMAIL_RE.match(email)


# class Unit2SignUpHandler(Handler):
#     def get(self):
#         self.render('signup.html')
#     def post(self):
#         username = self.request.get( 'username' )
#         password = self.request.get('password')
#         verify = self.request.get('verify')
#         email = self.request.get('email')

#         valid_username, valid_password, valid_verify, valid_email = True, True, True, True
#         error_username, error_password, error_verify, error_email = "", "", "", ""
        
#         if not is_valid_username(username):
#             username = cgi.escape(username, quote=True)
#             valid_username = False
#             error_username = "That's not a valid username."
#         if not is_valid_password(password):
#             valid_password = False
#             error_password = "That wasn't a valid password."
#         elif password != verify:
#             valid_verify = False
#             error_verify = "Your passwords didn't match."
#         if email and not is_valid_email(email):
#             email = cgi.escape(email, quote=True)
#             valid_email = False
#             error_email = "That's not a valid email."
#         if not(valid_username and valid_password and valid_verify and valid_email):
#             self.render('signup.html',  username = username, 
#                                         password = "",
#                                         verify = "",
#                                         email = email,
#                                         error_username = error_username,
#                                         error_password = error_password,
#                                         error_verify = error_verify, 
#                                         error_email = error_email)
#         else:
#             self.redirect("/unit2/signup/welcome?username=" + username)
           
# class Unit2SignUpWelcomeHandler(webapp2.RequestHandler):
#     def get(self):
#         username = self.request.get( 'username' )
#         self.response.out.write(signup_welcome %{"username": username})

#****************************************************************************
#**                        Unit 2a - Quiz: Fizzbuss                        **
#****************************************************************************

class Unit2aFizzbuzzHandler(Handler):
    def get(self):
        n = self.request.get('n', 0)
        n = n and int(n)
        self.render('fizzbuzz.html', n=n)


#****************************************************************************
#**                             Unit 3 - Blog                              **
#****************************************************************************
time_blog_cached = 0
time_post_cached = 0

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject       = db.StringProperty(required = True)
    content       = db.TextProperty(required = True)
    created       = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post = self)

class Unit3BlogFrontHandler(Handler):
    def get(self):
        key = 'top10'
        all_posts = memcache.get(key)
        if all_posts is None:
            logging.error("DB QUERY")
            all_posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10 ")
            global time_blog_cached
            time_blog_cached = calendar.timegm(time.gmtime())
            memcache.set(key, all_posts)
        self.render('blogfront.html', all_posts=all_posts, time_blog_cached=str(calendar.timegm(time.gmtime()) - time_blog_cached))


class Unit3PostHandler(Handler):
    def get(self, post_id):
        post = memcache.get(post_id)
        if post is None:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = Post.get(key)

            if not post:
                self.error(404)
                return

            global time_post_cached
            time_post_cached = calendar.timegm(time.gmtime())
            memcache.set(post_id, post)
        self.render("permalink.html", post = post, time_post_cached=str(calendar.timegm(time.gmtime()) - time_post_cached))

class Unit3BlogNewPostHandler(Handler):
    def get(self):
        self.render('newpost.html')
    def post(self):
        subject = self.request.get( 'subject' )
        content = self.request.get('content')
        if (subject and content):
            memcache.flush_all()
            new_post = Post(parent=blog_key(), subject = subject, content = content)
            b_key = new_post.put()
            self.redirect("/unit3/blog/%d" % b_key.id())
        else:
            error = "Please type subject and content please."
            self.render('newpost.html',subject=subject, content=content, error=error)

#****************************************************************************
#**               Unit 4 - Homework 1: Signup with cookies                 **
#****************************************************************************

def user_key(name = 'default'):
    return db.Key.from_path('users', name)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email    = db.StringProperty()

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def make_salt():
    s = string.lowercase+string.ascii_uppercase
    return ''.join(random.sample(s,5))

def hash_password(username, password, salt=make_salt()):
    hash = hashlib.sha256(username + password + salt).hexdigest()
    return '%s%s' % (hash, salt)

def verify_password(username, password, hash):
    salt = hash[-5:]
    newHash = hash_password(username, password, salt)
    return newH == hash

def verify_cookie(cookie_value_str):
    cookie_value = cookie_value_str.split('|')
    if len(cookie_value) == 2:
        user_id = cookie_value[0]
        hash_value = cookie_value[1]

        key = db.Key.from_path('User', int(user_id), parent=user_key())
        user = User.get(key)

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


class Unit4SignUpHandler(Handler):
    def add_user(self, username, password, email):
        hashed_password = hash_password(username, password)
        new_user = User( parent = user_key(), username = username, password = hashed_password, email = email )
        u_key = new_user.put()        

        hash_cookie = str(u_key.id()) + "|" + hashed_password

        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header( 'Set-Cookie', 'users=%s; Path=/' % hash_cookie)
        self.redirect("/unit4/signup/welcome" )

        
    def get(self):        
        self.render('signup.html')
    def post(self):
        username = self.request.get( 'username' )
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        valid_username, valid_password, valid_verify, valid_email = True, True, True, True
        error_username, error_password, error_verify, error_email = "", "", "", ""
        
        if not is_valid_username(username):
            username = cgi.escape(username, quote=True)
            valid_username = False
            error_username = "That's not a valid username."
        if not is_valid_password(password):
            valid_password = False
            error_password = "That wasn't a valid password."
        elif password != verify:
            valid_verify = False
            error_verify = "Your passwords didn't match."
        if email and not is_valid_email(email):
            email = cgi.escape(email, quote=True)
            valid_email = False
            error_email = "That's not a valid email."
        if does_user_exist(username):
            username = cgi.escape(username, quote=True)
            valid_username = False
            error_username = "Username already exists."
        if not(valid_username and valid_password and valid_verify and valid_email):
            self.render('signup.html',  username = username, 
                                        email = email,
                                        error_username = error_username,
                                        error_password = error_password,
                                        error_verify = error_verify, 
                                        error_email = error_email)
        else:
            self.add_user(username, password, email)


class Unit4SignUpWelcomeHandler(Handler):
    def get(self):
        user_id_cookie_str = self.request.cookies.get('users')
        if user_id_cookie_str:
            if verify_cookie( user_id_cookie_str ):
                user_id = user_id_cookie_str.split('|')[0]
                key = db.Key.from_path('User', int(user_id), parent=user_key())
                user = User.get(key)
                self.render("welcome.html", username=user.username)
            else:
                self.redirect("/unit4/signup")
        else:
            self.redirect("/unit4/signup")

#****************************************************************************
#**               Unit 4 - Homework 1: Login                 **
#****************************************************************************

def verify_credential(username, password):
    q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
    if q.count() == 1:
        user = q.get()
        salt = user.password[-5:]
        hash_pwd = hash_password(username, password, salt)
        return hash_pwd == user.password

class Unit4LoginHandler(Handler):
    def login_user(self, username):
        q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
        if q.count() == 1:
            user = q.get()
            hash_cookie = str(user.key().id()) + "|" + user.password

            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header( 'Set-Cookie', 'users=%s; Path=/' % str(hash_cookie))
            self.redirect("/unit4/login/welcome" )
        else:
            error_username = "Unexpected error. Plase try again."
            self.render("login.html", username= username, error_username=error_username)
    def get(self):
        self.render("login.html") 
    def post(self):
        username = self.request.get( 'username' )
        password = self.request.get('password')     

        valid_username, valid_password, valid_credentials = True, True,  True
        error_username, error_password, error_credentials = "", "", ""
        
        if not is_valid_username(username):
            username = cgi.escape(username, quote=True)
            valid_username = False
            error_username = "That's not a valid username."
        if not is_valid_password(password):
            valid_password = False
            error_password = "That wasn't a valid password."
        if not verify_credential(username, password):
            valid_credentials = False
            error_username = "Please verify tyour credentials"
        if not(valid_username and valid_password and valid_credentials):
            self.render('login.html',  username = username, 
                                        error_username = error_username)
        else:
            self.login_user(username)
            

class Unit4LoginWelcomeHandler(Handler):
    def get(self):
        user_id_cookie_str = self.request.cookies.get('users')
        if user_id_cookie_str:
            if verify_cookie( user_id_cookie_str ):
                user_id = user_id_cookie_str.split('|')[0]
                key = db.Key.from_path('User', int(user_id), parent=user_key())
                user = User.get(key)
                self.render("welcome.html", username=user.username)
            else:
                self.redirect("/unit4/login")
        else:
            self.redirect("/unit4/login")

#****************************************************************************
#**               Unit 4 - Homework 3: logout                 **
#****************************************************************************

class Unit4LogoutWelcomeHandler(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header( 'Set-Cookie', 'users=; Path=/')
        self.redirect("/unit4/signup" )

#****************************************************************************
#**                            Unit 5 - JSON                               **
#****************************************************************************

class Unit5PostJSONHandler(Handler):    
    def to_json(self, post):
        self.response.headers['Content-Type'] = 'application/json'
        json_str = '{"content": %s, "created": %s, "last_modified": %s, "subject": %s}' % (json.dumps(post.content), 
                                                                                                  json.dumps(post.created.strftime("%a %b %d %H:%M:%S %Y")),
                                                                                                  json.dumps(post.last_modified.strftime("%a %b %d %H:%M:%S %Y")), 
                                                                                                  json.dumps(post.subject))
        self.write(json_str)

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = Post.get(key)
        if not post:
            self.error(404)
            return
        self.to_json(post)

class Unit5BlogFrontJSONHandler(Handler):    
    def to_json(self, all_posts):
        self.response.headers['Content-Type'] = 'application/json'
        json_str = "["
        for post in all_posts:
            json_str += '{"content": %s, "created": %s, "last_modified": %s, "subject": %s}, ' % (json.dumps(post.content), 
                                                                                                  json.dumps(post.created.strftime("%a %b %d %H:%M:%S %Y")),
                                                                                                  json.dumps(post.last_modified.strftime("%a %b %d %H:%M:%S %Y")), 
                                                                                                  json.dumps(post.subject))
        json_str = json_str[:-2] + "]"
        self.write(json_str)

    
    def get(self):
        all_posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10 ")
        self.to_json(all_posts=all_posts)

#****************************************************************************
#**                         Unit 6 - Flush Memcache                        **
#****************************************************************************
class Unit6FlushMemCacheHandler(Handler):    
    def get(self):
        time_blog_cached = 0
        time_post_cached = 0
        memcache.flush_all()
        self.redirect("/unit3/blog")

#****************************************************************************
#**                              Page Handler                              **
#****************************************************************************
application = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/unit1/HelloUdacity', Unit1HelloUdacityHandler),
    ('/unit2/rot13', Unit2Rot13Handler),
    #('/unit2/signup', Unit2SignUpHandler),
    #('/unit2/signup/welcome', Unit2SignUpWelcomeHandler),
    ('/unit2a/fizzbuzz', Unit2aFizzbuzzHandler),
    ('/unit3/blog', Unit3BlogFrontHandler),
    ('/unit3/blog/newpost', Unit3BlogNewPostHandler),
    ('/unit3/blog/(\d+)', Unit3PostHandler),
    ('/unit4/signup', Unit4SignUpHandler),
    ('/unit4/signup/welcome', Unit4SignUpWelcomeHandler),
    ('/unit4/login', Unit4LoginHandler),
    ('/unit4/login/welcome', Unit4LoginWelcomeHandler),
    ('/unit4/logout', Unit4LogoutWelcomeHandler),
    ('/unit5/blog/(\d+).json', Unit5PostJSONHandler),
    ('/unit5/blog.json', Unit5BlogFrontJSONHandler),
    ('/unit6/flush', Unit6FlushMemCacheHandler),
    ('/finalproject', Unit6FlushMemCacheHandler),
], debug=True)