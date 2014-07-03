#------------------------------------------------------------------------------
#General imports
import jinja2
import os
import cgi
import time

#------------------------------------------------------------------------------
#Google App Engine imports
import webapp2
from google.appengine.ext import db

#------------------------------------------------------------------------------
#local imports
from utils import *
from datastore_classes import *
from session import *

#------------------------------------------------------------------------------
#Global Variables

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
DEBUG = True

#------------------------------------------------------------------------------
#Initialize jinja
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#------------------------------------------------------------------------------
#Global Functions
def wiki_key(name = 'default'):
    return db.Key.from_path('wikis', name)

#------------------------------------------------------------------------------
#Page Handlers

class HandlerMain(BaseHandler):
    def get(self):
        query = "SELECT * FROM Wiki WHERE page = '/' ORDER BY created DESC LIMIT 1"
        wiki = db.GqlQuery(query)
        username_session = get_username(self)
        content = ""
        if wiki.count():#if wiki exist
            content = wiki.get().content
        self.render("page.html", page = "/",username_session=username_session, link_edit_view="/_edit", edit_view="edit", content=content)

class HandlerSignUp(BaseHandler):

    def add_user(self, username, password, email):
        hashed_password = hash_password(username, password)
        new_user = User( parent = user_key(), username = username, password = hashed_password, email = email )
        u_key = new_user.put()        

        hash_cookie = str(u_key.id()) + "|" + hashed_password

        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header( 'Set-Cookie', 'users=%s; Path=/' % hash_cookie)
        self.redirect("/" )
        
    def get(self):
        if is_user_logged_in(self):
            username_session = get_username(self)
            self.render('signup.html', username_session=username_session)
        else:
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

class HandlerLogin(BaseHandler):
    def login_user(self, username):
        q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
        if q.count() == 1:
            user = q.get()
            hash_cookie = str(user.key().id()) + "|" + user.password

            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header( 'Set-Cookie', 'users=%s; Path=/' % str(hash_cookie))
            self.redirect("/")
        else:
            error_username = "Unexpected error. Plase try again."
            self.render("login.html", username= username, error_username=error_username)
    def get(self):
        if is_user_logged_in(self):
            self.redirect("/")
        else:
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
            error_username = "Please verify your credentials"
        if not(valid_username and valid_password and valid_credentials):
            self.render('login.html',  username = username, 
                                        error_username = error_username)
        else:
            self.login_user(username)

class HandlerLogoutFromMain(BaseHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header( 'Set-Cookie', 'users=; Path=/')
        self.redirect("/" )

class HandlerEdit(BaseHandler):
    def get(self, page):
        if is_user_logged_in(self):
            username_session = get_username(self)
            query = "SELECT * FROM Wiki WHERE page = '%s' ORDER BY created DESC LIMIT 1" %(page)
            wiki = db.GqlQuery(query)
            content = ""
            if wiki.count():#if wiki exist
                content = wiki.get().content
            self.render('edit.html', username_session=username_session, page=page, edit_view="view", content = content)
        else:
            self.redirect('/login' )

    def post(self, page):
        content = self.request.get( 'content' )
        query = "SELECT * FROM Wiki WHERE page = '%s' ORDER BY created DESC LIMIT 1" %(page)
        wiki = db.GqlQuery(query)
        if wiki.count():#if wiki exist
            old_wiki_content = wiki.get().content
            if(old_wiki_content != content):#if content is equal, don't save new version
                new_wiki = Wiki(parent=wiki_key(), page = page, content = content)
                new_wiki.put()
                time.sleep(.1) #make sure put goes before redirect
            self.redirect(page )
        else:
            if content:
                new_wiki = Wiki(parent=wiki_key(), page = page, content = content)
                new_wiki.put()
                time.sleep(.1) #make sure put goes before redirect
                self.redirect(page)
            else:
                error = "New wiki cannot be empty"
                self.render('edit.html', error=error)
        

class HandlerPage(BaseHandler):
    def get(self, page):
        query = "SELECT * FROM Wiki WHERE page = '%s' ORDER BY created DESC LIMIT 1" %(page)
        wiki = db.GqlQuery(query)
        if wiki.count():#if wiki exist
            content = wiki.get().content
            if is_user_logged_in(self):
                username_session = get_username(self)
                self.render('page.html',page=page, username_session=username_session, link_edit_view="/_edit" ,edit_view="edit", content=content)
            else:
                self.render('page.html',content=content)
        else:
            url = "/_edit%s"%(page)
            self.redirect(url)


application = webapp2.WSGIApplication(
				[
					('/?'              , HandlerMain),
					('/signup/?'       , HandlerSignUp),
					('/login/?'        , HandlerLogin),
					('/logout/?'       , HandlerLogoutFromMain),
					('/_edit' + PAGE_RE, HandlerEdit),
					(PAGE_RE           , HandlerPage),
				],
				debug=DEBUG
)