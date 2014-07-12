"""Final project of Udacity CS-253 course at https://www.udacity.com/course/cs253
   Project involves creating a wiki by using the Google App Engine in Python

"""

#------------------------------------------------------------------------------
#standard library imports
import os
import cgi
import time
import jinja2
import re

#------------------------------------------------------------------------------
#Google App Engine imports
import webapp2
from google.appengine.ext import db

#------------------------------------------------------------------------------
#local imports
from datastore_classes import User, Wiki
import session

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

#------------------------------------------------------------------------------
#Page Handlers
#------------------------------------------------------------------------------

class HandlerBase(webapp2.RequestHandler):
    r"""
        Base handler with common method that all other handler will inherit
    """

    def write(self, *a, **kw):
        r"""
            easier way to remember response.out.write
        """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        r"""
            render page with jinja
        """
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        r"""
            easier way to remember self.write
        """
        self.write(self.render_str(template, **kw))
    
    def set_escaping(self, escape):
        r"""
            Enable/Disable escaping
        """
        global jinja_env
        jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = escape)

    def get_last_10_wikis(self):
        query = "SELECT page FROM Wiki ORDER BY created DESC"
        wikis = db.GqlQuery(query)

        wiki_pages = []
        for w in wikis:
            if w.page not in wiki_pages:
                wiki_pages.append(w.page)
        return wiki_pages[:10]


class HandlerMain(HandlerBase):
    r"""Handler for index page

    """
    def get(self):
        r"""Load main page and change login header
            depending if user is logged-in or not

        """
        #check if main page exists, if it doesn't create a welcome message.
        query = "SELECT * FROM Wiki WHERE page = '/' ORDER BY created DESC LIMIT 1" 
        wiki = db.GqlQuery(query)
        if not wiki.count():#if main page does not exist
            content = "Welcome to my new wiki"
            new_wiki = Wiki(parent=Wiki.wiki_key(), page = '/', content = content)
            new_wiki.put()
            time.sleep(.5) #make sure put goes before geeting list of wikis

        last_10_wikis = self.get_last_10_wikis()
        id = self.request.get( 'id' )
        username_session = session.get_username(self)
        wiki = None
        if id:#if user is requesting an specific version
            wiki = Wiki.get_by_id(int(id), parent=Wiki.wiki_key())
        if wiki and wiki.page == "/": #Check version belong to this page
            content = wiki.content
            self.render("page.html", from_main = True, last_10_wikis=last_10_wikis, page = "/",username_session=username_session, link_edit_view="/_edit/?id="+ id, edit_view="edit", content=content)
        else:#Not a version, load last version
            query = "SELECT * FROM Wiki WHERE page = '/' ORDER BY created DESC LIMIT 1"
            wiki = db.GqlQuery(query)
            content = ""
            if wiki.count():#if wiki exist
                content = wiki.get().content
            self.render("page.html", from_main = True,  last_10_wikis=last_10_wikis, page = "/",username_session=username_session, link_edit_view="/_edit", edit_view="edit", content=content)
    def post(self):
        page = self.request.get( 'page' )

        if page[:1] != '/':
            page = "/" + page
        #replace spaces for underscore
        page = re.sub(' +','_',page)
        page = cgi.escape(page)
        url = "/_edit%s"%(page)
        self.redirect(url)


class HandlerSignUp(HandlerBase):
    r"""Shows singup info for user who'd like to register

    """

    def add_user(self, username, password, email):
        r""" Adds a user to the system and sends a cookie back

        """

        hashed_password = session.hash_password(username, password)
        new_user = User( parent = session.user_key(), username = username, password = hashed_password, email = email )
        u_key = new_user.put()        

        hash_cookie = str(u_key.id()) + "|" + hashed_password

        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header( 'Set-Cookie', 'users=%s; Path=/' % hash_cookie)
        self.redirect("/" )
        
    def get(self):
        r""" Shows sign-up page

        """

        last_10_wikis = self.get_last_10_wikis()
        username_session = session.get_username(self)
        self.render('signup.html', last_10_wikis=last_10_wikis, username_session=username_session)

    def post(self):
        r""" Verifies user's type info, if valid, add user, set cookies and redirect to index page
        """

        last_10_wikis = self.get_last_10_wikis()
        username = self.request.get( 'username' )
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        valid_username, valid_password, valid_verify, valid_email = True, True, True, True
        error_username, error_password, error_verify, error_email = "", "", "", ""
        
        if not session.is_valid_username(username):
            username = cgi.escape(username, quote=True)
            valid_username = False
            error_username = "That's not a valid username."
        if not session.is_valid_password(password):
            valid_password = False
            error_password = "That wasn't a valid password."
        elif password != verify:
            valid_verify = False
            error_verify = "Your passwords didn't match."
        if email and not session.is_valid_email(email):
            email = cgi.escape(email, quote=True)
            valid_email = False
            error_email = "That's not a valid email."
        if session.does_user_exist(username):
            username = cgi.escape(username, quote=True)
            valid_username = False
            error_username = "Username already exists."
        if not(valid_username and valid_password and valid_verify and valid_email):
            self.render('signup.html',  last_10_wikis=last_10_wikis,
                                        username = username, 
                                        email = email,
                                        error_username = error_username,
                                        error_password = error_password,
                                        error_verify = error_verify, 
                                        error_email = error_email)
        else:
            self.add_user(username, password, email)


class HandlerLogin(HandlerBase):
    r"""
        Handler for users who'd like to login
    """

    def login_user(self, username):
        r"""
            Pre-condition: username exists already in db (given that info was verified in post)
            logs-in user checking db. If not found send unexpected error
        """

        last_10_wikis = self.get_last_10_wikis()
        q = db.GqlQuery( "SELECT * FROM User where username = \'" + username + "\'" )
        if q.count() == 1:
            user = q.get()
            hash_cookie = str(user.key().id()) + "|" + user.password

            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header( 'Set-Cookie', 'users=%s; Path=/' % str(hash_cookie))
            self.redirect("/")
        else:
            error_username = "Unexpected error. Plase try again."
            self.render("login.html", last_10_wikis=last_10_wikis, username= username, error_username=error_username)
    def get(self):
        r"""
            if user already logged-in, send to index page, otherwise send to login page
        """

        last_10_wikis = self.get_last_10_wikis()
        if session.is_user_logged_in(self):
            self.redirect("/")
        else:
            self.render("login.html", last_10_wikis=last_10_wikis) 
    def post(self):
        r"""
            Verify users info. If incorrect, send eror message, otherwise loggin user.
        """

        last_10_wikis = self.get_last_10_wikis()
        username = self.request.get( 'username' )
        password = self.request.get('password')     

        valid_username, valid_password, valid_credentials = True, True,  True
        error_username, error_password, error_credentials = "", "", ""
        
        if not session.is_valid_username(username):
            username = cgi.escape(username, quote=True)
            valid_username = False
            error_username = "That's not a valid username."
        if not session.is_valid_password(password):
            valid_password = False
            error_password = "That wasn't a valid password."
        if not session.verify_credential(username, password):
            valid_credentials = False
            error_username = "Please verify your credentials"
        if not(valid_username and valid_password and valid_credentials):
            self.render('login.html',  last_10_wikis=last_10_wikis,
                                        username = username, 
                                        error_username = error_username)
        else:
            self.login_user(username)

class HandlerLogout(HandlerBase):
    r"""
        Handler to log-out user
    """
    def get(self):
        r"""
            Set cookie to empty string
        """
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header( 'Set-Cookie', 'users=; Path=/')
        self.redirect("/" )


class HandlerHistory(HandlerBase):
    r"""
        Handler to show all versions of a given page
    """
    def get(self, page):
        r"""
            get all versions of pages and show them to user in a table,
            if page does not exist, table will be empty
        """
        last_10_wikis = self.get_last_10_wikis()
        query = "SELECT * FROM Wiki WHERE page = '%s' ORDER BY created DESC" %(page)
        wikis = db.GqlQuery(query)
        self.set_escaping(True)
        username_session = session.get_username(self)
        self.render('history.html', last_10_wikis=last_10_wikis, username_session=username_session, wikis=wikis, page=page)
        self.set_escaping(False)

class HandlerEdit(HandlerBase):
    r"""
        Handles the edit of any new or existing page
    """
    def edit_last_version(self, page, username_session):
        last_10_wikis = self.get_last_10_wikis()
        query = "SELECT * FROM Wiki WHERE page = '%s' ORDER BY created DESC LIMIT 1" %(page)
        wiki = db.GqlQuery(query)
        content = ""
        if wiki.count():#if wiki exist
            content = wiki.get().content
        self.render('edit.html', last_10_wikis=last_10_wikis, username_session=username_session, page=page, edit_view="view", content = content)

    def get(self, page):
        r"""
            If an id is sent, and id is from given page, edit that version of a page,
            if no id is sent, and id is not from given page, edit the last version,
            if page doesn't exist, sow blank textarea
            If user not logged in, send user to loggin page
        """

        last_10_wikis = self.get_last_10_wikis()
        if session.is_user_logged_in(self):
            id = self.request.get( 'id' )
            wiki = None
            username_session = session.get_username(self)
            if id and id.isdigit() :
                wiki = Wiki.get_by_id(int(id), parent=Wiki.wiki_key())                
                if wiki and wiki.page == page:
                    content = wiki.content
                    self.render('edit.html', last_10_wikis=last_10_wikis, username_session=username_session, page=page, edit_view="view", content = content)
                else:
                    self.edit_last_version(page, username_session)
            else:
                self.edit_last_version(page, username_session)
        else:
            self.redirect('/login' )

    def post(self, page):
        r"""
            If content changed form prev. version, a new version of the wiki will be created
            A new Wiki's firs version can't be empty
        """

        last_10_wikis = self.get_last_10_wikis()
        content = self.request.get( 'content' )
        query = "SELECT * FROM Wiki WHERE page = '%s' ORDER BY created DESC LIMIT 1" %(page)
        wiki = db.GqlQuery(query)
        if wiki.count():#if wiki exist
            old_wiki_content = wiki.get().content
            if(old_wiki_content != content):#if content is equal, don't save new version
                new_wiki = Wiki(parent=Wiki.wiki_key(), page = page, content = content)
                new_wiki.put()
                time.sleep(.5) #make sure put goes before redirect
            self.redirect(page )
        else:
            if content:
                new_wiki = Wiki(parent=Wiki.wiki_key(), page = page, content = content)
                new_wiki.put()
                time.sleep(.5) #make sure put goes before redirect
                self.redirect(page)
            else:
                error = "New wiki cannot be empty"
                self.render('edit.html',last_10_wikis=last_10_wikis, error=error)


class HandlerPage(HandlerBase):
    r"""
        handles any page except the main page
    """
    def show_last_version(self,page):
        last_10_wikis = self.get_last_10_wikis()
        query = "SELECT * FROM Wiki WHERE page = '%s' ORDER BY created DESC LIMIT 1" %(page)
        wiki = db.GqlQuery(query)
        if wiki.count():#if wiki exist
            content = wiki.get().content
            if session.is_user_logged_in(self):
                username_session = session.get_username(self)
                self.render('page.html',last_10_wikis=last_10_wikis, page=page, username_session=username_session, link_edit_view="/_edit" ,edit_view="edit", content=content)
            else:
                self.render('page.html',last_10_wikis=last_10_wikis, page=page, content=content)
        else:
            url = "/_edit%s"%(page)
            self.redirect(url)

    def get(self, page):
        r"""
            If page doesn't exist, send to edit page
            If no id sent, show last version, 
            If id sent, and id matches page, show version with the id
            if id doesn't match page, show last version
        """

        last_10_wikis = self.get_last_10_wikis()
        id = self.request.get( 'id' )
        wiki = None
        #verify id exists and is a valid number, therwise show last version
        if id and id.isdigit():
            #if id is a valid number, verify that it exists and that id version belongs to page
            #If it does, show the id version, otherwise show last version
            wiki = Wiki.get_by_id(int(id), parent=Wiki.wiki_key())
            if wiki and wiki.page == page:#id exists and belongs to page
                content = wiki.content
                # Mofify login part on top depending on whether user is logged in
                if session.is_user_logged_in(self):
                    username_session = session.get_username(self)
                    self.render('page.html',last_10_wikis=last_10_wikis, page=page, username_session=username_session, link_edit_view="/_edit" ,edit_view="edit", content=content)
                else:
                    self.render('page.html',last_10_wikis=last_10_wikis, content=content)
            else:
                self.show_last_version(page)
        else:
            self.show_last_version(page)

class HandlerBadRequest(HandlerBase):
    def get(self, page):
        self.response.status_int = 400
        self.response.out.write("Bad Request: %s is an invalid page name"% page)

application = webapp2.WSGIApplication(
                [
                    ('/?'                 , HandlerMain),
                    ('/signup/?'          , HandlerSignUp),
                    ('/login/?'           , HandlerLogin),
                    ('/logout/?'          , HandlerLogout),
                    ('/_history' + PAGE_RE, HandlerHistory),
                    ('/_edit' + PAGE_RE   , HandlerEdit),
                    (PAGE_RE              , HandlerPage),
                    ('/(.+)'              , HandlerBadRequest)
                ],
                debug=DEBUG
)