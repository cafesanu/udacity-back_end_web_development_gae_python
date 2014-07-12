from google.appengine.ext import db

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email    = db.StringProperty()

class Wiki(db.Model):
    created       = db.DateTimeProperty(auto_now_add = True)
    page          = db.StringProperty(required = True)
    content       = db.TextProperty(required = False)

    @staticmethod
    def wiki_key(name = 'default'):
        return db.Key.from_path('wikis', name)