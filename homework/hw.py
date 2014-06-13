import webapp2
import re
import cgi

#****************************************************************************
#**                               Index                                    **
#****************************************************************************
index = """
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Udacity - CS253 - Web Development: cafesanu solutions</title>
    </head>
    <body>
        <h2><a href="https://www.udacity.com/course/cs253">Udacity - CS253 - Web Development:</a> My solutions</h2>
        <h3>Code available at <a href="https://github.com/cafesanu"> my github account </a></h3>

        <a href="/unit1/HelloUdacity">Unit 1: Homework 1: Hello Udacity</a><br>
        <a href="/unit2/rot13">       Unit 2: Homework 1: Rot13</a><br>
        <a href="/unit2/signup">      Unit 2: Homework 2: Signup Verification</a><br>
    </body>
</html>
"""


class IndexHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write(index)
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

#****************************************************************************
#**               Unit 2 - Homework 2: Sigup Verification                  **
#****************************************************************************
signup_main = """
<!DOCTYPE html>

<html>
    <head>
        <title>Sign Up</title>
        <style type="text/css">
            .label {text-align: right}
            .error {color:red}
        </style>
    </head>
    <form method="post">
        <h2>Signup</h2>
        <br>
        <table>
            <tr>
                <td class="label">
                    Username
                </td>
                <td>
                    <input type="text" name="username" value="%(username)s">
                </td>
                <td class="error">
                    %(error_username)s
                </td>
            </tr>

            <tr>
                <td class="label">
                    Password
                </td>
                <td>
                    <input type="password" name="password" value="%(password)s">
                </td>
                <td class="error">
                    %(error_password)s
                </td>
            </tr>

            <tr>
                <td class="label">
                    Verify Password
                </td>
                <td>
                    <input type="password" name="verify" value="%(verify)s">
                </td>
                <td class="error">
                    %(error_verify)s
                </td>
            </tr>

            <tr>
                <td class="label">
                    Email (optional)
                </td>
                <td>
                    <input type="text" name="email" value="%(email)s">
                </td>
                <td class="error">
                    %(error_email)s
                </td>
            </tr>
        </table>
        <br>
        <input type="submit">
    </form>
</html>
"""

signup_welcome = """
<!DOCTYPE html>

<html>
  <head>
    <title>Unit 2 Signup</title>
  </head>

  <body>
    <h2>Welcome,%(username)s!</h2>
  </body>
</html>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def is_valid_username(username):
    return USER_RE.match(username)

def is_valid_password(password):
    return PASSWORD_RE.match(password)

def is_valid_email(email):
    return EMAIL_RE.match(email)


class Unit2SignUpHandler(webapp2.RequestHandler):
    def write_signup_main(self, username="", password="", verify="",email="",
                   error_username="", error_password="", error_verify="", 
                   error_email=""
        ):
            self.response.out.write(signup_main % {"username": username, 
                                            "password":password, 
                                            "verify":verify, 
                                            "email":email, 
                                            "error_username": error_username,
                                            "error_password":error_password,
                                            "error_verify":error_verify, 
                                            "error_email":error_email
                                            })
    def get(self):
        self.write_signup_main()
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
        if not(valid_username and valid_password and valid_verify and valid_email):
            self.write_signup_main(username, "", "", email, error_username, error_password, error_verify, error_email )
        else:
            self.redirect("/unit2/signup/welcome?username=" + username)
           
class Unit2SignUpWelcomeHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get( 'username' )
        self.response.out.write(signup_welcome %{"username": username})



#****************************************************************************
#**                              Page Handler                              **
#****************************************************************************
application = webapp2.WSGIApplication([
    ('/', IndexHandler),
    ('/unit1/HelloUdacity', Unit1HelloUdacityHandler),
    ('/unit2/rot13', Unit2Rot13Handler),
    ('/unit2/signup', Unit2SignUpHandler),
    ('/unit2/signup/welcome', Unit2SignUpWelcomeHandler),
], debug=True)

