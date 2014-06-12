import webapp2
import cgi
form = """
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
    #return cgi.escape(''.join(str_list), quote=True)
    return cgi.escape(''.join(str_list), quote=True)


class MainPage(webapp2.RequestHandler):
    def write_form(self, text=""):
            self.response.out.write(form % {"text": text})
    def get(self):
        self.write_form()
    def post(self):
        text = self.request.get('text')
        self.write_form(rot13(text))
            


application = webapp2.WSGIApplication([
    ('/', MainPage),
], debug=True)
