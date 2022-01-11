import os,sys 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.wrappers import response
from todo import app
import unittest

class FlaskTest(unittest.TestCase):

    def test_login(self):
        tester = app.test_client(self)
        response = tester.get("/login")
        self.assertEqual(response.status_code, 401)
        pass

if __name__=="__main__": 
    unittest.main()