import unittest
import requests
from app import app
from bs4 import BeautifulSoup


server_address = "http://127.0.0.1:5000"


class FeatureTest(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        app.testing = True

    def test_register(self):
        req = requests.get(server_address + "/register")
        self.assertEqual(req.status_code, 200)

    def test_login(self):
        req = requests.get(server_address + "/login")
        self.assertEqual(req.status_code, 200)

    def test_no_login(self):
        req = requests.get(server_address + "/spell_check")
        self.assertEqual(req.status_code, 401)

    def test_spell_check(self):
        headers = {'User-Agent': 'My User Agent'}
        s = requests.Session()
        req = s.get(server_address + "/register")
        headers['cookie'] = '; '.join([x.name + '=' + x.value for x in req.cookies])
        headers['content-type'] = 'application/x-www-form-urlencoded'
        self.assertEqual(req.status_code, 200)
        uname = 'thava'
        pword = "1981228jothy"
        mfa = "9084101095"
        req = s.post(server_address + "/register", data=dict(
            uname=uname, pword=pword, mfa=mfa), headers=headers
                     )

        req = s.get(server_address + "/login")
        headers['cookie'] = '; '.join([x.name + '=' + x.value for x in req.cookies])
        headers['content-type'] = 'application/x-www-form-urlencoded'
        req = s.post(server_address + "/login", data=dict(
            uname=uname, pword=pword, mfa=mfa), headers=headers
                     )

        self.assertEqual(req.status_code, 200)
        req = s.get(server_address + "/spell_check")
        self.assertEqual(req.status_code, 200)
        inputtext = "lion is not the kiing of jjungle"
        req = s.post(server_address + "/spell_check", data=dict(
            inputtext=inputtext)
                     )
        soup = BeautifulSoup(req.content, 'html.parser')
        misspelled = soup.find("p", {"id": "misspelled"})
        textout = soup.find("p", {"id": "textout"})
        mspelled = 'kiing, jjungle'
        tout = "lion is not the kiing of jjungle"
        self.assertEqual(mspelled, misspelled.text)
        self.assertEqual(tout, textout.text)

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
