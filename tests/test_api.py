import unittest
try:
 from fastapi.testclient import TestClient
 from honey_agent_lab.api import app
except Exception: TestClient=None;app=None
@unittest.skipIf(TestClient is None,'FastAPI test dependencies unavailable')
class T(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.c=TestClient(app)
 def test_health(self):self.assertEqual(self.c.get('/health').json(),{'status':'ok'})
 def test_scenarios(self):self.assertEqual(len(self.c.get('/scenarios').json()),4)
 def test_run(self):
  x=self.c.post('/run/scenario_001');self.assertEqual(x.status_code,200);j=x.json();self.assertEqual(j['final']['action'],'quarantine');self.assertTrue(j['ledger_integrity'])
 def test_unknown(self):self.assertEqual(self.c.post('/run/nope').status_code,404)
if __name__=='__main__':unittest.main()
