import contextlib,io,json,tempfile,unittest
from pathlib import Path
from honey_agent_lab.cli import main,_is_loopback
from honey_agent_lab.models import Message,PolicyAction
from honey_agent_lab.orchestrator import run_scenario
from honey_agent_lab.risk import RiskScorer
class T(unittest.TestCase):
 def test_baselines(self):
  self.assertEqual(run_scenario('scenario_001').final_decision.action,PolicyAction.QUARANTINE)
  self.assertEqual(run_scenario('scenario_002').final_decision.action,PolicyAction.QUARANTINE)
  self.assertEqual(run_scenario('scenario_003').final_decision.action,PolicyAction.ISOLATE)
  self.assertEqual(run_scenario('scenario_004').final_decision.action,PolicyAction.ALLOW)
 def test_untrusted_auth_signal(self):
  a=RiskScorer().assess(Message('a','b','side-channel','routine synthetic update'));self.assertIn('UNTRUSTED_TRANSPORT',a.triggered_codes);self.assertIn('NO_AUTHORIZATION_EVIDENCE',a.triggered_codes)
 def test_boundary(self):self.assertNotIn('UNAUTHORIZED_CHANNEL',RiskScorer().assess(Message('a','b','authorized-bus','alongside channel review')).triggered_codes)
 def test_cli_fuzz_json(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):rc=main(['fuzz','--limit','5','--seed','1','--json'])
  self.assertEqual(rc,0);self.assertEqual(json.loads(out.getvalue())['total_messages'],5)
 def test_cli_rules_and_html(self):
  with tempfile.TemporaryDirectory() as d:
   html=Path(d)/'x.html';self.assertEqual(main(['run-scenario','scenario_001','--output-html',str(html)]),0);self.assertIn('Risk findings',html.read_text())
 def test_loopback_guard(self):self.assertTrue(_is_loopback('127.0.0.1'));self.assertTrue(_is_loopback('::1'));self.assertTrue(_is_loopback('localhost'));self.assertFalse(_is_loopback('0.0.0.0'))
 def test_serve_refusal(self):
  err=io.StringIO()
  with contextlib.redirect_stderr(err):rc=main(['serve','--host','0.0.0.0'])
  self.assertEqual(rc,2);self.assertIn('Refusing',err.getvalue())
if __name__=='__main__':unittest.main()
