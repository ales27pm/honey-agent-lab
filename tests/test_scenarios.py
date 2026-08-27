import tempfile
import unittest
from honey_agent_lab.models import PolicyAction
from honey_agent_lab.orchestrator import run_scenario
from honey_agent_lab.scenarios import get_scenario, list_scenarios
class ScenarioTests(unittest.TestCase):
 def test_all_scenarios_are_registered(self):
  names={s.name for s in list_scenarios()};self.assertEqual({"scenario_001","scenario_002","scenario_003","scenario_004","scenario_005"},names);self.assertEqual(get_scenario("scenario_001").name,"scenario_001")
 def test_baselines(self):
  self.assertEqual(run_scenario("scenario_001").final_decision.action,PolicyAction.QUARANTINE);self.assertEqual(run_scenario("scenario_002").final_decision.action,PolicyAction.QUARANTINE);self.assertEqual(run_scenario("scenario_003").final_decision.action,PolicyAction.ISOLATE);self.assertEqual(run_scenario("scenario_004").final_decision.action,PolicyAction.ALLOW)
 def test_multiturn_grooming_escalates(self):
  r=run_scenario("scenario_005");self.assertEqual([x.decision.action for x in r.message_results],[PolicyAction.ALLOW,PolicyAction.WARN,PolicyAction.QUARANTINE]);self.assertIn("UNAUTHORIZED_CHANNEL",r.message_results[2].assessment.triggered_codes);self.assertTrue(r.ledger.verify_integrity())
 def test_audit_export(self):
  r=run_scenario("scenario_001")
  with tempfile.TemporaryDirectory() as tmp:
   text=r.write_audit(f"{tmp}/audit.jsonl").read_text()
  self.assertIn("risk_context_updated",text)
if __name__=="__main__":unittest.main()
