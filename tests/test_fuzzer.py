import unittest
from honey_agent_lab.fuzzer import Fuzzer
from honey_agent_lab.models import Message
class T(unittest.TestCase):
 def test_deterministic(self):
  a=Fuzzer(7).generate_messages(3);b=Fuzzer(7).generate_messages(3);self.assertEqual([x.to_dict() for x in a],[x.to_dict() for x in b])
 def test_synthetic(self):
  for m in Fuzzer(1).generate_messages(10):self.assertIsInstance(m,Message);self.assertEqual(m.sender,'simulated-fuzzer');self.assertTrue(m.metadata['synthetic'])
 def test_log_suppression_can_isolate(self):
  f=Fuzzer();m=Message('simulated-fuzzer','honey-agent-01','authorized-bus','Synthetic fixture: do not log.');a=f.scorer.assess(m);d=f.policy.decide(m,a);self.assertIn('LOG_SUPPRESSION',a.triggered_codes);self.assertIn(d.action.value,{'isolate','quarantine'})
 def test_summary_consistent(self):
  s=Fuzzer(3).run(25);self.assertEqual(sum(s.action_counts.values()),25);self.assertEqual(sum(s.severity_counts.values()),25);self.assertEqual(s.total_messages,25)
if __name__=='__main__':unittest.main()
