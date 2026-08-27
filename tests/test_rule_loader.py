import json,tempfile,unittest
from pathlib import Path
from honey_agent_lab.rule_loader import load_rules
from honey_agent_lab.risk import RiskScorer
from honey_agent_lab.models import Message
class T(unittest.TestCase):
 def test_default(self): self.assertEqual(len(load_rules()),8); self.assertEqual(len(RiskScorer.RULES),8)
 def test_custom(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"r.json";p.write_text(json.dumps([{"code":"TEST_SIGNAL","score":40,"severity":"high","reason":"test","keywords":["synthetic marker"]}]))
   r=load_rules(p);self.assertEqual(r[0].code,"TEST_SIGNAL");self.assertIn("TEST_SIGNAL",RiskScorer(r).assess(Message("a","b","authorized-bus","synthetic marker")).triggered_codes)
 def test_invalid_cases(self):
  bads=[[{"code":"X","score":1,"severity":"low","reason":"x"}],[{"code":"bad code","score":1,"severity":"low","reason":"x","keywords":["x"]}],[{"code":"X","score":"1","severity":"low","reason":"x","keywords":["x"]}],[{"code":"X","score":1,"severity":"weird","reason":"x","keywords":["x"]}]]
  for data in bads:
   with self.subTest(data=data),tempfile.TemporaryDirectory() as d:
    p=Path(d)/"r.json";p.write_text(json.dumps(data))
    with self.assertRaises(ValueError):load_rules(p)
if __name__=='__main__':unittest.main()
