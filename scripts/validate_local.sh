#!/usr/bin/env bash
set -euo pipefail
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m honey_agent_lab run-scenario scenario_001 >/tmp/honey-agent-lab-scenario.txt
grep -q "Action: quarantine" /tmp/honey-agent-lab-scenario.txt
