import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'gate'))
import decide


def valid():
    return [{'agent': 'claude', 'version': '2.1.312', 'probe': name, 'outcome': 'holds',
             'control': {'fired': True, 'exit': 0}, 'policy': {'fired': False, 'started': True, 'exit': 0}}
            for name in sorted(decide.EXPECTED['claude'])]


class AdmissionEvidenceTest(unittest.TestCase):
    def test_complete_valid_evidence(self):
        self.assertEqual(decide.evidence('claude', '2.1.312', valid())[1], [])

    def test_install_and_container_failure_deny(self):
        for probe in ('install', 'container'):
            rows = [{'agent': 'claude', 'version': '2.1.312', 'probe': probe, 'outcome': 'did_not_run'}]
            self.assertTrue(decide.evidence('claude', '2.1.312', rows)[1])

    def test_missing_duplicate_metadata_and_unknown_outcome_deny(self):
        cases = [valid()[:-1], valid() + [valid()[0]]]
        for key, value in [('agent', 'codex'), ('version', '1.0.0'), ('outcome', 'unknown')]:
            rows = copy.deepcopy(valid())
            rows[0][key] = value
            cases.append(rows)
        for rows in cases:
            self.assertTrue(decide.evidence('claude', '2.1.312', rows)[1])

    def test_invalid_control_cannot_admit(self):
        rows = valid()
        rows[0]['outcome'] = 'invalid_control'
        self.assertTrue(decide.evidence('claude', '2.1.312', rows)[1])

    def test_claimed_hold_needs_observations(self):
        for key, value in [('control', {}), ('policy', {'fired': True, 'started': True}),
                           ('policy', {'fired': False, 'started': False})]:
            rows = valid()
            rows[0][key] = value
            self.assertTrue(decide.evidence('claude', '2.1.312', rows)[1])

    def test_empty_and_malformed_files_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = Path(tmp)
            (gate / 'claude').mkdir()
            for text in ('', '{invalid'):
                (gate / 'claude/2.1.312.jsonl').write_text(text)
                summary, _ = decide.build_summary(gate)
                self.assertEqual(summary['agents']['claude']['admitted'], [])

    def test_crash_or_timeout_after_api_contact_cannot_admit(self):
        for code in ('timeout', 139, 1):
            rows = valid()
            rows[0]['policy']['exit'] = code
            self.assertTrue(decide.evidence('claude', '2.1.312', rows)[1])


if __name__ == '__main__':
    unittest.main()
