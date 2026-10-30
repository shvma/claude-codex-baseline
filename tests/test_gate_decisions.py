import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'gate'))
import decide


REFUSAL = ("--mcp-config is disabled by your organization's managed settings (disableSideloadFlags).")


def valid(agent='claude', version='2.1.312'):
    rows = [{'agent': agent, 'version': version, 'probe': name, 'outcome': 'holds',
             'control': {'fired': True, 'exit': 0}, 'policy': {'fired': False, 'started': True, 'exit': 0}}
            for name in sorted(decide.EXPECTED[agent])]
    for row in rows:
        if (agent, row['probe']) in decide.REFUSALS:
            row['policy'].update(exit=1, output=REFUSAL)
    return rows


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


ROOT = Path(__file__).resolve().parents[1]


def stored(agent, version):
    return [json.loads(line) for line in (ROOT / 'results/gate' / agent / (version + '.jsonl')).read_text().splitlines()]


class ReviewCasesTest(unittest.TestCase):
    """gate_what_if.py from the 2026-10-30 review, on the stored results."""

    def test_sideload_without_refusal_cannot_admit(self):
        rows = valid()
        for row in rows:
            if row['probe'] == 'sideload_mcp_flag':
                row['policy'].update(exit=0, output='ok')  # flag accepted, server stopped by another key
        self.assertIn('unproven_hold:sideload_mcp_flag', decide.evidence('claude', '2.1.312', rows)[1])
        rows = stored('claude', '2.1.150')
        for row in rows:
            if row['probe'] == 'sideload_mcp_flag':
                row['policy']['started'], row['outcome'] = True, 'holds'
        self.assertIn('unproven_hold:sideload_mcp_flag', decide.evidence('claude', '2.1.150', rows)[1])

    def test_ignored_requirement_in_agent_output_denies(self):
        rows = stored('codex', '0.137.0')
        for row in rows:
            if row['probe'] == 'repo_hook':
                row['control']['fired'], row['outcome'] = True, 'holds'
        bad = decide.evidence('codex', '0.137.0', rows, minimums={})[1]
        self.assertTrue(any(b.startswith('policy_ignored:') and 'in_app_updates' in b for b in bad), bad)

    def test_ignored_requirement_in_warnings_field_denies(self):
        rows = valid('codex', '0.166.0')
        rows[0]['policy']['warnings'] = ['warning: Ignoring unknown `features` requirement `x` from /etc/codex/requirements.toml']
        self.assertTrue(decide.evidence('codex', '0.166.0', rows, minimums={})[1])
        self.assertEqual(decide.evidence('codex', '0.166.0', valid('codex', '0.166.0'), minimums={})[1], [])

    def test_versions_below_rule_minimum_deny(self):
        self.assertIn('below_min_version:R03>=2.1.223', decide.evidence('claude', '2.1.193', stored('claude', '2.1.193'))[1])
        self.assertIn('below_min_version:R09>=2.1.193', decide.evidence('claude', '2.1.150', stored('claude', '2.1.150'))[1])
        mins = decide.min_versions('claude')
        self.assertEqual(mins['R03'], '2.1.223')
        self.assertEqual(decide.evidence('claude', '2.1.312', valid(), mins)[1], [])
        self.assertTrue(decide.evidence('claude', '2.1.284', valid('claude', '2.1.284'), mins)[1])

    def test_legacy_rows_are_labelled_and_can_be_required_away(self):
        self.assertFalse(decide.fingerprinted(stored('claude', '2.1.312')))
        self.assertTrue(decide.fingerprinted([dict(r, input_sha256='x') for r in valid()]))
        with tempfile.TemporaryDirectory() as tmp:
            gate = Path(tmp)
            (gate / 'claude').mkdir()
            (gate / 'claude/2.1.312.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in valid()))
            summary, md = decide.build_summary(gate, minimums={'claude': {}})
            self.assertEqual(summary['agents']['claude']['admitted'], ['2.1.312'])
            self.assertEqual(summary['agents']['claude']['evidence']['legacy'], ['2.1.312'])
            self.assertIn('| legacy |', md)
            summary, _ = decide.build_summary(gate, minimums={'claude': {}}, require_fingerprint=True)
            self.assertEqual(summary['agents']['claude']['admitted'], [])


if __name__ == '__main__':
    unittest.main()
