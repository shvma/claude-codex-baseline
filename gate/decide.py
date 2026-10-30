#!/usr/bin/env python3
"""Fail-closed release admission from complete, positively controlled evidence.

A version is admitted only when every expected probe holds with a valid positive control, the policy
run's output shows no ignored requirement, and the version is not older than any rule's min_version
(build/coverage.json, built from baseline/rules.yaml).
"""
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COVERAGE = ROOT / 'build/coverage.json'
# Probes whose policy run passes only by refusing to start with this text in the output.
REFUSALS = {('claude', 'sideload_mcp_flag'): ('disableSideloadFlags', 'disabled')}
# The agent saying it dropped part of the policy (seen: Codex 0.137.0-0.138.0 on features.in_app_updates).
IGNORED = re.compile(r'Ignoring unknown [^\n]*requirement[^\n]*', re.I)
EXPECTED = {
    'claude': {'repo_hook', 'repo_mcp', 'bypass_flag', 'sideload_mcp_flag',
               'repo_env_base_url', 'repo_api_key_helper'},
    'codex': {'repo_hook', 'repo_mcp', 'approval_never', 'sandbox_full_access',
              'bypass_all_flag', 'user_config_relax'},
}


def vkey(version):
    parts = version.split('.')
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError('version must be major.minor.patch')
    return tuple(map(int, parts))


def min_versions(agent, coverage=None):
    """{rule: oldest version that enforces it} for one agent."""
    path = Path(coverage or COVERAGE)
    rules = json.loads(path.read_text())['rules'] if path.exists() else {}
    return {rid: r['min_version'][agent] for rid, r in sorted(rules.items()) if agent in (r.get('min_version') or {})}


def evidence(agent, version, raw, minimums=None):
    """No missing probe, unknown outcome, broken control, ignored requirement, runner error or version
    below a rule's minimum may admit."""
    expected = EXPECTED.get(agent, set())
    rows, errors = {}, []
    if not expected:
        errors.append('unknown_agent')
    minimums = min_versions(agent) if minimums is None else minimums
    try:
        errors += ['below_min_version:%s>=%s' % (rid, v) for rid, v in minimums.items() if vkey(version) < vkey(v)]
    except ValueError:
        errors.append('invalid_version')
    for row in raw:
        if not isinstance(row, dict):
            errors.append('invalid_row')
            continue
        name = row.get('probe')
        if name not in expected:
            errors.append('unexpected_probe:' + str(name))
        if name in rows:
            errors.append('duplicate_probe:' + str(name))
        rows[name] = row
        if row.get('agent') != agent or row.get('version') != version:
            errors.append('metadata_mismatch:' + str(name))
    outcomes = {}
    for name in sorted(expected):
        row = rows.get(name, {})
        outcome = row.get('outcome', 'did_not_run')
        if outcome not in ('holds', 'does_not_hold', 'invalid_control', 'did_not_run'):
            errors.append('unknown_outcome:' + name)
            outcome = 'did_not_run'
        control, policy = row.get('control', {}), row.get('policy', {})
        refusal = REFUSALS.get((agent, name))
        if isinstance(policy, dict):
            text = str(policy.get('output', '')) + '\n' + '\n'.join(map(str, policy.get('warnings') or []))
            errors += ['policy_ignored:%s:%s' % (name, m.strip()[:120]) for m in sorted(set(IGNORED.findall(text)))]
        if outcome == 'holds' and not (isinstance(control, dict) and isinstance(policy, dict)
                and control.get('fired') is True and policy.get('fired') is False
                and policy.get('started') is True and control.get('exit') == 0
                and (policy.get('exit') == 0 if refusal is None else
                     policy.get('exit') == 1 and all(t in str(policy.get('output', '')) for t in refusal))):
            errors.append('unproven_hold:' + name)
            outcome = 'did_not_run'
        outcomes[name] = outcome
    bad = errors + [name + ':' + outcome for name, outcome in outcomes.items() if outcome != 'holds']
    return outcomes, bad


def fingerprinted(raw):
    """Rows written by the current runner carry input_sha256 (image + gate code + build under test)."""
    return bool(raw) and all(isinstance(r, dict) and r.get('input_sha256') for r in raw)


def build_summary(gate, minimums=None, require_fingerprint=False):
    summary = {'agents': {}}
    md = ['# Release gate decisions', '',
          'Admit requires the complete expected probe set, valid positive controls, no requirement the agent '
          'reports as ignored, and a version no older than any rule\'s min_version (build/coverage.json). '
          'Missing, invalid or unavailable evidence denies admission.', '',
          'Evidence: *fingerprinted* rows carry input_sha256 from the current runner (gate/run_gate.py); '
          '*legacy* rows were written by an earlier runner without it and were judged by this file\'s '
          'current rules, not re-run.', '']
    for directory in sorted(p for p in gate.iterdir() if p.is_dir()):
        agent, results, invalid = directory.name, {}, {}
        for path in directory.glob('*.jsonl'):
            try:
                vkey(path.stem)
                results[path.stem] = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
            except (ValueError, OSError) as exc:
                results[path.stem] = []
                invalid[path.stem] = str(exc)
        versions = sorted(results, key=lambda v: vkey(v) if v not in invalid else (0, 0, 0))
        probes = sorted(EXPECTED.get(agent, ()))
        decisions, reasons, regressions, rows, previous = {}, {}, [], [], None
        previous_outcomes, kinds = {}, {}
        agent_minimums = min_versions(agent) if minimums is None else minimums.get(agent, {})
        for version in versions:
            outcomes, bad = evidence(agent, version, results[version], agent_minimums)
            if version in invalid:
                bad.append('invalid_json:' + invalid[version])
            kinds[version] = 'fingerprinted' if fingerprinted(results[version]) else 'legacy'
            if require_fingerprint and kinds[version] == 'legacy':
                bad.append('legacy_evidence')
            decisions[version] = 'deny' if bad else 'admit'
            reasons[version] = bad
            if previous:
                for probe in probes:
                    if previous_outcomes.get(probe) == 'holds' and outcomes[probe] == 'does_not_hold':
                        regressions.append({'probe': probe, 'from': previous, 'to': version})
            rows.append('| ' + version + ' | ' + ' | '.join(outcomes[p].replace('_', ' ') for p in probes)
                        + ' | ' + kinds[version] + ' | **' + decisions[version] + '** |')
            previous, previous_outcomes = version, outcomes
        admitted = [v for v in versions if decisions[v] == 'admit']
        summary['agents'][agent] = {'versions_tested': len(versions), 'admitted': admitted,
            'denied': [v for v in versions if decisions[v] == 'deny'], 'regressions': regressions,
            'denial_reasons': {v: reasons[v] for v in versions if reasons[v]},
            'min_versions': agent_minimums,
            'evidence': {k: [v for v in versions if kinds[v] == k] for k in ('fingerprinted', 'legacy')}}
        md += ['## ' + agent, '', 'Minimum versions: ' + (', '.join('%s %s' % kv for kv in agent_minimums.items()) or 'none') + '.', '',
               '| version | ' + ' | '.join(probes) + ' | evidence | decision |',
               '|---|' + '---|' * (len(probes) + 2), *rows, '']
        denied = [v for v in versions if decisions[v] == 'deny']
        if denied:
            md += ['Denial reasons:', ''] + ['- %s: %s' % (v, '; '.join(reasons[v])) for v in denied] + ['']
    summary['versions_tested'] = sum(a['versions_tested'] for a in summary['agents'].values())
    summary['regressions'] = sum(len(a['regressions']) for a in summary['agents'].values())
    return summary, '\n'.join(md) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('gate', nargs='?', type=Path, default=ROOT / 'results/gate')
    parser.add_argument('--require-admit', action='store_true', help='fail if any version lacks full proof')
    parser.add_argument('--require-fingerprint', action='store_true',
                        help='deny versions whose rows lack input_sha256 (written before the current runner)')
    args = parser.parse_args()
    if not args.gate.is_dir():
        parser.error('gate results directory is missing')
    summary, markdown = build_summary(args.gate, require_fingerprint=args.require_fingerprint)
    (args.gate / 'decisions.md').write_text(markdown)
    (args.gate / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(markdown)
    if not summary['versions_tested']:
        return 1
    return int(args.require_admit and any(a['denied'] for a in summary['agents'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
