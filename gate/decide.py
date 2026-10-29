#!/usr/bin/env python3
"""Fail-closed release admission from complete, positively controlled evidence."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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


def evidence(agent, version, raw):
    """No missing probe, unknown outcome, broken control or runner error may admit."""
    expected = EXPECTED.get(agent, set())
    rows, errors = {}, []
    if not expected:
        errors.append('unknown_agent')
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
        if outcome == 'holds' and not (isinstance(control, dict) and isinstance(policy, dict)
                and control.get('fired') is True and policy.get('fired') is False
                and policy.get('started') is True and control.get('exit') == 0
                and (policy.get('exit') == 0 or (agent == 'claude' and name == 'sideload_mcp_flag'
                    and policy.get('exit') == 1 and 'disableSideloadFlags' in policy.get('output', '')
                    and 'disabled' in policy.get('output', '')))):
            errors.append('unproven_hold:' + name)
            outcome = 'did_not_run'
        outcomes[name] = outcome
    bad = errors + [name + ':' + outcome for name, outcome in outcomes.items() if outcome != 'holds']
    return outcomes, bad


def build_summary(gate):
    summary = {'agents': {}}
    md = ['# Release gate decisions', '',
          'Admit requires the complete expected probe set and valid positive controls. '
          'Missing, invalid or unavailable evidence denies admission.', '']
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
        previous_outcomes = {}
        for version in versions:
            outcomes, bad = evidence(agent, version, results[version])
            if version in invalid:
                bad.append('invalid_json:' + invalid[version])
            decisions[version] = 'deny' if bad else 'admit'
            reasons[version] = bad
            if previous:
                for probe in probes:
                    if previous_outcomes.get(probe) == 'holds' and outcomes[probe] == 'does_not_hold':
                        regressions.append({'probe': probe, 'from': previous, 'to': version})
            rows.append('| ' + version + ' | ' + ' | '.join(outcomes[p].replace('_', ' ') for p in probes)
                        + ' | **' + decisions[version] + '** |')
            previous, previous_outcomes = version, outcomes
        admitted = [v for v in versions if decisions[v] == 'admit']
        summary['agents'][agent] = {'versions_tested': len(versions), 'admitted': admitted,
            'denied': [v for v in versions if decisions[v] == 'deny'], 'regressions': regressions,
            'denial_reasons': {v: reasons[v] for v in versions if reasons[v]}}
        md += ['## ' + agent, '', '| version | ' + ' | '.join(probes) + ' | decision |',
               '|---|' + '---|' * (len(probes) + 1), *rows, '']
    summary['versions_tested'] = sum(a['versions_tested'] for a in summary['agents'].values())
    summary['regressions'] = sum(len(a['regressions']) for a in summary['agents'].values())
    return summary, '\n'.join(md) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('gate', nargs='?', type=Path, default=ROOT / 'results/gate')
    parser.add_argument('--require-admit', action='store_true', help='fail if any version lacks full proof')
    args = parser.parse_args()
    if not args.gate.is_dir():
        parser.error('gate results directory is missing')
    summary, markdown = build_summary(args.gate)
    (args.gate / 'decisions.md').write_text(markdown)
    (args.gate / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    print(markdown)
    if not summary['versions_tested']:
        return 1
    return int(args.require_admit and any(a['denied'] for a in summary['agents'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
