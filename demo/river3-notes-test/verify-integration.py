#!/usr/bin/env python3
"""Exercise real shadow/active containment with an explicit operator test command."""

import datetime
import json
from pathlib import Path
import subprocess
import sys
import time

import river3ctl as r


def ctl(command):
    subprocess.run([sys.executable, str(r.ROOT / 'river3ctl.py'), command], check=True)


def state():
    return json.loads(r.docker('inspect', 'river3-notes-agent'))[0]['State']


def incidents():
    return [i for i in r.request('/api/v1/incidents?limit=100') if i['workload']['id'] == r.WORKLOAD]


def wait_for(fn, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(0.5)
    raise RuntimeError('Timed out waiting for the expected live River3 result')


def probe():
    command = ['docker', 'compose', 'exec', '-T', 'agent', 'wget', '--version']
    try:
        p = subprocess.run(command, cwd=r.ROOT, capture_output=True, text=True, timeout=8)
        return {'command': command, 'exit_code': p.returncode,
                'stdout': p.stdout[:2000], 'stderr': p.stderr[:2000]}
    except subprocess.TimeoutExpired:
        return {'command': command, 'client_timed_out': True,
                'note': 'The command may be suspended inside the paused container.'}


def main():
    # Never interrupt an in-progress model experiment to perform this separate test.
    if '/agents/agent.py' in r.docker('top', 'river3-notes-agent', '-eo', 'pid,args'):
        raise RuntimeError('Wait for the coding-agent task to finish before running this test')
    if state()['Paused']:
        raise RuntimeError('Review and resume the existing incident before running this test')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder = r.ROOT / 'evidence' / ('containment-' + stamp)
    folder.mkdir()
    report = {'started_at': stamp, 'type': 'operator containment test, not an LLM injection result',
              'probe': 'wget --version (no remote download)', 'passed': False}
    try:
        ctl('ready')
        ctl('shadow')
        old = {i['id'] for i in incidents()}
        report['shadow_command'] = probe()
        shadow = wait_for(lambda: next((i for i in incidents()
                                       if i['id'] not in old and i['rule'] == 'EXEC_CLASS_DENIED'), None))
        report['shadow_incident'] = r.request('/api/v1/incidents/' + shadow['id'])
        report['shadow_state'] = state()
        assert shadow['mode'] == 'shadow' and not report['shadow_state']['Paused']
        print('PASS: shadow mode recorded the forbidden wget execution without pausing.')

        ctl('active')
        old = {i['id'] for i in incidents()}
        report['active_command'] = probe()
        wait_for(lambda: state()['Paused'])
        active = wait_for(lambda: next((i for i in incidents()
                                       if i['id'] not in old and i['rule'] == 'EXEC_CLASS_DENIED'
                                       and i['response'].get('state') == 'verified'), None))
        report['active_incident'] = r.request('/api/v1/incidents/' + active['id'])
        report['paused_state'] = state()
        assert active['response']['action'] == 'PAUSE_CONTAINER'
        assert report['paused_state']['Paused'] and active['mode'] == 'active'
        print('PASS: active mode paused the real container and verified the pause.')
        report['passed'] = True
    except BaseException as error:
        # Keep the real failure in the evidence; cleanup below must not hide it.
        report['failure'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        save(folder, report)
        cleanup(folder, report)
    print(folder / 'verification.json')
    if report.get('cleanup_errors'):
        sys.exit(1)
    print('PASS: restored shadow mode and resumed the agent through River3.')


def save(folder, report):
    (folder / 'verification.json').write_text(json.dumps(report, indent=2, default=str))


def step(report, name, fn):
    """Run one cleanup step; record its error instead of raising, so later steps still run."""
    try:
        return fn()
    except Exception as error:
        report.setdefault('cleanup_errors', {})[name] = f'{type(error).__name__}: {error}'
        print(f'CLEANUP FAILED ({name}): {error}', file=sys.stderr)
        return None


def cleanup(folder, report):
    step(report, 'shadow', lambda: ctl('shadow'))
    if step(report, 'state', lambda: state()['Paused']):
        step(report, 'resume', lambda: ctl('resume'))
    report['final_state'] = step(report, 'final_state', state)
    report['restored_to_shadow'] = 'shadow' not in report.get('cleanup_errors', {})
    if 'active_incident' in report:
        report['active_incident_after_resume'] = step(
            report, 'incident_after_resume',
            lambda: r.request('/api/v1/incidents/' + report['active_incident']['id']))
    export = step(report, 'export', lambda: r.request('/api/v1/workloads/' + r.WORKLOAD + '/export'))
    if export is not None:
        (folder / 'kernel-events.json').write_text(json.dumps(export, indent=2))
    save(folder, report)
    if report.get('cleanup_errors'):
        print('WARNING: cleanup incomplete; check that the agent is unpaused and the profile is in shadow mode.',
              file=sys.stderr)


if __name__ == '__main__':
    main()
