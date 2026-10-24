#!/usr/bin/env python3
"""Configure and inspect the local River3 experiment using its supported API."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
API = os.getenv('RIVER3_API', 'http://127.0.0.1:8001')
CONTROLLER = os.getenv('RIVER3_CONTROLLER', 'http://127.0.0.1:8788')
PROFILE = 'coding-notes-agent'
WORKLOAD = 'coding-notes-agent-01'


def request(path, body=None, method=None, base=API):
    req = urllib.request.Request(
        base + path, data=None if body is None else json.dumps(body).encode(), method=method,
        headers={'Authorization': 'Bearer ' + os.getenv('RIVER3_OPERATOR_TOKEN', 'dev-operator-token'),
                 'Content-Type': 'application/json'},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, cwd=ROOT)


def model_rules():
    networks = json.loads(docker('inspect', 'river3-notes-model'))[0]['NetworkSettings']['Networks']
    addresses = sorted({net['IPAddress'] for net in networks.values() if net['IPAddress']})
    if not addresses:
        raise RuntimeError('Start the model container before initializing its policy')
    # This controller revision does not forward target.port to the policy Event.
    # Address-only rules avoid incorrectly flagging legitimate model inference.
    return ['127.0.0.0/8'] + [ip + '/32' for ip in addresses]


def starter():
    return {
        'name': PROFILE, 'kind': 'ai_worker', 'version': 1, 'mode': 'SHADOW_MODE',
        'description': 'Local coding agent: project files and local inference allowed; network-client execution and external egress are out of scope.',
        'decoys': [], 'protected_read': ['/etc/shadow', '/root/**'],
        'read_allowed': ['/', '/workspace/**', '/agents/**', '/evidence/**', '/usr/**', '/lib/**',
                         '/lib64/**', '/etc/**', '/proc/**', '/sys/**', '/dev/**', '/tmp/**'],
        'write_allowed': ['/workspace/**', '/evidence/**', '/tmp/**', '/dev/null'],
        'exec_allowed_classes': ['INTERPRETER', 'DIAGNOSTIC', 'OTHER'],
        'exec_denied_classes': ['NET_CLIENT', 'PRIVILEGED_TOOL'],
        'egress_allowed': model_rules(),
        'response': {'on_violation': 'PAUSE_CONTAINER', 'on_structural_guard': 'ALERT'},
    }


def save(profile, version, comment):
    return request('/api/v1/policies/' + PROFILE,
                   {'profile': profile, 'base_version': version, 'comment': comment}, 'PUT')


def wait_synced(version):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        bundle = request('/api/v1/policies')
        # Controller sync reports provide the applied policy-bundle revision.
        controllers = bundle.get('controllers', [])
        if any(c.get('active_revision') == bundle.get('revision') and not c.get('error') for c in controllers):
            print(f'Controller has applied policy version {version}.')
            return
        time.sleep(1)
    raise RuntimeError('Controller did not acknowledge the current policy bundle within 30 seconds')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init', 'shadow', 'active', 'ready', 'resume', 'status', 'export'])
    args = parser.parse_args()
    if args.command == 'init':
        try:
            current = request('/api/v1/policies/' + PROFILE)['profile']
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            current = None
        if current is None:
            result = save(starter(), 0, 'Initialize local coding-agent experiment in shadow mode')
        else:
            profile = current['body']
            rules = model_rules()
            needs_root = '/' not in profile['read_allowed']
            if profile['egress_allowed'] == rules and not needs_root:
                result = current
            else:
                profile['egress_allowed'] = rules
                if needs_root:
                    profile['read_allowed'].insert(0, '/')
                result = save(profile, current['version'], 'Allow Docker exec directory setup and local inference addresses')
        (ROOT / 'integration/profiles/coding-notes-agent.json').write_text(json.dumps(result['body'], indent=2) + '\n')
        print(f"{PROFILE}: version {result['version']}, {result['body']['mode']}")
    elif args.command in ('shadow', 'active'):
        current = request('/api/v1/policies/' + PROFILE)['profile']
        profile = current['body']
        mode = 'SHADOW_MODE' if args.command == 'shadow' else 'ACTIVE_FREEZE_MODE'
        if profile['mode'] != mode:
            profile['mode'] = mode
            current = save(profile, current['version'], f'Switch local coding-agent experiment to {args.command} mode')
        wait_synced(current['version'])
        print(mode)
    elif args.command == 'ready':
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                health = request('/healthz', base=CONTROLLER)
                workloads = request('/api/v1/workloads')
                if (health.get('adapter') == 'docker' and health['registry']['workloads'] >= 1
                        and any(w['id'] == WORKLOAD for w in workloads)):
                    current = request('/api/v1/policies/' + PROFILE)['profile']
                    wait_synced(current['version'])
                    print('Real Docker controller and sensor enrollment are ready.')
                    return
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(1)
        raise RuntimeError('Real controller or sensor enrollment did not become ready')
    elif args.command == 'resume':
        state = json.loads(docker('inspect', 'river3-notes-agent'))[0]['State']
        if not state['Paused']:
            print('Agent is already unpaused.')
            return
        incidents = request('/api/v1/incidents?status=contained&limit=100')
        incident = next((i for i in incidents if i['workload']['id'] == WORKLOAD), None)
        if incident is None:
            raise RuntimeError('No contained River3 incident found for this paused agent')
        result = request('/api/v1/incidents/' + incident['id'] + '/actions',
                         {'action': 'resume', 'reason': 'Resume local coding-agent experiment after reviewing containment evidence'}, 'POST')
        print(json.dumps(result))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if not json.loads(docker('inspect', 'river3-notes-agent'))[0]['State']['Paused']:
                print('Agent resumed through the River3 operator-action API.')
                return
            time.sleep(1)
        raise RuntimeError('River3 did not resume the agent within 30 seconds')
    elif args.command == 'status':
        print(json.dumps({'controller': request('/healthz', base=CONTROLLER),
                          'workloads': request('/api/v1/workloads'),
                          'policies': request('/api/v1/policies'),
                          'container': json.loads(docker('inspect', 'river3-notes-agent'))[0]['State']}, indent=2))
    else:
        data = request(f'/api/v1/workloads/{WORKLOAD}/export')
        target = ROOT / 'evidence' / (time.strftime('river3-export-%Y%m%d-%H%M%S') + '.json')
        target.write_text(json.dumps(data, indent=2))
        print(target)


if __name__ == '__main__':
    main()
