"""Offline preview gates: no Docker daemon, registry credentials or publication."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/docker/preview.py'
SPEC = importlib.util.spec_from_file_location('docker_preview', SCRIPT)
preview = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preview)
SHA = 'a' * 40


def workflow():
    return yaml.load((ROOT / '.github/workflows/docker-preview.yml').read_text(), Loader=yaml.BaseLoader)


def image_info(architecture='amd64'):
    return {'Os': 'linux', 'Architecture': architecture, 'Config': {'Labels': {
        'org.opencontainers.image.revision': SHA,
        'org.opencontainers.image.source': 'https://github.com/dplush/mnemosyne'}}}


def test_commit_preview_metadata():
    meta = preview.metadata('dplush/mnemosyne', SHA, 'ddplush')
    assert meta['image'] == 'ddplush/mnemosyne-mcp'
    assert meta['tag'] == 'preview-sha-' + SHA
    assert 'latest' not in meta.values()


@pytest.mark.parametrize('repository,sha,username', [
    ('mnemosyne-oss/mnemosyne', SHA, 'ddplush'), ('other/fork', SHA, 'ddplush'),
    ('dplush/mnemosyne', 'main', 'ddplush'), ('dplush/mnemosyne', 'a' * 7, 'ddplush'),
    ('dplush/mnemosyne', 'A' * 40, 'ddplush'), ('dplush/mnemosyne', SHA + '\n', 'ddplush'),
    ('dplush/mnemosyne', SHA, 'user/repo'), ('dplush/mnemosyne', SHA, 'user\nIMAGE=bad'),
])
def test_invalid_targets_and_mutable_refs_are_rejected(repository, sha, username):
    with pytest.raises(ValueError):
        preview.metadata(repository, sha, username)


@pytest.mark.parametrize('architecture', ['amd64', 'arm64'])
def test_native_platform_and_source_identity(architecture):
    preview.verify_image(image_info(architecture), preview.metadata(preview.FORK, SHA, 'ddplush'), architecture)


@pytest.mark.parametrize('field,value', [('Os', 'windows'), ('Architecture', 'arm64'),
                                         ('revision', 'b' * 40), ('source', 'https://github.com/other/fork')])
def test_wrong_tested_image_is_rejected(field, value):
    info = image_info()
    if field in ('Os', 'Architecture'):
        info[field] = value
    else:
        info['Config']['Labels']['org.opencontainers.image.' + field] = value
    with pytest.raises(ValueError):
        preview.verify_image(info, preview.metadata(preview.FORK, SHA, 'ddplush'), 'amd64')


def test_manifest_uses_pushed_repository_digests():
    digest = 'ddplush/mnemosyne-mcp@sha256:' + 'b' * 64
    assert preview.pushed_digest({'RepoDigests': [digest]}, 'ddplush/mnemosyne-mcp') == digest
    assert preview.pushed_digest({'RepoDigests': ['docker.io/' + digest]}, 'ddplush/mnemosyne-mcp') == 'docker.io/' + digest
    for values in ([], ['other/repo@sha256:' + 'b' * 64], [digest, digest], ['ddplush/mnemosyne-mcp:latest']):
        with pytest.raises(ValueError):
            preview.pushed_digest({'RepoDigests': values}, 'ddplush/mnemosyne-mcp')


def test_manual_fork_only_and_two_publish_opt_ins():
    w = workflow()
    assert set(w['on']) == {'workflow_dispatch'}
    assert w['env']['DOCKERHUB_USERNAME'] == 'ddplush'
    assert w['on']['workflow_dispatch']['inputs']['publish']['default'] == 'false'
    assert w['on']['workflow_dispatch']['inputs']['publish']['type'] == 'boolean'
    assert w['permissions'] == {'contents': 'read'}
    native = w['jobs']['build-and-test']
    publish = w['jobs']['publish']
    assert native['if'] == "github.repository == 'dplush/mnemosyne'"
    assert publish['needs'] == 'build-and-test'
    assert publish['if'] == ("github.repository == 'dplush/mnemosyne' && inputs.publish && "
                             "vars.MNEMOSYNE_DOCKERHUB_PREVIEW_ENABLED == 'true'")
    assert publish['environment'] == 'dockerhub-preview'
    assert {(v['runner'], v['architecture']) for v in native['strategy']['matrix']['include']} == {
        ('ubuntu-24.04', 'amd64'), ('ubuntu-24.04-arm', 'arm64')}
    assert 'secrets.' not in json.dumps(native)
    for job in w['jobs'].values():
        for step in job['steps']:
            if 'uses' in step:
                assert re.fullmatch(r'[^@]+@[0-9a-f]{40}', step['uses'])
    assert all(step['with']['persist-credentials'] == 'false'
               for job in w['jobs'].values() for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
    steps = publish['steps']
    names = [s.get('name') for s in steps]
    assert names.index('Validate both tested artifacts before login') < names.index('Login to Docker Hub')
    assert not re.search(r'\bdocker build\s', json.dumps(publish))
    assert ':latest' not in json.dumps(w)
    upload_index = next(i for i, s in enumerate(native['steps']) if s.get('uses', '').startswith('actions/upload-artifact@'))
    test_index = next(i for i, s in enumerate(native['steps']) if s.get('name') == 'Verify native deployment')
    assert upload_index > test_index


@pytest.mark.parametrize('failure', [None, 'missing-arm', 'wrong-revision'])
def test_actual_prelogin_script_validates_both_artifacts(tmp_path, failure):
    """Run the workflow's shell gate with fixture images, never a real registry."""
    w = workflow()
    step = next(s for s in w['jobs']['publish']['steps'] if s.get('name') == 'Validate both tested artifacts before login')
    for arch in ('amd64', 'arm64'):
        if failure == 'missing-arm' and arch == 'arm64':
            continue
        path = tmp_path / 'tested-images' / f'preview-{SHA}-{arch}'
        path.mkdir(parents=True)
        (path / 'image.tar').write_text('fixture archive')
    infos = {arch: image_info(arch) for arch in ('amd64', 'arm64')}
    if failure == 'wrong-revision':
        infos['arm64']['Config']['Labels']['org.opencontainers.image.revision'] = 'b' * 40
    (tmp_path / 'infos.json').write_text(json.dumps(infos))
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    docker = fake_bin / 'docker'
    docker.write_text('''#!/usr/bin/env python
import json, os, pathlib, sys
args=sys.argv[1:]
if args[0]=='load':
    sys.exit(0 if pathlib.Path(args[2]).is_file() else 2)
if args[:2]==['image','inspect']:
    arch=args[2].rsplit('-',1)[1]
    print(json.dumps([json.load(open(os.environ['FIXTURE_IMAGES']))[arch]]))
else:
    sys.exit('Unexpected Docker operation: '+repr(args))
''')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'],
               PREVIEW_SHA=SHA, GITHUB_REPOSITORY='dplush/mnemosyne', DOCKERHUB_USERNAME='ddplush',
               RUNNER_TEMP=str(tmp_path), GITHUB_ENV=str(tmp_path / 'github-env'), FIXTURE_IMAGES=str(tmp_path / 'infos.json'))
    result = subprocess.run(['bash', '-eo', 'pipefail', '-c', step['run']], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=15)
    assert (result.returncode == 0) == (failure is None), result.stdout + result.stderr
    if failure is None:
        assert 'PREVIEW_TAG=preview-sha-' + SHA in (tmp_path / 'github-env').read_text()


def test_verify_cli_rejects_multiple_images(tmp_path):
    file = tmp_path / 'inspect.json'
    file.write_text(json.dumps([image_info(), copy.deepcopy(image_info())]))
    result = subprocess.run([sys.executable, str(SCRIPT), 'verify', '--repository', preview.FORK,
                             '--sha', SHA, '--username', 'ddplush', '--architecture', 'amd64',
                             '--inspect-file', str(file)], capture_output=True, text=True)
    assert result.returncode != 0
    assert 'exactly one image' in result.stderr


@pytest.mark.parametrize('fail_arm', [False, True])
def test_actual_publish_script_assembles_only_after_both_pushes(tmp_path, fail_arm):
    """Fixture-only Docker records calls; no socket or registry is contacted."""
    step = next(s for s in workflow()['jobs']['publish']['steps']
                if s.get('name') == 'Push tested images and assemble preview manifest')
    fake_bin = tmp_path / 'bin'
    fake_bin.mkdir()
    docker = fake_bin / 'docker'
    docker.write_text('''#!/usr/bin/env python
import json, os, sys
args=sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f:
    f.write(json.dumps(args)+'\\n')
if args[0]=='push' and args[1].endswith('-arm64') and os.environ['FAIL_ARM']=='true':
    sys.exit(2)
if args[:2]==['image','inspect']:
    char='b' if args[2].endswith('-amd64') else 'c'
    print(json.dumps([{'RepoDigests':['ddplush/mnemosyne-mcp@sha256:'+char*64]}]))
''')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'],
               PREVIEW_SHA=SHA, PREVIEW_IMAGE='ddplush/mnemosyne-mcp', PREVIEW_TAG='preview-sha-' + SHA,
               GITHUB_REPOSITORY=preview.FORK, DOCKERHUB_USERNAME='ddplush', RUNNER_TEMP=str(tmp_path),
               GITHUB_STEP_SUMMARY=str(tmp_path / 'summary'), CALLS=str(tmp_path / 'calls.jsonl'),
               FAIL_ARM=str(fail_arm).lower())
    result = subprocess.run(['bash', '-eo', 'pipefail', '-c', step['run']], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=15)
    calls = [json.loads(line) for line in (tmp_path / 'calls.jsonl').read_text().splitlines()]
    creates = [call for call in calls if call[:3] == ['buildx', 'imagetools', 'create']]
    assert (result.returncode == 0) == (not fail_arm), result.stdout + result.stderr
    if fail_arm:
        assert not creates
    else:
        assert creates == [['buildx', 'imagetools', 'create', '-t',
                            'ddplush/mnemosyne-mcp:preview-sha-' + SHA,
                            'ddplush/mnemosyne-mcp@sha256:' + 'b' * 64,
                            'ddplush/mnemosyne-mcp@sha256:' + 'c' * 64]]
        assert [c for c in calls if c[0] == 'push'] == [
            ['push', 'ddplush/mnemosyne-mcp:preview-sha-' + SHA + '-amd64'],
            ['push', 'ddplush/mnemosyne-mcp:preview-sha-' + SHA + '-arm64']]
