"""Tagged images must build the exact release with a separate trusted recipe."""
import importlib.util
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def helper():
    spec = importlib.util.spec_from_file_location('docker_version', ROOT / 'deploy/docker/version.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


@pytest.fixture
def upstream(tmp_path):
    git(tmp_path, 'init', '-q')
    git(tmp_path, 'config', 'user.name', 'Fixture')
    git(tmp_path, 'config', 'user.email', 'fixture@example.invalid')
    for file in ('pyproject.toml', 'setup.py', 'README.md', 'LICENSE', 'MANIFEST.in'):
        (tmp_path / file).write_text('# fixture\n')
    for package in ('mnemosyne', 'hermes_memory_provider'):
        (tmp_path / package).mkdir()
        (tmp_path / package / '__init__.py').write_text('__version__ = "4.0.0"\n')
    (tmp_path / 'Dockerfile').write_text('DO NOT USE OLD DOCKERFILE\n')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-qm', 'tagged source')
    git(tmp_path, 'tag', 'v4.0.0')
    git(tmp_path, 'tag', '-a', 'v4.0.1', '-m', 'mismatched annotated version')
    return tmp_path


def test_release_resolution_and_isolated_context(upstream, tmp_path):
    mod = helper()
    source = tmp_path / 'checkout'
    meta = mod.resolve('v4.0.0', source, remote=str(upstream))
    assert meta['sha'] == git(upstream, 'rev-parse', 'v4.0.0^{commit}')
    assert meta['version'] == '4.0.0'
    context = tmp_path / 'context'
    mod.prepare(source, ROOT, context, meta['sha'], '4.0.0')
    assert (context / 'mnemosyne/__init__.py').read_bytes() == (upstream / 'mnemosyne/__init__.py').read_bytes()
    assert (context / 'Dockerfile').read_bytes() == (ROOT / 'Dockerfile').read_bytes()
    assert (context / 'deploy/docker/requirements.lock').is_file()
    assert not (context / '.git').exists()
    assert not (context / 'tests').exists()


def test_annotated_tag_resolves_to_commit(upstream, tmp_path):
    git(upstream, 'tag', '-a', 'v4.0.0-rc.1', '-m', 'annotation')
    # Its package still reports 4.0.0: a pre-release name must not disguise it.
    with pytest.raises(ValueError, match='version'):
        helper().resolve('v4.0.0-rc.1', tmp_path / 'checkout', remote=str(upstream))
    git(upstream, 'tag', '-d', 'v4.0.0')
    git(upstream, 'tag', '-a', 'v4.0.0', '-m', 'release')
    meta = helper().resolve('v4.0.0', tmp_path / 'annotated', remote=str(upstream))
    assert meta['sha'] == git(upstream, 'rev-parse', 'HEAD')


@pytest.mark.parametrize('tag', ['main', 'v4', 'v4.0.0\n', '--upload-pack=bad', 'v4.0.0;echo bad', 'v4.0.0/../../main'])
def test_invalid_release_ref_rejected_before_network(tmp_path, tag):
    with pytest.raises(ValueError):
        helper().resolve(tag, tmp_path / 'checkout', remote='must-not-be-contacted')


def test_package_version_mismatch_is_rejected(upstream, tmp_path):
    with pytest.raises(ValueError, match='version'):
        helper().resolve('v4.0.1', tmp_path / 'checkout', remote=str(upstream))


def test_prepare_rejects_wrong_commit(upstream, tmp_path):
    with pytest.raises(ValueError, match='commit'):
        helper().prepare(upstream, ROOT, tmp_path / 'context', '0' * 40, '4.0.0')
