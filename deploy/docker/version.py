"""Resolve upstream releases and assemble an isolated source-build context."""
import argparse
import ast
import json
from pathlib import Path
import re
import shutil
import subprocess

UPSTREAM = 'https://github.com/mnemosyne-oss/mnemosyne.git'
SOURCE_PATHS = ('pyproject.toml', 'setup.py', 'README.md', 'LICENSE', 'MANIFEST.in',
                'mnemosyne', 'hermes_memory_provider')


def release_version(tag):
    if not re.fullmatch(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', tag):
        raise ValueError('Expected a stable version tag such as v4.0.0')
    return tag[1:]


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True, timeout=120).strip()


def package_version(source):
    tree = ast.parse((source / 'mnemosyne/__init__.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__version__' for t in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise ValueError('Missing literal package version')


def fetch(ref, destination, remote=UPSTREAM):
    destination.mkdir(parents=True, exist_ok=False)
    git(destination, 'init', '-q')
    git(destination, 'fetch', '--depth=1', '--no-tags', remote, ref)
    sha = git(destination, 'rev-parse', 'FETCH_HEAD^{commit}')
    git(destination, 'checkout', '--detach', '-q', sha)
    return sha


def resolve(tag, destination, remote=UPSTREAM):
    version = release_version(tag)
    sha = fetch('refs/tags/' + tag, destination, remote)
    if package_version(destination) != version:
        raise ValueError('Tag and package version differ')
    return {'sha': sha, 'version': version}


def prepare(source, recipe, context, sha, version):
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or git(source, 'rev-parse', 'HEAD') != sha:
        raise ValueError('Unexpected source commit')
    if git(source, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Source checkout must be clean')
    if package_version(source) != version:
        raise ValueError('Unexpected package version')
    context.mkdir(parents=True, exist_ok=False)
    for name in SOURCE_PATHS:
        path = source / name
        if path.is_dir():
            shutil.copytree(path, context / name)
        else:
            shutil.copyfile(path, context / name)
    for name in ('Dockerfile', '.dockerignore'):
        shutil.copyfile(recipe / name, context / name)
    target = context / 'deploy/docker'
    target.mkdir(parents=True)
    for name in ('requirements.lock', 'healthcheck.py', 'readiness.py'):
        shutil.copyfile(recipe / 'deploy/docker' / name, target / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['resolve', 'prepare'])
    parser.add_argument('--tag', default='')
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--sha', default='')
    parser.add_argument('--version', default='')
    parser.add_argument('--recipe', type=Path)
    parser.add_argument('--context', type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'resolve':
            print(json.dumps(resolve(args.tag, args.checkout)))
        else:
            if not re.fullmatch(r'[0-9a-f]{40}', args.sha):
                raise ValueError('Expected full source commit')
            fetch(args.sha, args.checkout)
            prepare(args.checkout, args.recipe, args.context, args.sha, args.version)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
