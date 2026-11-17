"""Validate fork preview metadata and tested images without registry access."""
import argparse
import json
from pathlib import Path
import re

FORK = 'dplush/mnemosyne'


def metadata(repository, sha, username):
    if repository != FORK:
        raise ValueError('Preview builds are restricted to ' + FORK)
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Expected a full lowercase Git commit SHA')
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', username):
        raise ValueError('Expected a Docker Hub username, without a registry or path')
    return {'image': username + '/mnemosyne-mcp', 'tag': 'preview-sha-' + sha,
            'sha': sha, 'source': 'https://github.com/' + repository}


def verify_image(info, expected, architecture):
    if architecture not in ('amd64', 'arm64'):
        raise ValueError('Unsupported architecture')
    labels = info.get('Config', {}).get('Labels') or {}
    if (info.get('Os'), info.get('Architecture')) != ('linux', architecture):
        raise ValueError('Image platform does not match its native test job')
    if labels.get('org.opencontainers.image.revision') != expected['sha']:
        raise ValueError('Image revision does not match the dispatched source')
    if labels.get('org.opencontainers.image.source') != expected['source']:
        raise ValueError('Image source does not match the fork')


def pushed_digest(info, image):
    matches = [value for value in info.get('RepoDigests', [])
               if re.fullmatch(r'(?:docker.io/)?' + re.escape(image) + r'@sha256:[0-9a-f]{64}', value)]
    if len(matches) != 1:
        raise ValueError('Expected exactly one pushed digest for the preview repository')
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['metadata', 'verify', 'digest'])
    parser.add_argument('--repository', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--username', required=True)
    parser.add_argument('--architecture')
    parser.add_argument('--inspect-file', type=Path)
    args = parser.parse_args()
    try:
        expected = metadata(args.repository, args.sha, args.username)
        if args.operation == 'metadata':
            print(json.dumps(expected))
        else:
            values = json.loads(args.inspect_file.read_text()) if args.inspect_file else []
            if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
                raise ValueError('Expected docker inspect output for exactly one image')
            if args.operation == 'verify':
                verify_image(values[0], expected, args.architecture)
            else:
                print(pushed_digest(values[0], expected['image']))
    except (ValueError, OSError, TypeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
