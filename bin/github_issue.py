#!/usr/bin/env python3
"""Trusted workflow_run notifier; never executes or downloads PR artifacts."""
import argparse
import importlib.util
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', required=True)
    parser.add_argument('--run-url', required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('protect', Path(__file__).with_name('github_protect.py'))
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    repo = client.repository(args.repository)
    title = 'agent-gates: main is unverified'
    pages = client.api(repo, 'GET', '/issues?state=open&per_page=100', pages=True)
    matches = [issue for page in pages for issue in page
               if issue.get('title') == title and 'pull_request' not in issue]
    body = 'agent-gates/verify failed. Review the check summary and receipt artifact.\n\nRun: ' + args.run_url
    if matches:
        client.api(repo, 'PATCH', '/issues/' + str(min(i['number'] for i in matches)), {'body': body})
    else:
        client.api(repo, 'POST', '/issues', {'title': title, 'body': body})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
