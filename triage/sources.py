"""Read-only inputs. The AWS dependency is optional for the local demo."""

import json
from pathlib import Path


def read_file(path):
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = payload.get("Findings") if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        raise ValueError("input must be an ASFF array or an object containing Findings")
    return findings


def read_owners(path):
    if path is None:
        return {}
    owners = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(owners, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) or not v.strip()
        for k, v in owners.items()
    ):
        raise ValueError("owners file must map account IDs to nonempty team names")
    return owners


def aws_findings(region, profile=None, client=None):
    if client is None:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise ValueError("AWS mode requires: python3 -m pip install -r requirements-aws.txt") from exc
        session = boto3.Session(profile_name=profile, region_name=region)
        client = session.client("securityhub", config=Config(
            retries={"mode": "standard", "total_max_attempts": 5},
            connect_timeout=10, read_timeout=30,
        ))
    # Include resolved/archived findings so the local database learns about closures.
    paginator = client.get_paginator("get_findings")
    for page in paginator.paginate(PaginationConfig={"PageSize": 100}):
        for finding in page["Findings"]:
            yield finding
