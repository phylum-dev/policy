"""
Script to upload a set of policy files to Phylum.
"""

import io
import json
import os
from pathlib import Path
import shutil
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
import uuid

# Set the group name if you are uploading policies for a group.
GROUP_NAME = None
token = os.environ["PHYLUM_TOKEN"]
version = os.environ.get("GITHUB_SHA", None)
BASE_ADDRESS = "https://api.phylum.io/api/"

# Build a multipart form body.
boundary = uuid.uuid4().hex
body = io.BytesIO()

for file in Path.cwd().glob("*.rego"):
    body.write(f"--{boundary}\r\n".encode("ascii"))
    body.write(
        f'Content-Disposition: form-data; name="{file.stem}"; filename="{file.name}"\r\n'.encode(
            "ascii"
        )
    )
    body.write(b"Content-Type: text/plain\r\n\r\n")

    with file.open("rb") as f:
        shutil.copyfileobj(f, body)

    body.write(b"\r\n")

body.write(f"--{boundary}--".encode("ascii"))

# Send the request.
if GROUP_NAME is None:
    endpoint = f"{BASE_ADDRESS}v0/available-policies"
else:
    endpoint = (
        f"{BASE_ADDRESS}v0/groups/{quote(GROUP_NAME, safe='')}/available-policies"
    )

if version is not None:
    endpoint = f"{endpoint}?version={quote(version, safe='')}"

request = Request(
    endpoint,
    data=body.getbuffer(),
    headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": f'multipart/form-data;boundary="{boundary}"',
    },
    method="PUT",
)

try:
    with urlopen(request) as f:
        pass
except HTTPError as error:
    response = error.read().decode("utf8", errors="replace")
    try:
        # Phylum's API returns JSON error descriptions.
        # If that's what we got, reformat it to be more readable.
        response = json.dumps(json.loads(response), indent=2)
    except json.JSONDecodeError:
        pass
    print(response)
    exit(1)
