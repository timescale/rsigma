# pySigma's TextQueryTestBackend, the reference for rsigma's `test` backend.
# Dependencies are pinned with hashes in requirements.txt, generated from
# requirements.in with:
#   uv pip compile --generate-hashes --python-version 3.13 requirements.in -o requirements.txt
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt
COPY convert.py /usr/local/bin/convert.py
ENTRYPOINT ["python", "/usr/local/bin/convert.py"]
