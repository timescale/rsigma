# pySigma's TextQueryTestBackend, the reference for rsigma's `test` backend.
# Dependencies are pinned with hashes in requirements.txt, generated from
# requirements.in with:
#   uv pip compile --generate-hashes --python-version 3.13 requirements.in -o requirements.txt
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt
COPY convert.py /usr/local/bin/convert.py
ENTRYPOINT ["python", "/usr/local/bin/convert.py"]
