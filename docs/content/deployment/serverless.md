---
description: "Run RSigma correlations in AWS Lambda or a scheduled container job: one stdin batch run per invocation, with state carried in one SQLite file."
---

# Serverless

{{ added "0.28.0" }}

Run detection and correlation as one short-lived process per batch instead of a long-running daemon. Each invocation runs `engine daemon --input stdin` as a [batch run](../cli/engine/daemon.md#batch-runs): it restores correlation state from a single SQLite file, evaluates the batch, saves the state, and exits with a code that says whether to keep it. A correlation window that spans batches fires in the invocation that completes it.

Batches that need no correlation state can use [`engine eval`](../cli/engine/eval.md) instead, which has no state to carry and scales out freely.

## How a run works

Every invocation follows the same four steps:

1. Restore the last good state file into a fresh, writable path, or start with no file on the first run.
2. Pipe the batch into `rsigma engine daemon -r <rules> --input stdin --state-db <path> --api-addr 127.0.0.1:0 --timestamp-fallback skip`.
3. On exit `0`, store the new state file as the last good state.
4. On any other exit, keep the previous state and fail the invocation so the platform retries the batch.

`--api-addr 127.0.0.1:0` binds an ephemeral loopback port, so the API needs no authentication and concurrent runs on one host never clash. `--timestamp-fallback skip` keeps events without a timestamp out of correlation windows; otherwise they would all land at the time the batch happened to run. Findings go to stdout by default, and the daemon's JSON logs go to stderr.

After a clean exit the state file has no `-wal` or `-shm` sidecar, so it can be stored as one object. Exit `4` means the run did not complete cleanly and the batch should be replayed. Exits `2` and `3` mean the run did not start, because the rules or the configuration are broken or the stored state cannot be restored, so a retry fails the same way until someone fixes it. See [Batch runs](../cli/engine/daemon.md#batch-runs) for the full contract.

## One run per state file

A run reads the stored state at startup and writes the whole file at exit, so two runs that share a state file overwrite each other's windows. Keep exactly one run in flight per state file:

- Partition the input by the correlation's `group-by` value, so every event for a given user or host reaches the same partition, and keep one state file per partition.
- Process each partition in order, one batch at a time. A retried batch must finish before the next one starts.
- If two runs can still overlap, guard the upload with a conditional write (an ETag or generation precondition on the stored object), so a stale run cannot replace newer state.

## AWS Lambda with Kinesis

A Kinesis event source mapping invokes the function once per shard at a time, in order, when the parallelization factor is `1` (the default). A function error retries the same batch and holds the shard until it succeeds, which matches the replay rule above. Keep one state object per shard.

Package the function as a container image, copying the static `rsigma` binary out of the published image:

```dockerfile
FROM public.ecr.aws/lambda/python:3.13
COPY --from=ghcr.io/timescale/rsigma:{{ rsigma.version }} /rsigma /usr/local/bin/rsigma
COPY rules/ /opt/rules/
COPY handler.py ${LAMBDA_TASK_ROOT}/
CMD ["handler.handler"]
```

Build it for the function's architecture (`linux/amd64` or `linux/arm64`). A [`ruleset build`](../cli/ruleset/build.md) output directory works as `rules/` when you curate rules with rulesets.

The handler restores the shard's state from S3, runs the batch, and stores the state only on success:

```python
import base64
import os
import subprocess

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
BUCKET = os.environ["STATE_BUCKET"]
STATE = "/tmp/state.db"


def handler(event, context):
    records = event["Records"]
    shard = records[0]["eventID"].split(":")[0]
    key = f"rsigma/{shard}/state.db"
    batch = b"".join(
        base64.b64decode(r["kinesis"]["data"]).rstrip(b"\n") + b"\n" for r in records
    )

    # /tmp survives between warm invocations, so clear the previous run's files.
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(STATE + suffix)
        except FileNotFoundError:
            pass
    try:
        s3.download_file(BUCKET, key, STATE)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("404", "NoSuchKey"):
            raise

    run = subprocess.run(
        [
            "/usr/local/bin/rsigma", "engine", "daemon",
            "-r", "/opt/rules",
            "--input", "stdin",
            "--state-db", STATE,
            "--api-addr", "127.0.0.1:0",
            "--timestamp-fallback", "skip",
        ],
        input=batch,
        capture_output=True,
    )
    if run.returncode != 0:
        print(run.stderr.decode(errors="replace"))
        raise RuntimeError(f"rsigma exited {run.returncode}")

    s3.upload_file(STATE, BUCKET, key)
    return {"findings": run.stdout.decode().splitlines()}
```

Only a missing object starts fresh. Any other download error fails the invocation, so a transient S3 error cannot replace good state with an empty one.

Some notes on the function settings:

- The run exits before the handler returns, so nothing is left running for Lambda to freeze between invocations.
- Set the function timeout well above the longest batch, including sink retries. A timed-out invocation is killed before the upload, so the stored state stays at the previous batch.
- Exit `2` or `3` retries until the records expire, holding the shard. Set a maximum retry count and an on-failure destination on the event source mapping, and alert on them.
- Grant the function `s3:GetObject` and `s3:PutObject` on the state prefix only.

## Scheduled container jobs

For cron-style batches, such as hourly files or an archive replayed in chunks, run a small wrapper in a container job. The published image has no shell, so copy the binary into a minimal base:

```dockerfile
FROM alpine:3.21
COPY --from=ghcr.io/timescale/rsigma:{{ rsigma.version }} /rsigma /usr/local/bin/rsigma
COPY rules/ /rules/
COPY run-batch.sh /usr/local/bin/run-batch
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/run-batch"]
```

The wrapper reads the batch on stdin and keeps the last good state in a directory that outlives the job, such as a mounted volume:

```sh
#!/bin/sh
# Usage: run-batch <state-dir> < batch.ndjson
set -u
state_dir=$1
work=$(mktemp -d)
if [ -f "$state_dir/last-good.db" ]; then
  cp "$state_dir/last-good.db" "$work/state.db" || exit 1
fi
rsigma engine daemon -r /rules --input stdin --state-db "$work/state.db" --api-addr 127.0.0.1:0 --timestamp-fallback skip
code=$?
if [ "$code" -eq 0 ]; then
  if ! { cp "$work/state.db" "$state_dir/last-good.db.tmp" && mv "$state_dir/last-good.db.tmp" "$state_dir/last-good.db"; }; then
    code=1
  fi
fi
rm -rf "$work"
exit "$code"
```

The fresh work directory keeps a failed run's files, or a sidecar left by a killed process, out of the next run, and the rename replaces the stored state in one step. Treat any non-zero exit from the wrapper as a failed batch.

Keep one job in flight per state directory:

- Kubernetes CronJob: set `concurrencyPolicy: Forbid` and mount the state directory from a PersistentVolumeClaim.
- Cloud Run jobs or ECS scheduled tasks: run one task per state directory at a time.
- Plain cron: wrap the call in `flock -n /var/lock/rsigma.lock run-batch /var/lib/rsigma < batch.ndjson`.

## Delivery and replays

A replayed batch evaluates the same events again, so findings that a failed run already delivered to a sink such as NATS, OTLP, or a webhook can arrive twice. Deduplicate downstream, or collect the findings from stdout and forward them only after a clean exit, as the Lambda handler above does.

Output that reached neither its sink nor the [dead-letter queue](../cli/engine/daemon.md#batch-runs) fails the run with exit `4`, so a batch never reports success while findings were lost. With `--dlq` set, a delivery that keeps failing is parked there and the run still exits `0`.

## See also

- [`engine daemon` batch runs](../cli/engine/daemon.md#batch-runs) for the exit-code contract and the state file.
- [Exit codes](../reference/exit-codes.md) for every command's codes.
- [Docker](docker.md) for the published image and how to verify its signature.
- [Kubernetes](kubernetes.md) and [systemd](systemd.md) for long-running deployments.
- [Streaming Detection](../guide/streaming-detection.md) for the long-running daemon.
