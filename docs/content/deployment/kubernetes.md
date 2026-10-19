# Kubernetes

Run the streaming daemon in a cluster from the published image: a single-replica Deployment with a persistent volume for correlation state, the rules and config from ConfigMaps, liveness and readiness probes on the daemon API, and a locked-down pod security context.

The manifests below go into one file (for example `rsigma.yaml`) and apply with `kubectl apply -f rsigma.yaml`. They assume a `rsigma` namespace:

```bash
kubectl create namespace rsigma
```

## Configuration

The daemon reads one config file, mounted from a ConfigMap. Inside a pod the API has to bind a routable address, so either serve TLS from the daemon or keep the traffic in-cluster and opt in to plaintext with `tls.allow_plaintext`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rsigma-config
  namespace: rsigma
data:
  config.yaml: |
    version: 1
    global:
      log_format: json
    daemon:
      rules: /etc/rsigma/rules
      api:
        addr: "0.0.0.0:9090"
        tls:
          allow_plaintext: true
      input:
        source: http
      output:
        sinks: [stdout]
        drain_timeout: 30
      state:
        db: /var/lib/rsigma/state.db
        save_interval: 30
```

Detections go to stdout and logs go to stderr, so a log collector that keeps the two streams apart can ship detections from the container log. For anything beyond a trial, send detections to NATS, OTLP, or a [webhook](../guide/webhooks.md) instead; see [output sinks](../cli/engine/daemon.md). With `source: http`, clients post events to the Service; swap in a `nats://` URL to consume from JetStream instead.

To serve TLS from the daemon, mount a certificate Secret (for example one issued by cert-manager) and set `tls.cert` and `tls.key` instead of `allow_plaintext`. See [TLS termination](../reference/security.md#tls-termination-for-the-api-listener).

## Rules

Small rule sets fit in a ConfigMap:

```bash
kubectl -n rsigma create configmap rsigma-rules --from-file=rules/
```

`--from-file` on a directory takes only the files at its top level, and a ConfigMap is capped at 1 MiB. For a larger or nested rule tree (the SigmaHQ corpus, for example), build a small image that layers your rules on top of the published one and drop the rules ConfigMap:

```dockerfile
FROM ghcr.io/timescale/rsigma:{{ rsigma.version }}
COPY rules/ /etc/rsigma/rules/
```

## API token

The pod binds a routable address, so the daemon refuses to start without [bearer-token authentication](../reference/security.md#daemon-api-authentication), client certificates, or an explicit `allow_unauthenticated: true`. {{ added "0.25.0" }} The token lives in a Secret and reaches the daemon as an environment variable:

```bash
kubectl -n rsigma create secret generic rsigma-api \
  --from-literal=token="$(openssl rand -hex 32)"
```

`/healthz` and `/readyz` stay open, so the probes below need no token. `/metrics` and every other route require one.

## State volume

`daemon.state.db` persists correlation, alert-pipeline, and risk state across restarts, so pod rescheduling and upgrades do not reset open correlation windows:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: rsigma-state
  namespace: rsigma
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
```

## Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rsigma
  namespace: rsigma
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: rsigma
  template:
    metadata:
      labels:
        app.kubernetes.io/name: rsigma
    spec:
      terminationGracePeriodSeconds: 45
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: rsigma
          image: ghcr.io/timescale/rsigma:{{ rsigma.version }}
          args:
            - engine
            - daemon
            - --config
            - /etc/rsigma/config.yaml
            - --api-token-env
            - RSIGMA_API_TOKEN
          env:
            - name: RSIGMA_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: rsigma-api
                  key: token
          ports:
            - name: api
              containerPort: 9090
          livenessProbe:
            httpGet:
              path: /healthz
              port: api
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: api
            periodSeconds: 5
            failureThreshold: 2
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              memory: 1Gi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          volumeMounts:
            - name: config
              mountPath: /etc/rsigma/config.yaml
              subPath: config.yaml
              readOnly: true
            - name: rules
              mountPath: /etc/rsigma/rules
              readOnly: true
            - name: state
              mountPath: /var/lib/rsigma
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: config
          configMap:
            name: rsigma-config
        - name: rules
          configMap:
            name: rsigma-rules
        - name: state
          persistentVolumeClaim:
            claimName: rsigma-state
        - name: tmp
          emptyDir:
            medium: Memory
            sizeLimit: 64Mi
---
apiVersion: v1
kind: Service
metadata:
  name: rsigma
  namespace: rsigma
spec:
  selector:
    app.kubernetes.io/name: rsigma
  ports:
    - name: api
      port: 9090
      targetPort: api
```

Notes on the choices:

- **One replica, `Recreate`.** Correlation state is per process and lives in one SQLite file on a `ReadWriteOnce` volume, so two pods must never run against it at once. `Recreate` stops the old pod before the new one starts.
- **Grace period above the drain timeout.** Kubernetes sends `SIGTERM`, the daemon drains in-flight events for up to `drain_timeout` seconds and writes the final state snapshot, and only then exits. `terminationGracePeriodSeconds` must be longer, or the kubelet kills the process before the snapshot lands.
- **Probes.** `/healthz` answers as soon as the listener is up. `/readyz` returns `503` until the rules are loaded and again after a failed reload, which takes the pod out of the Service without restarting it; the previous rules keep running. See the [endpoint summary](../reference/http-api.md#endpoint-summary).
- **Security context.** The image is `FROM scratch` and already runs as uid `65534`; the pod spec enforces it, drops every capability, and makes the root filesystem read-only. `fsGroup` makes the state volume writable. The image passes the Kubernetes "restricted" Pod Security Standard with this spec.
- **Pin the image.** Use a version tag or digest rather than `latest`, and verify the cosign signature as described in [Docker](docker.md#verify-the-signature).

The container has no shell, so `kubectl exec` works only for the `rsigma` binary itself. `kubectl debug` with an ephemeral container gives you a shell in the pod's namespaces when you need one.

## Reloading rules

Kubernetes updates a mounted ConfigMap by swapping a hidden `..data` symlink rather than rewriting the rule files in place, so do not rely on the daemon's file watcher to notice. Trigger the reload explicitly once the kubelet has synced the new ConfigMap (up to a minute or so):

```bash
kubectl -n rsigma port-forward deploy/rsigma 9090:9090 &
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9090/api/v1/reload
```

The reload endpoint requires the `reload:execute` permission; the single `--api-token-env` token has full `admin` permissions. Reloading also re-reads TLS material, so the same call picks up a rotated certificate Secret.

The config file is mounted with `subPath`, and `subPath` mounts never receive ConfigMap updates, so config changes need a restart. A restart is also the way to roll out a new rules image, and correlation state survives it:

```bash
kubectl -n rsigma rollout restart deploy/rsigma
```

Kustomize's `configMapGenerator` automates the restart: it appends a content hash to the ConfigMap name, so every rules change produces a new name, a new pod template, and a rollout.

## Metrics

`/metrics` sits on the same port and requires the `metrics:read` permission once authentication is on. Rather than hand Prometheus the admin token, replace `--api-token-env` with a `daemon.api.auth` block (the two are mutually exclusive) that defines a second, read-only token:

```yaml
daemon:
  api:
    auth:
      tokens:
        - name: admin
          role: admin
          token_env: RSIGMA_API_TOKEN
        - name: prometheus
          role: reader
          token_env: RSIGMA_METRICS_TOKEN
```

Drop `--api-token-env` from the container args, add `RSIGMA_METRICS_TOKEN` to `env` from a second Secret key, and set the same value as the scrape job's bearer token. The `reader` role can read metrics and status but gets `403` on writes such as reload. The [Observability](../guide/observability.md) guide lists the metrics worth alerting on, and [Prometheus Metrics](../reference/metrics.md) has the full catalog.

## Scaling out

A single daemon handles most workloads; [Performance Tuning](../guide/performance-tuning.md) covers the knobs to try first. To spread load across pods, consume from NATS JetStream with a [consumer group](../guide/nats-streaming.md#consumer-groups): every replica with the same `--consumer-group` (or `RSIGMA_CONSUMER_GROUP`) shares one durable consumer, and NATS balances messages across them.

Each replica keeps its own correlation state, and it is not partitioned by the consumer group. Use a StatefulSet with a `volumeClaimTemplates` entry so each replica gets its own state volume, and make sure events that must correlate reach the same replica, either by partitioning subjects upstream on the `group_by` key or by leaving correlation rules on a single replica.

## See also

- [Docker](docker.md) for the image, its hardening flags, and signature verification.
- [systemd](systemd.md) for running the binary directly on a host.
- [`engine daemon`](../cli/engine/daemon.md) for every flag and its config key.
- [Security Hardening](../reference/security.md) for TLS, authentication, and the supply-chain controls.
- [NATS Streaming](../guide/nats-streaming.md) for JetStream input, replay, consumer groups, and the dead-letter queue.
