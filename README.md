# sandbox-guestwatch

A small agent that records process, network and file activity inside an [Amazon EKS Nitro Sandbox](https://docs.aws.amazon.com/eks/latest/userguide/sandboxing.html) Pod, for verification and investigation. It runs as a sidecar in the same Pod, so it sees the workload from inside the Pod's own microVM, and writes one JSON line per event to stdout.

This is not an AWS project. It is a lightweight tool for trying out what can be observed inside a sandbox; it is not a security product and does not prevent anything.

## Why it exists

A Nitro Sandbox Pod runs on its own guest kernel. Node-level agents cannot see into it, and on the guest kernel (6.18, measured) the eBPF program types `kprobe`, `tracepoint`, `raw_tracepoint`, `tracing` and `lsm` are not available, there is no BTF, and the netlink audit interface is not available. Falco, Tetragon, Tracee, auditd and similar tools therefore cannot start inside the sandbox.

sandbox-guestwatch uses only what the guest kernel does provide:

| Signal | Mechanism |
|---|---|
| Process exec, with the command line (truncated at `--max-cmdline`) | proc connector |
| Outbound connections and UDP sends, with PID, UID and command name | eBPF `cgroup/connect4`, `connect6`, `sendmsg4`, `sendmsg6` (no BTF, no C toolchain) |
| File creates, writes, moves, attribute changes and deletes | inotify on directories inside each container |

## What it does not do

- It never blocks anything. Every eBPF program returns "allow".
- It does not survive a compromised guest. It shares the microVM with the workload, so root in the guest can stop it. Heartbeats make silence visible; ship the logs out of the Pod promptly.
- It does not see inbound connections, raw sockets, `AF_PACKET`, `AF_UNIX`, writes through `mmap`, read access to files, or files outside the watched directories.
- File events carry no process. A file written in the first seconds of a container, before the agent discovers it, is not reported.
- A connect event is an attempt, not a result. For a Service, the destination is the cluster IP before translation.

See [docs/DESIGN.md](docs/DESIGN.md) for the design and the blind spots it knows of.

## Requirements

- An EKS cluster with Nitro Sandbox support and a node that can run the `isolated-sandbox` (or `confidential-sandbox`) RuntimeClass.
- The sidecar must be `privileged: true` and the Pod must set `hostPID: true`. Inside a Nitro Sandbox, `hostPID` is the PID namespace of the Pod's own microVM, not the node's.
- Tested on x86_64 nodes. The image is also built for arm64; arm64 has not been tested on real hardware yet.

## Build

With Docker:

```bash
export IMAGE=registry.example.com/sandbox-guestwatch:dev
docker buildx build --platform linux/amd64,linux/arm64 -t "$IMAGE" --push .
```

Or the binary only (Go 1.26):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o guestwatch ./cmd/guestwatch
```

## Run

[deploy/example-pod.yaml](deploy/example-pod.yaml) is a sandbox Pod with the agent as a sidecar and an example workload. Replace the workload with your own containers.

```bash
export GUESTWATCH_IMAGE="$IMAGE"
envsubst < deploy/example-pod.yaml | kubectl apply -f -
kubectl wait --for=condition=Ready pod/guestwatch-example --timeout=300s
kubectl logs -f guestwatch-example -c guestwatch
```

`agent_start` is written when startup checks finish; `container_add`, `agent_error` and the first workload events can come before it. It reports each signal as `ok`, `off`, `failed: <reason>`, or `set up, but the startup probe saw no event`:

- `exec` and `net` are `ok` only after the agent has seen one event of its own through them (an exec and a UDP connect it makes at startup).
- `file` is `ok` once inotify is set up; it is not probed. Watch `file.watches`, `file.add_failures` and `file.watch_cap_hits` in the heartbeat, which reports `capped` when the watch cap is hit.

`--require=exec,net,file` makes the agent exit if any of them is not `ok`.

## Output

One JSON object per line, with `"v": 1`. Example (shortened):

```json
{"v":1,"type":"exec","container":{"id":"e4964251…","mntns":4026532721},"process":{"pid":1902,"ppid":1879,"uid":1000,"exe":"/tmp/fastcurl","cmdline":["/tmp/fastcurl","--version"]},"rules":["exec_from_temp_dir"]}
{"v":1,"type":"connect","container":{"id":"e4964251…"},"process":{"pid":1904,"uid":1000,"comm":"curl","exe":"/usr/bin/curl"},"net":{"proto":"tcp","family":4,"dst":"93.184.216.34","port":80,"count":1},"rules":["connect_outside_allowlist"]}
{"v":1,"type":"connect","container":{"id":"e4964251…"},"process":{"pid":1884,"comm":"bash"},"net":{"proto":"udp","family":4,"dst":"192.0.2.20","port":9999,"count":499,"repeat":true,"window_start":"…"}}
{"v":1,"type":"file","container":{"id":"de48706c…"},"file":{"path":"/usr/local/bin/evil","op":"create"},"rules":["write_to_binary_dir"]}
```

| Type | Meaning |
|---|---|
| `exec` | A process in a workload container started a program. `partial: true` means the process was gone before it could be read: container, parent and UID come from its parent, and there is no `exe` or `cmdline`. |
| `connect` | `connect()` on a TCP or UDP socket. |
| `send` | A datagram sent on an unconnected UDP socket. |
| `file` | `op` is `create`, `write`, `moved_to`, `moved_from`, `attrib` or `delete`. `write` means a file opened for writing was closed. There is no process. Identical events for the same path within `--file-coalesce` (1 s) are written once. `rescan: true` means the entry was found when a new directory was first scanned. |
| `container_add`, `container_remove` | A workload container appeared or went away. `container.id` is the runtime id from the cgroup path, the same as `kubectl get pod POD -o jsonpath='{.status.containerStatuses[*].containerID}'` without the `containerd://` prefix; it is absent if the cgroup path has none. |
| `heartbeat` | Every 30 s: the state of each signal and every counter, including events dropped and why. |
| `agent_start`, `agent_error` | Startup report and runtime failures. |

Identical connect and send records from the same process to the same destination are collapsed for 10 s: the first one is written at once with `count: 1`, and when the window closes, one more line with `repeat: true` gives the number of repeats.

### Rules

Rules add a name to `rules` and never drop an event. Tagged events are never rate limited, but like any event they are dropped (and counted) if their queue is full.

| Rule | Fires when |
|---|---|
| `exec_from_temp_dir` | The executable is under `/tmp`, `/var/tmp` or `/dev/shm`, or is a memfd. |
| `exec_deleted_binary` | The executable was already deleted when the agent read it, right after the exec. Every memfd exec gets this too. Deletion later, while the process runs, is not detected. |
| `write_to_binary_dir` | A file is created, written, moved in or changed under `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin` or `/bin`. |
| `connect_outside_allowlist` | `--allow-cidr` is set and the destination is outside every listed range. |

The exec rules look at the executable only. A script run by an interpreter (`sh /tmp/x.sh`, `python3 /tmp/x.py`) has the interpreter as its executable and is not tagged, and a `partial` exec has no executable to look at.

## Flags

| Flag | Default | |
|---|---|---|
| `--watch` | binary dirs, temp dirs, `/etc`, `/root`, `/home` | Directories to watch in every container, in priority order. |
| `--binary-dirs`, `--temp-dirs` | as in the table above | Directories used by the rules. Every binary directory must be covered by `--watch`, or the agent refuses to start. |
| `--allow-cidr` | none | Ranges for `connect_outside_allowlist`. |
| `--require` | none | Signals (`exec`, `net`, `file`) that must be `ok` at startup. |
| `--rate` | 300 | Untagged events per second written; the rest are counted and dropped. It counts events, not bytes. |
| `--heartbeat` | 30s | Heartbeat interval. |
| `--net-coalesce` | 10s | Window for collapsing identical network records. |
| `--max-watches` | 8192 | Total inotify watches. |
| `--max-cmdline` | 4096 | Longer command lines are truncated and marked `truncated`. |
| `--cgroup-prefix` | `/kubepods` | Only mount namespaces whose cgroup is under this are treated as containers; the guest's own system services are ignored. |

Run `guestwatch --help` for the rest.

## Test

Unit tests run on Linux:

```bash
go test ./...
```

[test/e2e/run.sh](test/e2e/run.sh) runs the agent in a real Nitro Sandbox Pod, generates activity in an unprivileged and a root workload container, restarts one of them, and checks the events with [test/e2e/check.py](test/e2e/check.py):

```bash
export GUESTWATCH_IMAGE="$IMAGE"
export NAMESPACE=default
./test/e2e/run.sh
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
