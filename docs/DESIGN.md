# sandbox-guestwatch design

## Purpose

sandbox-guestwatch is a small agent that records what happens inside an Amazon EKS Nitro Sandbox Pod, for verification and investigation. It runs as a sidecar container in the same Pod, and therefore in the same microVM and on the same guest kernel as the workload.

It exists because the usual runtime monitors do not work in this guest. Measured on guest kernel 6.18.56 (x86_64):

- No BTF. The eBPF program types `kprobe`, `tracepoint`, `raw_tracepoint`, `tracing` and `lsm` are not available, so Falco, Tetragon, Tracee and similar tools cannot start.
- The netlink audit interface is not available, so auditd and audit-based tables (osquery `process_events`) do not work.
- Node-level agents cannot see into the microVM at all.

What does work in the guest, and is therefore what this agent is built on:

| Signal | Kernel mechanism | Notes |
|---|---|---|
| Process fork, exec, exit | proc connector (`NETLINK_CONNECTOR`, `CN_IDX_PROC`) | Only delivered to sockets in the initial network namespace of the guest |
| Outbound connection attempts and UDP sends, with PID | eBPF `cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6` writing to a ring buffer | No BTF needed. The programs are built with the Go assembler, so no C toolchain is needed |
| File changes | inotify on directories inside each workload container | No PID attribution |

At startup the agent makes one exec and one UDP connect of its own and waits for each to come back through its source. `exec` and `net` are reported `ok` in `agent_start` only when that happened, so `ok` means events are delivered, not only that setup returned without error. `file` is `ok` once inotify is set up and is not probed; its health is in the heartbeat counters.

## Non-goals

- Prevention. Every eBPF program returns "allow".
- Tamper resistance. Root in the guest can stop the agent. The goal is to get events out of the VM quickly and to make silence visible (heartbeats), not to survive a compromised guest.
- Syscall-level tracing. The guest kernel does not offer it.
- A rule language, fleet management or a UI. Output is JSON lines on stdout, so whatever already collects container logs collects these.

Known blind spots, stated so that "no event" is not read as "did not happen". The list is what is known, not a guarantee that nothing else is missed.

- Network: inbound connections (bind, accept), raw sockets, `AF_PACKET`, `AF_UNIX`. Connect events are attempts, not results, and the destination is the address the process asked for (for a Service, the cluster IP before translation).
- Files: writes through `mmap` are invisible to inotify. Directories created and filled faster than the watch is added are covered by a rescan, but files created and deleted in between are lost. Read access is not recorded. Nothing outside the watched directories is seen. The first walk of a container reports nothing, so files written before the agent discovers it (up to one discovery interval after the container starts or restarts) are not reported. A directory shared by two containers is watched for the first one only, and loses its watch when that container goes away.
- Processes: a process that exits before the agent reads `/proc` produces an exec event with only what the kernel event carries plus what the agent remembers about its parent (`"partial": true`). The first exec of a container that starts while the agent runs can carry only the mount namespace, because it happens before the next discovery scan; it also triggers that scan.
- Processes of the sandbox runtime itself (for example the processes that start a `kubectl exec` session) have unreadable `/proc` entries; their exec events are counted as `exec.unattributed` and not written. The program the session runs inside a container is reported as usual.

## Deployment shape

One privileged sidecar container per sandbox Pod, with `hostPID: true` on the Pod. Inside a Nitro Sandbox, `hostPID` gives the guest PID namespace, not the node's, so the sidecar sees only processes in its own microVM. `privileged: true` is needed to `setns` into the guest network namespace, to attach cgroup programs at the cgroup root, and to open other containers' root directories.

## Packages

```
cmd/guestwatch      flags and signal handling only
internal/pipeline   attribution, network coalescing, rule tagging, startup probe, heartbeat, shutdown order
internal/config     the single place for default directory lists, limits and their validation
internal/event      Event type and schema version
internal/sink       bounded queue, rate limit, drop accounting, JSON writer
internal/procinfo   pid table (fork/exec/exit) and /proc readers shared by all sources
internal/discover   containers: mount namespace, root directory fd, cgroup; publishes add/remove
internal/procconn   proc connector transport
internal/netmon     cgroup sock_addr programs and ring buffer reader
internal/filewatch  inotify over directories inside each container
internal/rules      pure func(Event) []string
```

Sources (`procconn`, `netmon`, `filewatch`) only produce records. `procinfo` and `discover` own process and container identity. `pipeline` turns records into events. `sink` owns everything about output volume.

### Container identity

A container is identified by its mount namespace inode. `discover` excludes the agent's own mount namespace and the guest init's, and treats a namespace as a container only if its cgroup is under `--cgroup-prefix` (default `/kubepods`); the guest's own system services also run in private mount namespaces and are ignored. For each container it records:

- an anchor PID, and a directory fd opened on `/proc/<anchor>/root`, held for the life of the container so that PID reuse cannot redirect it;
- the cgroup v2 path from `/proc/<anchor>/cgroup`, and the cgroup id (inode of that directory under the cgroup root);
- a container id, when the last cgroup path segment contains a 64-hex runtime id.

`discover` rescans `/proc` periodically and also on demand when a source sees a PID in an unknown mount namespace, at most every 250 ms. On every scan it re-reads the cgroup of a live process in each known namespace, so a new container that reuses a namespace inode number is seen as a removal and an addition. It publishes `container_add` and `container_remove` events and notifies `filewatch`. A nested mount namespace inside a container (`unshare`, bubblewrap) shares the container's cgroup; the first namespace keeps the cgroup mapping.

Events carry the same `container` object. Network events are looked up by the cgroup id the kernel recorded, then by PID; exec events by PID (mount namespace). Exec and network records that match no container and no readable process are counted (`exec.unattributed`, `net.unattributed`) and not written.

### Process events

The proc connector socket must be created in the guest's initial network namespace. The agent locks an OS thread, `setns` into `/proc/1/ns/net`, creates and binds the socket, then `setns` back. If returning fails, the thread is never unlocked, so Go discards it. The receive buffer is raised with `SO_RCVBUFFORCE`; `ENOBUFS` is counted.

`fork` events fill the pid table: a child inherits its parent's identity and program until it execs (a parent that started before the agent is read from `/proc` once). `exec` events read `/proc/<pid>/{cmdline,exe,status}` and `ns/mnt`; command lines longer than `--max-cmdline` are truncated and marked. `exit` events remove the entry. Thread events (pid != tgid) are ignored. Only exec events are written; fork and exit are used internally. `EINTR` is retried.

### Network events

Four programs are attached at the cgroup v2 root through `bpf_link`. The agent verifies the cgroup root is a cgroup2 file system and that it is the root (inode 1) before attaching. Each program reserves a record in a ring buffer, fills `{time, cgroup id, pid, tid, uid, family, hook, protocol, socket type, port, address, comm}`, submits it and returns 1. A failed reservation increments a counter in an array map, which the heartbeat reports.

`sendmsg4/6` fire for each datagram on unconnected UDP, and retry loops repeat connects, so `pipeline` coalesces identical `(pid, hook, destination, port, protocol)` within a window (default 10 s). The first record of a window is attributed and written at once; when the window closes (on the next record for the same key or on a 1 s sweep), one more event with `repeat: true`, the repeat count and `window_start` is written. The number of open windows is capped; beyond the cap records pass through uncoalesced. IPv4-mapped IPv6 destinations are reported as IPv4.

### File events

For each container, each configured directory is resolved with `openat2(rootfd, path, RESOLVE_IN_ROOT)`, so an absolute symlink inside the image (`/bin -> usr/bin`, or one the workload created) resolves inside the container, never in the agent. Below it, every subdirectory is opened relative to its parent's fd with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, so the workload cannot redirect the walk by swapping a directory for a symlink, and depth is capped. Watches are added through `/proc/self/fd/<n>`, in the priority order of the configured list, up to a cap; when the same directory is reached twice, the first path keeps it. The mask is `CREATE | CLOSE_WRITE | MOVED_TO | MOVED_FROM | ATTRIB | DELETE`.

- A directory created or moved in later is watched when it appears and then scanned; its entries are reported as `create` with `"rescan": true`.
- A directory moved away loses its watches, so later events never carry its old path.
- On inotify queue overflow, every container is walked again so that directories created meanwhile get watches.
- Identical `(container, path, op)` within one second are coalesced.
- Watches are global to the inotify instance, so a directory shared by two containers (a volume) is reported for the container watched first, and the cap is shared.

### Rules

Rules only tag events (`"rules": [...]`) and never drop them. Directory lists come from `internal/config`; the configuration is rejected if a binary directory is not covered by the watch list.

| Rule | Fires when |
|---|---|
| `exec_from_temp_dir` | the executable is under a temp directory (`/tmp`, `/var/tmp`, `/dev/shm`) or is a memfd |
| `exec_deleted_binary` | the executable link already ends in ` (deleted)` when it is read right after the exec |
| `write_to_binary_dir` | a file is created, written, moved in or has attributes changed under a binary directory |
| `connect_outside_allowlist` | `--allow-cidr` is set and the destination is outside every listed range |

### Output and volume

JSON lines on stdout with a schema version (`"v": 1`). Events go to one of two bounded lanes without blocking; a full lane drops and counts. The priority lane carries `agent_start`, `agent_error`, `heartbeat`, container lifecycle events and every event a rule tagged; it is drained first and never rate limited. The normal lane is rate limited (default 300 events per second). The limit counts events, not bytes, and does not apply to the priority lane, so tagged events and long command lines can still exceed the per-Pod log bandwidth limit of Nitro Sandbox. Heartbeats carry per-signal status and all counters (emitted and dropped by type and reason, proc connector overruns, ring buffer drops, inotify overflows, watch cap hits, watch failures), so a collector can alert when the agent is silent or degraded. `--require` makes the agent exit with an error at startup if a listed signal is not `ok`.

## Testing

- Unit tests: proc connector message parsing, ring buffer record decoding, IPv4-mapped normalisation, that the eBPF programs assemble, coalescing including window rollover and the entry cap, rules, rate limiting and lanes, command line truncation, cgroup parsing.
- `test/e2e/run.sh` on a real EKS Nitro Sandbox `isolated-sandbox` Pod with an unprivileged and a root workload container. Each signal has to be observed for a workload container, not for the agent's own: a program copied to `/tmp` that exits at once, a TCP connect, a burst of 500 UDP datagrams, a directory created and filled in one command, an absolute symlink inside the image, an IPv4-mapped connect, a write to a binary directory, a directory moved into a binary directory, a command line longer than the limit, and a workload container restart.
