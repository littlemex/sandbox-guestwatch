#!/usr/bin/env python3
"""Checks the events written during run.sh. Prints one line per check."""
import json
import sys


def load_ids(path):
    return dict(line.strip().split("=", 1) for line in open(path) if "=" in line)


events = [json.loads(line) for line in open(sys.argv[1]) if line.startswith("{")]
before, after = load_ids(sys.argv[2]), load_ids(sys.argv[3])
wl, root, wl2 = before["workload"], before["workload-root"], after["workload"]
failed = 0


def cid(e):
    return (e.get("container") or {}).get("id")


def find(pred):
    return [e for e in events if pred(e)]


def check(name, ok, detail=""):
    global failed
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail and not ok else ""))
    failed += 0 if ok else 1


start = find(lambda e: e["type"] == "agent_start")
check("agent_start reports exec, net and file ok", bool(start) and start[0]["signals"] == {"exec": "ok", "net": "ok", "file": "ok"}, start)
check("no agent_error", not find(lambda e: e["type"] == "agent_error"), find(lambda e: e["type"] == "agent_error"))
check("heartbeats are written", len(find(lambda e: e["type"] == "heartbeat")) >= 2)

ex = find(lambda e: e["type"] == "exec" and e["process"].get("exe") == "/tmp/fastcurl")
check("short-lived exec from /tmp is attributed and tagged", ex and cid(ex[0]) == wl and "exec_from_temp_dir" in ex[0].get("rules", []) and ex[0]["process"]["uid"] == 1000, ex)

cu = find(lambda e: e["type"] == "connect" and e["process"]["comm"] == "curl" and e["net"]["proto"] == "tcp" and e["net"]["port"] == 80 and cid(e) == wl)
check("TCP connect has pid, comm and container", bool(cu) and cu[0]["process"]["pid"] > 0)

udp = find(lambda e: e["net"]["dst"] == "192.0.2.20" and e["net"]["port"] == 9999 if e.get("net") else False)
first = [e for e in udp if not e["net"].get("repeat")]
rep = [e for e in udp if e["net"].get("repeat")]
check("UDP burst of 500 is one line plus one repeat of 499", len(first) == 1 and len(rep) == 1 and rep[0]["net"]["count"] == 499, [e["net"] for e in udp])
check("burst is tagged connect_outside_allowlist", bool(first) and "connect_outside_allowlist" in first[0].get("rules", []))

mapped = find(lambda e: e["type"] == "connect" and e["net"]["dst"] == "93.184.216.34")
check("IPv4-mapped IPv6 connect is reported as IPv4", bool(mapped) and mapped[0]["net"]["family"] == 4, mapped)

# mkdir -p /tmp/c/d && cp ... /tmp/c/d/y: whether /tmp/c/d is seen live or by
# the rescan of /tmp/c depends on timing; neither it nor the file may be lost.
race_d = find(lambda e: e["type"] == "file" and e["file"]["path"] == "/tmp/c/d" and cid(e) == wl)
race_y = find(lambda e: e["type"] == "file" and e["file"]["path"] == "/tmp/c/d/y" and cid(e) == wl)
check("directory tree created in one command is not lost", bool(race_d) and bool(race_y), [e["file"] for e in race_d + race_y])

sym = find(lambda e: e["type"] == "file" and e["file"]["path"] == "/tmp/real/f" and cid(e) == wl)
check("absolute symlink in the image resolves inside the container", bool(sym))

evil = find(lambda e: e["type"] == "file" and e["file"]["path"] == "/usr/local/bin/evil" and cid(e) == root)
check("write to a binary directory is tagged", bool(evil) and "write_to_binary_dir" in evil[0].get("rules", []))

moved = find(lambda e: e["type"] == "file" and e["file"]["path"] == "/usr/local/bin/s/f" and cid(e) == root)
check("directory moved into a binary directory is re-watched under its new path", bool(moved) and "write_to_binary_dir" in moved[0].get("rules", []), find(lambda e: e.get("file") and e["file"]["path"].endswith("/s/f")))
stale = find(lambda e: e["type"] == "file" and e["file"]["path"].startswith("/tmp/s/"))
check("no event under the old path of the moved directory", not stale, stale)

trunc = find(lambda e: e["type"] == "exec" and e["process"].get("truncated"))
check("long command line is truncated and flagged", bool(trunc) and len("\0".join(trunc[0]["process"]["cmdline"])) <= 4096)

check("workload restart: old container removed", bool(find(lambda e: e["type"] == "container_remove" and cid(e) == wl)))
check("workload restart: new container added", bool(find(lambda e: e["type"] == "container_add" and cid(e) == wl2)) and wl2 != wl)
check("events after the restart carry the new container", bool(find(lambda e: e["type"] == "file" and e["file"]["path"] == "/tmp/after_restart" and cid(e) == wl2)))

orphans = find(lambda e: e["type"] == "exec" and not e.get("container"))
check("no exec event without a container", not orphans, orphans[:3])

print(f"{len(events)} events, {failed} failed")
sys.exit(1 if failed else 0)
