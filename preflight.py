"""Generic, download-free capacity gate for a manually approved public runner."""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

GIB = 1024 ** 3


def require(value):
    if not value:
        raise RuntimeError("SAFETY_CHECK_FAILED")


def context_ok(env, event):
    repository = event.get("repository", {})
    owner = env.get("GITHUB_REPOSITORY_OWNER", "")
    return all((
        bool(owner), env.get("GITHUB_ACTIONS") == "true", env.get("RUNNER_ENVIRONMENT") == "github-hosted",
        env.get("RUNNER_OS") == "Linux", env.get("RUNNER_ARCH") == "X64",
        env.get("GITHUB_EVENT_NAME") == "workflow_dispatch", env.get("GITHUB_ACTOR") == owner,
        repository.get("private") is False, repository.get("owner", {}).get("login") == owner,
        repository.get("full_name") == env.get("GITHUB_REPOSITORY"),
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", env.get("GITHUB_REPOSITORY", "")) is not None,
        str(repository.get("id", "")) == env.get("GITHUB_REPOSITORY_ID"),
        env.get("GITHUB_RUN_ID", "").isdigit(), env.get("GITHUB_RUN_ATTEMPT") == "1",
        env.get("GITHUB_REF") == "refs/heads/main", env.get("APPROVAL") == "SYNTHETIC_ONLY",
        re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is not None,
    ))


def memory():
    values = {line.split(":")[0]: int(line.split()[1]) * 1024
              for line in pathlib.Path("/proc/meminfo").read_text().splitlines()}
    available = values["MemAvailable"]
    group = next((line.split(":", 2)[2] for line in pathlib.Path("/proc/self/cgroup").read_text().splitlines()
                  if line.startswith("0::")), None)
    require(group is not None)
    root = pathlib.Path("/sys/fs/cgroup")
    node = root / group.lstrip("/")
    if not node.exists():
        node = root
    for parent in (node, *node.parents):
        if parent != root and root not in parent.parents:
            continue
        limit, used = parent / "memory.max", parent / "memory.current"
        if limit.exists() and used.exists() and limit.read_text().strip() != "max":
            available = min(available, int(limit.read_text()) - int(used.read_text()))
        if parent == root:
            break
    return values["MemTotal"], max(0, available)


def safe_environment():
    result = {key: os.environ[key] for key in ("PATH",) if key in os.environ}
    # Do not read ambient Docker credentials or forward runner credentials.
    result.update(HOME="/nonexistent", DOCKER_CONFIG="/nonexistent",
                  DOCKER_HOST="unix:///var/run/docker.sock", LC_ALL="C.UTF-8", LANG="C.UTF-8")
    return result


def capacity_reason(data):
    if min(data["cpus"], data["engine_cpus"]) < 4:
        return "CPU_CAPACITY"
    if min(data["total_memory"], data["engine_memory"]) < 15 * GIB:
        return "TOTAL_MEMORY_CAPACITY"
    if data["available_memory"] < 6 * GIB:
        return "AVAILABLE_MEMORY"
    if not data["disks"] or min(data["disks"].values()) < 18 * GIB:
        return "DISK_CAPACITY"
    return None


def runtime_reason(available, disks, initial):
    if available < 4 * GIB:
        return "MEMORY_FLOOR"
    if set(disks) != set(initial) or min(disks.values()) < 10.5 * GIB:
        return "DISK_FLOOR"
    if any(initial[path] - disks[path] >= 7.5 * GIB for path in initial):
        return "DISK_GROWTH"
    return None


def measure():
    require(sys.platform == "linux" and all(shutil.which(tool) for tool in ("docker", "git", "go", "ss")))
    require(hasattr(os, "memfd_create"))
    total, available = memory()
    def query(*args):
        p = subprocess.run(["docker", *args], env=safe_environment(), capture_output=True, timeout=10)
        require(p.returncode == 0 and len(p.stdout) < 1024 * 1024)
        return json.loads(p.stdout)
    require(query("context", "inspect")[0]["Endpoints"]["docker"]["Host"].startswith("unix://"))
    info = query("info", "--format", "{{json .}}")
    require(info["DockerRootDir"] == "/var/lib/docker")
    paths = ("/", os.environ["RUNNER_TEMP"], "/var/lib/docker", "/var/lib/containerd")
    return {"cpus": os.cpu_count() or 0, "engine_cpus": info["NCPU"], "total_memory": total,
            "engine_memory": info["MemTotal"], "available_memory": available,
            "disks": {path: shutil.disk_usage(path).free for path in paths}}


def gate_file():
    return pathlib.Path(os.environ["RUNNER_TEMP"]) / "synthetic-recovery-gate.json"


def main():
    if sys.argv[1:] != ["--approve-capacity"]:
        print("INERT")
        return 0
    stage = "context"
    try:
        origin = {"wall": time.time(), "mono": time.monotonic()}
        event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        require(context_ok(os.environ, event))
        stage = "resource_measurement"
        data = measure()
        print(json.dumps({"capacity_measurements": data}))
        stage = "capacity_thresholds"
        reason = capacity_reason(data)
        if reason:
            print(json.dumps({"status": "BLOCKED_BEFORE_DOWNLOADS", "reason": reason}))
            return 2
        record = {"origin": origin, "capacity": data, "run": os.environ["GITHUB_RUN_ID"],
                  "repository": os.environ["GITHUB_REPOSITORY_ID"], "commit": os.environ["GITHUB_SHA"]}
        with gate_file().open("x", encoding="utf-8") as handle:
            json.dump(record, handle)
        print('{"status":"CAPACITY_PASSED"}')
        return 0
    except Exception as error:
        print(json.dumps({"status": "BLOCKED_BEFORE_DOWNLOADS", "reason": "UNVERIFIED_SAFETY",
                          "stage": stage, "error_type": type(error).__name__}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
