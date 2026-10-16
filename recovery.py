"""Standalone synthetic PostgreSQL recovery example. Inert without --run."""
import hashlib
import io
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
import uuid

import preflight

GIB = 1024 ** 3
MEMORY = 768 * 1024 ** 2
MAX_OUTPUT = 16 * 1024 ** 2
IMAGE_DIGEST = "sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826"
IMAGE = "docker.io/library/postgres@" + IMAGE_DIGEST
AGE_SHA = "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"
PROOF_SHA = "98402fa59b4e433426156b4a7e74a32e44902e0434c61158f7de18ffc84f1f97"
PUBLISHER_KEYS = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM1WpnEswJLPzvXJDiswowy48U+G+G1kmgwUE2eaRHZG\n"
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAz2WM5CyPLqiNjk7CLl4roDXwKhQ0QExXLebukZEZFS\n"
)
ROLES = ("sample_owner", "sample_a", "sample_b")
FIXTURE = """
CREATE ROLE sample_owner NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE sample_a NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE ROLE sample_b NOLOGIN NOINHERIT NOBYPASSRLS;
CREATE SCHEMA sample AUTHORIZATION sample_owner;
CREATE TABLE sample.organizations(code text PRIMARY KEY);
CREATE TABLE sample.entries(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 organization text NOT NULL REFERENCES sample.organizations(code),
 minor_units bigint NOT NULL CHECK(minor_units>=0), note text NOT NULL);
ALTER TABLE sample.organizations OWNER TO sample_owner;
ALTER TABLE sample.entries OWNER TO sample_owner;
INSERT INTO sample.organizations VALUES('a'),('b');
INSERT INTO sample.entries(organization,minor_units,note)
 VALUES('a',10,'synthetic é'),('a',20,'synthetic β'),('b',7,'synthetic 例');
CREATE INDEX sample_entries_organization ON sample.entries(organization);
ALTER TABLE sample.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE sample.entries FORCE ROW LEVEL SECURITY;
CREATE POLICY sample_read ON sample.entries FOR SELECT TO sample_a,sample_b
 USING(organization=CASE current_user WHEN 'sample_a' THEN 'a' WHEN 'sample_b' THEN 'b' END);
REVOKE ALL ON SCHEMA sample FROM PUBLIC;
GRANT USAGE ON SCHEMA sample TO sample_a,sample_b;
GRANT SELECT ON sample.entries TO sample_a,sample_b;
"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def configuration_ok(obj, item):
    host = obj["HostConfig"]
    mounts = obj.get("Mounts", [])
    return all((host["Memory"] == MEMORY, host["MemorySwap"] == MEMORY,
                host["NanoCpus"] == 1_000_000_000, host["PidsLimit"] == 128,
                host["ShmSize"] == 64 * 1024 ** 2, host["IpcMode"] == "private",
                host.get("PidMode", "") == "", not host["Privileged"], not host.get("Binds"),
                not host.get("CapAdd"), not host.get("Devices"), host["NetworkMode"] == item["network"],
                host["RestartPolicy"]["Name"] == "no", host["LogConfig"]["Type"] == "none",
                "no-new-privileges:true" in host.get("SecurityOpt", []),
                host["PortBindings"] == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(item["port"])}]},
                len(mounts) == 1, mounts[0].get("Name") == item["volume"] if mounts else False,
                mounts[0].get("Type") == "volume" if mounts else False,
                mounts[0].get("Destination") == "/var/lib/postgresql/data" if mounts else False))


def decode_bundle(data):
    preflight.require(len(data) <= MAX_OUTPUT)
    bundle = json.loads(data)
    preflight.require(set(bundle) == {"format", "roles", "sql", "catalog", "sha256"})
    preflight.require(bundle["format"] == "synthetic-postgresql-v1")
    preflight.require(isinstance(bundle["roles"], str) and isinstance(bundle["sql"], str))
    preflight.require(isinstance(bundle["catalog"], dict))
    preflight.require(sha((bundle["roles"] + bundle["sql"]).encode()) == bundle["sha256"])
    return bundle


class Example:
    def __init__(self, gate):
        self.gate = gate
        self.origin = gate["origin"]["mono"]
        self.work_deadline = self.origin + 45 * 60
        self.cleanup_limit = self.origin + 51 * 60
        self.tag = uuid.uuid4().hex
        self.root = pathlib.Path(os.environ["RUNNER_TEMP"]) / ("postgres-example-" + self.tag)
        self.env = preflight.safe_environment()
        self.owned = []
        self.passwords = {}
        self.image_new = False
        self.abort = threading.Event()
        self.done = threading.Event()
        self.current = None
        self.stop_lock = threading.Lock()
        self.checks = []
        self.timings = {}
        self.minimum_ram = float("inf")
        self.minimum_disk = float("inf")
        self.maximum_growth = 0
        self.monitor = None
        self.baseline = None

    def check(self, name, valid):
        self.checks.append({"check": name, "passed": bool(valid)})
        preflight.require(valid)

    def command(self, args, data=None, *, timeout=60, failure_ok=False, extra=None, fds=(), cleanup=False):
        if not cleanup:
            preflight.require(not self.abort.is_set() and time.monotonic() < self.work_deadline)
            timeout = min(timeout, max(1, self.work_deadline - time.monotonic()))
        elif hasattr(self, "active_cleanup_limit"):
            timeout = min(timeout, max(1, self.active_cleanup_limit - time.monotonic()))
        process = subprocess.Popen(args, env={**self.env, **(extra or {})}, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=fds, start_new_session=True)
        tracked = threading.current_thread() is threading.main_thread()
        if tracked:
            self.current = process
        try:
            out, _ = process.communicate(data, timeout=timeout)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            raise RuntimeError("COMMAND_INCOMPLETE") from None
        finally:
            if tracked:
                self.current = None
        preflight.require(len(out) <= MAX_OUTPUT)
        if not cleanup:
            preflight.require(not self.abort.is_set())
        if process.returncode:
            if failure_ok:
                return process.returncode, b""  # Discard ALL partial output.
            raise RuntimeError("COMMAND_FAILED")
        return 0, out

    def docker(self, *args, **options):
        return self.command(["docker", *args], **options)

    def inspect(self, kind, name):
        return json.loads(self.docker(kind, "inspect", name, timeout=5, cleanup=True)[1])[0]

    def journal(self):
        (self.root / "ownership.json").write_text(json.dumps(self.owned))

    def sample(self):
        _, ram = preflight.memory()
        initial = self.gate["capacity"]["disks"]
        disks = {p: shutil.disk_usage(p).free for p in initial}
        self.minimum_ram = min(self.minimum_ram, ram)
        self.minimum_disk = min(self.minimum_disk, *disks.values())
        self.maximum_growth = max(self.maximum_growth, *(initial[p]-disks[p] for p in initial))
        preflight.require(preflight.runtime_reason(ram, disks, initial) is None)

    def watch(self):
        while not self.done.wait(1):
            try:
                self.sample()
                preflight.require(time.monotonic() < self.work_deadline)
                active = 0
                for item in list(self.owned):
                    if item["kind"] != "container" or not item.get("started"):
                        continue
                    obj = self.inspect("container", item["id"])
                    preflight.require(configuration_ok(obj, item) and not obj["State"]["OOMKilled"])
                    preflight.require(obj["State"]["Running"] or item.get("stopping"))
                    preflight.require(set(obj["NetworkSettings"]["Networks"]) == {item["network"]})
                    if obj["State"]["Running"]:
                        preflight.require(obj["NetworkSettings"]["Ports"] == {
                            "5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(item["port"])}]})
                    active += bool(obj["State"]["Running"])
                preflight.require(active <= 1)
            except Exception:
                self.abort.set()
                process = self.current
                if process is not None and process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.stop_owned()
                return

    def baseline_state(self):
        result = {}
        for kind, args in (("containers", ("ps", "-aq")), ("networks", ("network", "ls", "-q")),
                           ("volumes", ("volume", "ls", "-q")), ("images", ("image", "ls", "-q", "--no-trunc"))):
            result[kind] = sorted(set(self.docker(*args, cleanup=True)[1].decode().split()))
        for kind, key in (("network", "networks"), ("volume", "volumes")):
            for identifier in result[key]:
                result[kind + ":" + identifier] = sha(json.dumps(self.inspect(kind, identifier), sort_keys=True).encode())
        return result

    def prepare(self):
        event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        self.check("manual_public_context", preflight.context_ok(os.environ, event))
        self.check("original_job_clock", self.gate["run"] == os.environ["GITHUB_RUN_ID"]
                   and self.gate["commit"] == os.environ["GITHUB_SHA"]
                   and self.gate["repository"] == os.environ["GITHUB_REPOSITORY_ID"]
                   and 0 <= time.monotonic()-self.origin < 45*60)
        current = preflight.measure()
        self.check("capacity_before_tools", preflight.capacity_reason(current) is None)
        self.check("same_filesystems", set(current["disks"]) == set(self.gate["capacity"]["disks"]))
        self.sample()
        self.baseline = self.baseline_state()
        self.check("no_preexisting_containers", not self.baseline["containers"])
        self.root.mkdir(mode=0o700, exist_ok=False)
        config = self.root / "registry-config"
        config.mkdir(mode=0o700)
        (config / "config.json").write_text('{"auths":{}}')
        self.env["DOCKER_CONFIG"] = str(config)
        self.journal()
        self.monitor = threading.Thread(target=self.watch, daemon=True)
        self.monitor.start()

    def fetch(self, url, limit, headers=None):
        self.sample()
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=30) as response:
            data = response.read(limit+1)
        preflight.require(len(data) <= limit)
        return data

    def tools(self):
        folder = self.root / "tools"
        folder.mkdir(mode=0o700)
        env = {"GOBIN": str(folder), "GOCACHE": str(folder/"cache"), "GOPATH": str(folder/"modules"),
               "GOTOOLCHAIN": "local", "GOMAXPROCS": "2", "CGO_ENABLED": "0", "GOENV": "off", "GOAUTH": "off",
               "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"}
        self.command(["go", "install", "sigsum.org/sigsum-go/cmd/sigsum-verify@v0.13.1"], timeout=600, extra=env)
        url = "https://dl.filippo.io/age/v1.3.2?for=linux/amd64"
        archive = self.fetch(url, 48*1024**2)
        proof = self.fetch(url+"&proof", 1024**2)
        self.check("publisher_release_hashes", sha(archive) == AGE_SHA and sha(proof) == PROOF_SHA)
        keyfile, prooffile = folder/"publisher.pub", folder/"release.proof"
        keyfile.write_text(PUBLISHER_KEYS)
        prooffile.write_bytes(proof)
        verifier = [str(folder/"sigsum-verify"), "-k", str(keyfile), "-P", "sigsum-generic-2025-1", str(prooffile)]
        self.command(verifier, archive)
        damaged = bytearray(archive)
        damaged[len(damaged)//2] ^= 1
        self.check("bad_tool_rejected", self.command(verifier, bytes(damaged), failure_ok=True)[0] != 0)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            for filename in ("age", "age-keygen"):
                entries = [m for m in package.getmembers() if m.name == "age/"+filename and m.isfile() and m.size <= 16*1024**2]
                preflight.require(len(entries) == 1)
                target = folder/filename
                target.write_bytes(package.extractfile(entries[0]).read())
                target.chmod(0o700)
        self.age, self.keygen = str(folder/"age"), str(folder/"age-keygen")
        self.check("age_version", self.command([self.age, "--version"])[1].strip() in (b"1.3.2", b"v1.3.2"))

    def image(self):
        token = json.loads(self.fetch("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/postgres:pull", 128*1024))["token"]
        headers = {"Authorization": "Bearer "+token, "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json"}
        endpoint = "https://registry-1.docker.io/v2/library/postgres/manifests/"
        index = self.fetch(endpoint+IMAGE_DIGEST, 1024**2, headers)
        self.check("public_image_digest", "sha256:"+sha(index) == IMAGE_DIGEST)
        entries = [m for m in json.loads(index)["manifests"] if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == "amd64"]
        preflight.require(len(entries) == 1)
        manifest_bytes = self.fetch(endpoint+entries[0]["digest"], 1024**2, headers)
        preflight.require("sha256:"+sha(manifest_bytes) == entries[0]["digest"])
        manifest = json.loads(manifest_bytes)
        self.check("compressed_image_budget", sum(layer["size"] for layer in manifest["layers"]) <= 0.4*GIB)
        exists = self.docker("image", "inspect", IMAGE, failure_ok=True)[0] == 0
        if not exists:
            preflight.require(manifest["config"]["digest"] not in self.baseline["images"])
            self.docker("pull", "--platform", "linux/amd64", IMAGE, timeout=600)
            self.image_new = True
        obj = self.inspect("image", IMAGE)
        self.check("image_platform_and_size", obj["Architecture"] == "amd64" and obj["Size"] <= 4*GIB
                   and any(value in obj.get("RepoDigests", []) for value in (
                       IMAGE, "postgres@"+IMAGE_DIGEST, "library/postgres@"+IMAGE_DIGEST)))
        self.image_id = obj["Id"]

    def create(self, kind, name, arguments, **metadata):
        self.check("fresh_"+kind, self.docker(kind, "inspect", name, failure_ok=True)[0] != 0)
        item = {"kind": kind, "id": name, "name": name, **metadata}
        self.owned.append(item)
        self.journal()
        self.docker(*arguments)
        obj = self.inspect(kind, name)
        item["id"] = obj.get("Id", obj.get("Name"))
        labels = obj.get("Labels", obj.get("Config", {}).get("Labels", {})) or {}
        self.check("created_resource_owner", labels.get("synthetic.recovery") == self.tag)
        self.journal()
        return item

    def database(self, phase, port):
        label = "synthetic.recovery="+self.tag
        prefix = "pg-example-"+self.tag[:12]+"-"+phase
        network, volume = prefix+"-net", prefix+"-data"
        self.create("network", network, ["network", "create", "--internal", "--driver", "bridge", "--label", label, network])
        net = self.inspect("network", network)
        self.check("internal_network", net["Internal"] and not net["EnableIPv6"])
        self.create("volume", volume, ["volume", "create", "--label", label, volume])
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
        password = secrets.token_urlsafe(32)
        args = ["create", "--name", prefix, "--label", label, "--pull", "never", "--memory", str(MEMORY),
                "--memory-swap", str(MEMORY), "--cpus", "1", "--pids-limit", "128", "--shm-size", "64m",
                "--ipc", "private", "--security-opt", "no-new-privileges:true", "--restart", "no", "--log-driver", "none",
                "--network", network, "--publish", f"127.0.0.1:{port}:5432/tcp",
                "--mount", f"type=volume,src={volume},dst=/var/lib/postgresql/data", "--env", "POSTGRES_PASSWORD",
                "--env", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256", IMAGE,
                "postgres", "-c", "shared_buffers=64MB", "-c", "work_mem=2MB", "-c", "maintenance_work_mem=32MB",
                "-c", "max_connections=32", "-c", "max_parallel_workers=0", "-c", "log_statement=none",
                "-c", "log_min_error_statement=panic", "-c", "log_connections=off", "-c", "log_disconnections=off"]
        self.check("fresh_container", self.docker("container", "inspect", prefix, failure_ok=True)[0] != 0)
        item = {"kind": "container", "id": prefix, "name": prefix, "network": network, "volume": volume, "port": port, "started": False}
        self.owned.append(item)
        self.journal()
        self.docker(*args, extra={"POSTGRES_PASSWORD": password})
        obj = self.inspect("container", prefix)
        item["id"] = obj["Id"]
        self.passwords[item["id"]] = password
        self.journal()
        self.check("prestart_limits", configuration_ok(obj, item) and obj["Image"] == self.image_id
                   and obj["Config"]["Labels"].get("synthetic.recovery") == self.tag)
        self.docker("start", item["id"])
        item["started"] = True
        self.journal()
        obj = self.inspect("container", item["id"])
        self.check("explicit_loopback_only", obj["NetworkSettings"]["Ports"] == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]})
        self.check("only_owned_network", set(obj["NetworkSettings"]["Networks"]) == {network})
        limits = self.docker("exec", item["id"], "sh", "-c", "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max")[1].decode().splitlines()
        self.check("effective_resource_limits", len(limits) == 4 and limits[0] == str(MEMORY) and limits[1] == "0"
                   and limits[2].split()[0] == limits[2].split()[1] and limits[3] == "128")
        until = time.monotonic()+120
        while time.monotonic() < until:
            if self.docker("exec", item["id"], "pg_isready", "-h", "127.0.0.1", "-U", "postgres", failure_ok=True)[0] == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("DATABASE_NOT_READY")
        for _ in range(30):
            preflight.require(not self.abort.wait(1))
        self.sample()
        listeners = self.command(["ss", "-H", "-lnt"])[1].decode().splitlines()
        self.check("no_wildcard_listener", all(line.split()[3] == "127.0.0.1:"+str(port)
                   for line in listeners if len(line.split()) >= 4 and line.split()[3].endswith(":"+str(port))))
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        self.query(item, "postgres", "CREATE DATABASE specimen;")
        return item

    def query(self, item, database, statement, *, transaction=False, failure_ok=False):
        args = ["exec", "-i", "--env", "PGPASSWORD", item["id"], "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
                "-h", "127.0.0.1", "-U", "postgres", "-d", database]
        if transaction:
            args += ["--single-transaction"]
        return self.docker(*args, "-f", "-", data=statement.encode(), failure_ok=failure_ok,
                           extra={"PGPASSWORD": self.passwords[item["id"]]})

    def catalog(self, item):
        sql = """SELECT json_build_object(
 'rows',(SELECT json_agg(r ORDER BY id) FROM sample.entries r),
 'organizations',(SELECT json_agg(r ORDER BY code) FROM sample.organizations r),
 'sequence',(SELECT json_build_array(last_value,is_called) FROM sample.entries_id_seq),
 'tables',(SELECT json_agg(r ORDER BY relname) FROM
 (SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner) owner,c.relacl::text acl
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sample') r),
 'schema',(SELECT json_build_array(pg_get_userbyid(nspowner),nspacl::text) FROM pg_namespace WHERE nspname='sample'),
 'policies',(SELECT json_agg(r ORDER BY policyname) FROM (SELECT policyname,roles,cmd,qual,with_check FROM pg_policies WHERE schemaname='sample') r),
 'constraints',(SELECT json_agg(r ORDER BY conname) FROM (SELECT conname,pg_get_constraintdef(oid) definition FROM pg_constraint WHERE connamespace='sample'::regnamespace) r),
 'indexes',(SELECT json_agg(r ORDER BY indexname) FROM (SELECT indexname,indexdef FROM pg_indexes WHERE schemaname='sample') r),
 'roles',(SELECT json_agg(r ORDER BY rolname) FROM (SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls
 FROM pg_roles WHERE rolname IN ('sample_owner','sample_a','sample_b')) r));"""
        return json.loads(self.query(item, "specimen", sql)[1])

    def behavior(self, item):
        def value(text):
            return self.query(item, "specimen", text)[1].strip()
        self.check("exact_rows_and_integer_units", value("SELECT count(*),sum(minor_units) FROM sample.entries;") == b"3|37")
        for role, own, other, count in (("sample_a", "a", "b", 2), ("sample_b", "b", "a", 1)):
            self.check("role_visibility", value(f"SET ROLE {role};SELECT count(*) FROM sample.entries;") == str(count).encode())
            self.check("other_rows_hidden", value(f"SET ROLE {role};SELECT count(*) FROM sample.entries WHERE organization='{other}';") == b"0")
            self.check("direct_write_denied", self.query(item, "specimen", f"SET ROLE {role};INSERT INTO sample.entries(organization,minor_units,note) VALUES('{own}',1,'synthetic');", transaction=True, failure_ok=True)[0] != 0)
        for organization, amount in (("a", -1), ("missing", 1)):
            self.check("constraint_rejection", self.query(item, "specimen", f"INSERT INTO sample.entries OVERRIDING SYSTEM VALUE VALUES(999,'{organization}',{amount},'synthetic');", transaction=True, failure_ok=True)[0] != 0)

    def decrypt(self, ciphertext, identity, *, failure_ok=False):
        descriptor = os.memfd_create("synthetic-identity", os.MFD_CLOEXEC)
        try:
            os.write(descriptor, identity)
            os.lseek(descriptor, 0, os.SEEK_SET)
            return self.command([self.age, "--decrypt", "--identity", f"/proc/self/fd/{descriptor}"], ciphertext,
                                fds=(descriptor,), failure_ok=failure_ok)
        finally:
            os.close(descriptor)

    def stop_one(self, item):
        obj = self.inspect("container", item["id"])
        preflight.require(obj["Config"]["Labels"].get("synthetic.recovery") == self.tag)
        item["stopping"] = True
        if obj["State"]["Running"]:
            self.docker("stop", "--time", "10", item["id"], timeout=15, cleanup=True)
        self.check("owned_container_stopped", not self.inspect("container", item["id"])["State"]["Running"])
        item["started"] = False

    def stop_owned(self):
        if not self.stop_lock.acquire(timeout=1):
            return False
        ok = True
        try:
            for item in list(self.owned):
                if item["kind"] == "container":
                    try:
                        self.stop_one(item)
                    except Exception:
                        ok = False
            return ok
        finally:
            self.stop_lock.release()

    def execute(self):
        self.prepare()
        code, out = self.command([sys.executable, "-B", "-c",
                                  "import sys;sys.stdout.write('partial');sys.exit(1)"], failure_ok=True)
        self.check("failed_producer_discards_output", code != 0 and out == b"")
        self.tools()
        self.image()
        source = self.database("source", 25439)
        self.query(source, "specimen", FIXTURE, transaction=True)
        self.check("postgres_major", 170000 <= int(self.query(source, "specimen", "SHOW server_version_num;")[1]) < 180000)
        self.behavior(source)
        catalog = self.catalog(source)
        before = time.monotonic()
        connection = {"PGPASSWORD": self.passwords[source["id"]]}
        common = ["exec", "--env", "PGPASSWORD", source["id"]]
        dump = self.docker(*common, "pg_dump", "--format=plain", "--schema=sample", "--host=127.0.0.1", "--username=postgres", "specimen", extra=connection)[1]
        globals_dump = self.docker(*common, "pg_dumpall", "--roles-only", "--no-role-passwords", "--host=127.0.0.1", "--username=postgres", extra=connection)[1].decode()
        lines = [line for line in globals_dump.splitlines() if re.fullmatch(r"(?:CREATE|ALTER) ROLE sample_(?:owner|a|b)(?:;| WITH [^;]+;)", line)]
        self.check("three_role_definitions", len(lines) == 6 and all("CREATE ROLE "+role+";" in lines for role in ROLES))
        roles = "\n".join(lines)+"\n"
        self.check("nonempty_complete_dump", bool(dump) and b"CREATE TABLE sample.entries" in dump)
        bundle = {"format": "synthetic-postgresql-v1", "roles": roles, "sql": dump.decode(), "catalog": catalog,
                  "sha256": sha(roles.encode()+dump)}
        plaintext = json.dumps(bundle, ensure_ascii=False).encode()
        decode_bundle(plaintext)
        identity = self.command([self.keygen])[1]
        recipient = self.command([self.keygen, "-y"], identity)[1].decode().strip()
        ciphertext = self.command([self.age, "--encrypt", "--recipient", recipient], plaintext)[1]
        encrypted = self.root/"synthetic.age"
        encrypted.write_bytes(ciphertext)
        self.check("encrypted_file_integrity", sha(encrypted.read_bytes()) == sha(ciphertext))
        self.timings["backup_and_encryption_seconds"] = round(time.monotonic()-before, 3)
        wrong = self.command([self.keygen])[1]
        code, out = self.decrypt(ciphertext, wrong, failure_ok=True)
        self.check("wrong_key_rejected_no_output", code != 0 and not out)
        broken = bytearray(ciphertext)
        broken[-1] ^= 1
        for candidate in (bytes(broken), ciphertext[:-20]):
            code, out = self.decrypt(candidate, identity, failure_ok=True)
            self.check("corruption_rejected_no_output", code != 0 and not out)
        decoded = self.decrypt(ciphertext, identity)[1]
        self.check("decrypted_hash_exact", sha(decoded) == sha(plaintext))
        recovered = decode_bundle(decoded)
        self.stop_one(source)
        self.check("source_stopped_before_target", not self.inspect("container", source["id"])["State"]["Running"])
        target = self.database("target", 25440)
        restore = recovered["roles"]+recovered["sql"]
        before = time.monotonic()
        self.check("empty_target", self.query(target, "specimen", "SELECT count(*) FROM pg_namespace WHERE nspname='sample';")[1].strip() == b"0")
        code, _ = self.query(target, "specimen", restore+"\nSELECT 1/0;\n", transaction=True, failure_ok=True)
        self.check("full_restore_failure_rejected", code != 0)
        self.check("no_partial_schema", self.query(target, "specimen", "SELECT count(*) FROM pg_namespace WHERE nspname='sample';")[1].strip() == b"0")
        self.check("no_partial_roles", self.query(target, "specimen", "SELECT count(*) FROM pg_roles WHERE rolname IN ('sample_owner','sample_a','sample_b');")[1].strip() == b"0")
        self.query(target, "specimen", restore, transaction=True)
        self.check("restored_catalog_exact", self.catalog(target) == recovered["catalog"])
        self.behavior(target)
        baseline = self.catalog(target)
        code, _ = self.query(target, "specimen", "CREATE TABLE sample.partial(id int);SELECT 1/0;", transaction=True, failure_ok=True)
        self.check("failed_sql_preserves_catalog", code != 0 and self.catalog(target) == baseline)
        self.check("sequence_recovered", int(self.query(target, "specimen", "SELECT nextval('sample.entries_id_seq');")[1]) == catalog["sequence"][0]+1)
        self.timings["restore_and_checks_seconds"] = round(time.monotonic()-before, 3)

    def cleanup(self):
        before = time.monotonic()
        self.active_cleanup_limit = min(before+270, self.cleanup_limit)
        self.done.set()
        if self.monitor:
            self.monitor.join(timeout=35)
        ok = self.stop_owned()
        if self.monitor and self.monitor.is_alive():
            ok = False
        for item in reversed(self.owned):
            try:
                preflight.require(time.monotonic() < self.active_cleanup_limit)
                obj = self.inspect(item["kind"], item["id"])
                labels = obj.get("Labels", obj.get("Config", {}).get("Labels", {})) or {}
                preflight.require(labels.get("synthetic.recovery") == self.tag)
                preflight.require(item["kind"] != "container" or not obj["State"]["Running"])
                self.docker(item["kind"], "rm", item["id"], cleanup=True, timeout=10)
            except Exception:
                ok = False
        if self.image_new:
            try:
                preflight.require(self.inspect("image", IMAGE)["Id"] == self.image_id)
                self.docker("image", "rm", IMAGE, cleanup=True, timeout=15)
            except Exception:
                ok = False
        if self.baseline is not None:
            try:
                ok = ok and self.baseline_state() == self.baseline
            except Exception:
                ok = False
        self.passwords.clear()
        if self.root.exists():
            try:
                parent = pathlib.Path(os.environ["RUNNER_TEMP"]).resolve()
                preflight.require(self.root.parent.resolve() == parent and self.root.name == "postgres-example-"+self.tag
                                  and not self.root.is_symlink())
                for path in self.root.rglob("*"):
                    preflight.require(time.monotonic() < self.active_cleanup_limit)
                    if not path.is_symlink():
                        path.chmod(0o700 if path.is_dir() else 0o600)
                shutil.rmtree(self.root)
            except Exception:
                ok = False
        self.timings["cleanup_seconds"] = round(time.monotonic()-before, 3)
        return ok


def main():
    if sys.argv[1:] != ["--run"]:
        print("INERT")
        return 0
    example = None
    completed = cleaned = False
    try:
        require_event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        preflight.require(preflight.context_ok(os.environ, require_event))
        import resource  # Linux only; offline review can import this module on other systems.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        example = Example(json.loads(preflight.gate_file().read_text()))
        def interrupted(signum, frame):
            raise RuntimeError("INTERRUPTED")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        example.execute()
        completed = True
    except BaseException:
        completed = False
    finally:
        if example is not None:
            try:
                cleaned = example.cleanup()
            except BaseException:
                cleaned = False
    accepted = bool(completed and cleaned and example is not None and not example.abort.is_set())
    if example is not None:
        example.checks.extend([{"check": "execution_completed", "passed": completed},
                               {"check": "cleanup_completed", "passed": cleaned},
                               {"check": "no_watchdog_failure", "passed": not example.abort.is_set()}])
    result = {"status": "VERIFIED" if accepted else "INCOMPLETE_NOT_ACCEPTED", "cleanup_verified": cleaned,
              "checks_passed": sum(c["passed"] for c in example.checks) if example else 0,
              "checks_failed": sum(not c["passed"] for c in example.checks) if example else 0,
              "not_tested": ["application recovery", "hosted authentication", "provider backup services"],
              "timings": example.timings if example else {}}
    if example and example.minimum_ram != float("inf"):
        result["resources"] = {"minimum_available_gib": round(example.minimum_ram/GIB, 3),
                               "minimum_free_disk_gib": round(example.minimum_disk/GIB, 3),
                               "maximum_growth_gib": round(example.maximum_growth/GIB, 3)}
    print(json.dumps(result, indent=2))
    return 0 if accepted else 2


if __name__ == "__main__":
    sys.exit(main())
