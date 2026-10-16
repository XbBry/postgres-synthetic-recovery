"""Offline guard tests. No Docker, downloads, keys, SQL, or cloud operations."""
import copy
import contextlib
import io
import json
import sys
import time
import types
import unittest
from unittest import mock

import preflight
import recovery


class Guards(unittest.TestCase):
    def capacity(self):
        return {"cpus": 4, "engine_cpus": 4, "total_memory": 16*preflight.GIB,
                "engine_memory": 16*preflight.GIB, "available_memory": 6*preflight.GIB,
                "disks": {"example": 18*preflight.GIB}}

    def context(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux",
               "RUNNER_ARCH": "X64", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTOR": "example",
               "GITHUB_REPOSITORY_OWNER": "example", "GITHUB_REPOSITORY": "example/example",
               "GITHUB_REPOSITORY_ID": "1", "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_REF": "refs/heads/main", "APPROVAL": "SYNTHETIC_ONLY", "GITHUB_SHA": "0"*40}
        event = {"repository": {"private": False, "owner": {"login": "example"},
                                "full_name": "example/example", "id": 1}}
        return env, event

    def configuration(self):
        item = {"port": 25439, "volume": "example-data", "network": "example-net"}
        obj = {"HostConfig": {"Memory": recovery.MEMORY, "MemorySwap": recovery.MEMORY,
               "NanoCpus": 1_000_000_000, "PidsLimit": 128, "ShmSize": 64*1024**2,
               "IpcMode": "private", "Privileged": False, "NetworkMode": item["network"],
               "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none"},
               "SecurityOpt": ["no-new-privileges:true"],
               "PortBindings": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25439"}]}},
               "Mounts": [{"Name": item["volume"], "Type": "volume", "Destination": "/var/lib/postgresql/data"}]}
        return obj, item

    def test_capacity_boundary(self):
        self.assertIsNone(preflight.capacity_reason(self.capacity()))

    def test_low_startup_resources_rejected(self):
        for field, value in (("cpus", 3), ("engine_cpus", 3), ("total_memory", 14*preflight.GIB),
                             ("engine_memory", 14*preflight.GIB), ("available_memory", 6*preflight.GIB-1)):
            data = self.capacity()
            data[field] = value
            with self.subTest(field=field):
                self.assertIsNotNone(preflight.capacity_reason(data))
        data = self.capacity()
        data["disks"]["example"] -= 1
        self.assertEqual(preflight.capacity_reason(data), "DISK_CAPACITY")

    def test_runtime_stop_margins(self):
        g = preflight.GIB
        self.assertIsNone(preflight.runtime_reason(4*g, {"example": 18*g}, {"example": 18*g}))
        self.assertEqual(preflight.runtime_reason(4*g-1, {"example": 18*g}, {"example": 18*g}), "MEMORY_FLOOR")
        self.assertEqual(preflight.runtime_reason(4*g, {"example": 10.5*g-1}, {"example": 18*g}), "DISK_FLOOR")
        self.assertEqual(preflight.runtime_reason(4*g, {"example": 12.5*g}, {"example": 20*g}), "DISK_GROWTH")

    def test_context_is_owner_manual_public_first_attempt_only(self):
        env, event = self.context()
        self.assertTrue(preflight.context_ok(env, event))
        for field, value in (("GITHUB_ACTOR", "other"), ("GITHUB_RUN_ATTEMPT", "2"),
                             ("GITHUB_EVENT_NAME", "push"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                             ("GITHUB_REF", "refs/heads/other"), ("APPROVAL", "")):
            changed = {**env, field: value}
            with self.subTest(field=field):
                self.assertFalse(preflight.context_ok(changed, event))
        event["repository"]["private"] = True
        self.assertFalse(preflight.context_ok(env, event))

    def test_only_loopback_is_accepted(self):
        obj, item = self.configuration()
        self.assertTrue(recovery.configuration_ok(obj, item))
        for address in ("", "0.0.0.0", "::", "::1"):
            changed = copy.deepcopy(obj)
            changed["HostConfig"]["PortBindings"]["5432/tcp"][0]["HostIp"] = address
            with self.subTest(address=address):
                self.assertFalse(recovery.configuration_ok(changed, item))

    def test_unsafe_limits_and_mounts_rejected(self):
        obj, item = self.configuration()
        for key, value in (("Privileged", True), ("Memory", 0), ("MemorySwap", -1), ("NanoCpus", 0),
                           ("PidsLimit", 0), ("NetworkMode", "host"), ("Binds", ["/:/host"]),
                           ("SecurityOpt", []), ("CapAdd", ["SYS_ADMIN"])):
            changed = copy.deepcopy(obj)
            changed["HostConfig"][key] = value
            with self.subTest(key=key):
                self.assertFalse(recovery.configuration_ok(changed, item))
        obj["Mounts"].append({"Type": "bind", "Destination": "/extra"})
        self.assertFalse(recovery.configuration_ok(obj, item))

    def test_bundle_hash_and_shape(self):
        bundle = {"format": "synthetic-postgresql-v1", "roles": "", "sql": "synthetic",
                  "catalog": {}, "sha256": recovery.sha(b"synthetic")}
        self.assertEqual(recovery.decode_bundle(json.dumps(bundle).encode()), bundle)
        bundle["sql"] = "changed"
        with self.assertRaises(RuntimeError):
            recovery.decode_bundle(json.dumps(bundle).encode())
        bundle["extra"] = True
        with self.assertRaises(RuntimeError):
            recovery.decode_bundle(json.dumps(bundle).encode())


class Diagnostics(unittest.TestCase):
    def example(self):
        # Constructor only: no files, credentials, Docker, keys or databases.
        with mock.patch.dict(recovery.os.environ, {"RUNNER_TEMP": "/unused-synthetic-path"}):
            example = recovery.Example({"origin": {"mono": time.monotonic()}})
        example.stage = "source_port_binding"
        return example

    def report(self, *, failure=None, cleanup=True):
        example = self.example()
        def execute():
            if failure == "guard":
                example.check("explicit_loopback_only", False)
            if failure == "unexpected":
                raise RuntimeError("do-not-emit-this")
        def clean():
            example.stage = "cleanup"
            return cleanup
        output = io.StringIO()
        fake_resource = types.SimpleNamespace(RLIMIT_CORE=4, setrlimit=lambda *args: None)
        with mock.patch.dict(sys.modules, {"resource": fake_resource}), \
             mock.patch.dict(recovery.os.environ, {"GITHUB_EVENT_PATH": "unused"}), \
             mock.patch.object(recovery.sys, "argv", ["recovery.py", "--run"]), \
             mock.patch.object(recovery.pathlib.Path, "read_text", return_value="{}"), \
             mock.patch.object(recovery.preflight, "context_ok", return_value=True), \
             mock.patch.object(recovery.preflight, "gate_file", return_value=recovery.pathlib.Path("unused-gate")), \
             mock.patch.object(recovery.signal, "signal"), \
             mock.patch.object(recovery, "Example", return_value=example), \
             mock.patch.object(example, "execute", side_effect=execute), \
             mock.patch.object(example, "cleanup", side_effect=clean), contextlib.redirect_stdout(output):
            code = recovery.main()
        return code, json.loads(output.getvalue()), output.getvalue()

    def test_failed_names_and_execution_stage_survive_cleanup(self):
        code, result, _ = self.report(failure="guard")
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "INCOMPLETE_NOT_ACCEPTED")
        self.assertTrue(result["cleanup_verified"])
        failed = [entry for entry in result["check_results"] if not entry["passed"]]
        self.assertEqual(result["failed_checks"], failed)
        self.assertEqual([entry["check"] for entry in failed], ["explicit_loopback_only", "execution_completed"])
        self.assertTrue(all(entry["stage"] == "source_port_binding" for entry in failed))
        self.assertEqual(result["execution_stage"], "source_port_binding")
        self.assertEqual(result["failures"][0]["category"], "CHECK_REJECTED")

    def test_cleanup_failure_still_rejects_success(self):
        code, result, _ = self.report(cleanup=False)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "INCOMPLETE_NOT_ACCEPTED")
        self.assertEqual([c["check"] for c in result["check_results"] if not c["passed"]], ["cleanup_completed"])
        code, result, _ = self.report()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "VERIFIED")

    def test_unexpected_exception_text_is_never_reported(self):
        code, result, raw = self.report(failure="unexpected")
        self.assertEqual(code, 2)
        self.assertEqual(result["failures"][0]["category"], "UNEXPECTED_ERROR")
        self.assertNotIn("do-not-emit-this", raw)

    def test_nonzero_commands_discard_partial_output_and_report_exit_code(self):
        example = self.example()
        process = mock.Mock(returncode=23)
        process.communicate.return_value = (b"do-not-emit-this", b"do-not-emit-this")
        with mock.patch.object(recovery.subprocess, "Popen", return_value=process):
            self.assertEqual(example.command(["docker", "exec", "do-not-emit-this"], failure_ok=True), (23, b""))
            self.assertEqual(example.failures, [])
            with self.assertRaisesRegex(RuntimeError, "COMMAND_FAILED"):
                example.command(["docker", "exec", "do-not-emit-this"])
        self.assertEqual(example.failures[0]["exit_code"], 23)
        self.assertEqual(example.failures[0]["category"], "COMMAND_FAILED")
        self.assertNotIn("do-not-emit-this", json.dumps(example.failures))

    def test_timeouts_have_safe_category_and_keep_bounded_kill(self):
        example = self.example()
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        process.communicate.side_effect = [recovery.subprocess.TimeoutExpired("do-not-emit-this", 1), (b"partial", b"do-not-emit-this")]
        with mock.patch.object(recovery.subprocess, "Popen", return_value=process), \
             mock.patch.object(recovery.os, "killpg", create=True) as kill, \
             mock.patch.object(recovery.signal, "SIGKILL", 9, create=True):
            with self.assertRaisesRegex(RuntimeError, "COMMAND_INCOMPLETE"):
                example.command(["synthetic-command"])
            kill.assert_called_once_with(123, 9)
        self.assertEqual(example.failures[0]["category"], "COMMAND_TIMEOUT")
        self.assertEqual(process.communicate.call_args.kwargs, {"timeout": 5})
        self.assertNotIn("do-not-emit-this", json.dumps(example.failures))

    def test_watchdog_names_its_failed_port_guard_and_stops_work(self):
        example = self.example()
        obj, item = Guards().configuration()
        item.update(kind="container", id="synthetic", started=True)
        obj.update(State={"Running": True, "OOMKilled": False},
                   NetworkSettings={"Networks": {item["network"]: {}}, "Ports": {}})
        example.owned = [item]
        example.done = mock.Mock()
        example.done.wait.return_value = False
        with mock.patch.object(example, "sample"), mock.patch.object(example, "inspect", return_value=obj), \
             mock.patch.object(example, "stop_owned") as stop:
            example.watch()
        self.assertTrue(example.abort.is_set())
        stop.assert_called_once_with()
        self.assertEqual(example.failures[0], {"stage": "source_port_binding", "origin": "watchdog",
                         "category": "SAFETY_CHECK_FAILED", "check": "watchdog_loopback_port_binding"})

    def test_safe_error_categories_never_echo_values(self):
        sentinel = "do-not-emit-this"
        cases = [(RuntimeError(sentinel), "UNEXPECTED_ERROR"),
                 (PermissionError(sentinel), "PERMISSION_DENIED"),
                 (FileNotFoundError(sentinel), "LOCAL_RESOURCE_MISSING"),
                 (ValueError(sentinel), "INVALID_OUTPUT"),
                 (recovery.urllib.error.URLError(sentinel), "DOWNLOAD_CONNECTION_ERROR"),
                 (recovery.urllib.error.HTTPError("https://example.invalid/"+sentinel, 403, sentinel, {}, io.BytesIO()), "DOWNLOAD_HTTP_ERROR")]
        for error, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(recovery.error_category(error), expected)
                self.assertNotIn(sentinel, recovery.error_category(error))
            if isinstance(error, recovery.urllib.error.HTTPError):
                example = self.example()
                with mock.patch.object(error, "close", side_effect=RuntimeError(sentinel)):
                    example.record_failure(error)
                example.record_failure(error)
                self.assertTrue(error.fp.closed)
                self.assertNotIn(sentinel, json.dumps(example.failures))


if __name__ == "__main__":
    unittest.main()
