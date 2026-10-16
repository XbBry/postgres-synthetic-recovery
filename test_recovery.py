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
        item = {"volume": "example-data", "network": "example-net", "network_id": "synthetic-network-id"}
        obj = {"HostConfig": {"Memory": recovery.MEMORY, "MemorySwap": recovery.MEMORY,
               "NanoCpus": 1_000_000_000, "PidsLimit": 128, "ShmSize": 64*1024**2,
               "IpcMode": "private", "Privileged": False, "NetworkMode": item["network"],
               "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none"},
               "SecurityOpt": ["no-new-privileges:true"],
               "PortBindings": {}, "PublishAllPorts": False},
               "Config": {"ExposedPorts": {"5432/tcp": {}}},
               "NetworkSettings": {"Ports": {}, "Networks": {item["network"]: {"NetworkID": item["network_id"]}}},
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

    def test_all_host_publication_is_rejected(self):
        obj, item = self.configuration()
        self.assertTrue(recovery.configuration_ok(obj, item))
        for address in ("127.0.0.1", "", "0.0.0.0", "::", "::1"):
            changed = copy.deepcopy(obj)
            changed["HostConfig"]["PortBindings"] = {"5432/tcp": [{"HostIp": address, "HostPort": "25439"}]}
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
        example.stage = "source_zero_publication"
        return example

    def report(self, *, failure=None, cleanup=True):
        example = self.example()
        def execute():
            if failure == "guard":
                example.check("zero_published_ports", False)
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
        self.assertEqual([entry["check"] for entry in failed], ["zero_published_ports", "execution_completed"])
        self.assertTrue(all(entry["stage"] == "source_zero_publication" for entry in failed))
        self.assertEqual(result["execution_stage"], "source_zero_publication")
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
        obj.update(State={"Running": True, "OOMKilled": False})
        obj["NetworkSettings"]["Ports"] = {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25439"}]}
        example.owned, example.done = [item], mock.Mock()
        example.done.wait.return_value = False
        with mock.patch.object(example, "sample"), mock.patch.object(example, "inspect", return_value=obj), \
             mock.patch.object(example, "stop_owned") as stop:
            example.watch()
        self.assertTrue(example.abort.is_set())
        stop.assert_called_once_with()
        self.assertEqual(example.failures[0], {"stage": "source_zero_publication", "origin": "watchdog",
                         "category": "SAFETY_CHECK_FAILED", "check": "watchdog_zero_publication"})

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


class ZeroPublication(unittest.TestCase):
    def configuration(self, example=None):
        example = example or Diagnostics().example()
        obj, item = Guards().configuration()
        prefix = "pg-example-"+example.tag[:12]+"-source"
        item.update(network=prefix+"-net", volume=prefix+"-data", kind="container", id="synthetic", started=True)
        obj["HostConfig"]["NetworkMode"] = item["network"]
        obj["Mounts"][0]["Name"] = item["volume"]
        obj["NetworkSettings"]["Networks"] = {item["network"]: {"NetworkID": item["network_id"]}}
        obj.update(Id=item["id"], Image="synthetic-image", State={"Running": True, "OOMKilled": False})
        obj["Config"]["Labels"] = {"synthetic.recovery": example.tag}
        net = {"Name": item["network"], "Id": item["network_id"], "Driver": "bridge", "Internal": True,
               "EnableIPv6": False, "Labels": {"synthetic.recovery": example.tag}}
        return example, obj, item, net

    def cases(self):
        cases = []
        def add(label, path, value, reason):
            cases.append((label, path, value, reason))
        for field in ("HostConfig", "Config", "NetworkSettings"):
            for label, value in (("missing", mock.sentinel.missing), ("null", None),
                                 ("list", []), ("string", "do-not-emit-this")):
                add(field+"_"+label, (field,), value, "MISSING_OR_INVALID_INSPECTION")
        for field in (("HostConfig", "PortBindings"), ("HostConfig", "PublishAllPorts"),
                      ("Config", "ExposedPorts"), ("NetworkSettings", "Ports")):
            add("missing_"+field[-1], field, mock.sentinel.missing, "MISSING_OR_INVALID_INSPECTION")
        for value in ([], "do-not-emit-this", {"5432/tcp": None}, {"5432/tcp": []}):
            reason = "CONFIGURED_PORT_PUBLICATION" if type(value) is dict else "MISSING_OR_INVALID_INSPECTION"
            add("configured_"+str(len(cases)), ("HostConfig", "PortBindings"), value, reason)
        for address in ("127.0.0.1", "0.0.0.0", "::", "::1", "", None):
            binding = {"5432/tcp": [{"HostIp": address, "HostPort": "25439"}]}
            add("configured_address_"+str(len(cases)), ("HostConfig", "PortBindings"), binding, "CONFIGURED_PORT_PUBLICATION")
            add("runtime_address_"+str(len(cases)), ("NetworkSettings", "Ports"), binding, "RUNTIME_PORT_PUBLICATION")
        for value in (True, None, 0, "false", []):
            add("publish_all_"+str(len(cases)), ("HostConfig", "PublishAllPorts"), value, "PUBLISH_ALL_PORTS")
        for value in (None, [], {}, {"5432/tcp": None}, {"5432/tcp": {"extra": "do-not-emit-this"}},
                      {"5432/tcp": {}, "5433/tcp": {}}):
            add("expose_"+str(len(cases)), ("Config", "ExposedPorts"), value, "UNEXPECTED_EXPOSE_METADATA")
        for value in (None, [], "do-not-emit-this", {"5433/tcp": None}, {"5432/tcp": None, "5433/tcp": None}):
            reason = "UNEXPECTED_RUNTIME_PORTS" if type(value) is dict else "MISSING_OR_INVALID_INSPECTION"
            add("runtime_shape_"+str(len(cases)), ("NetworkSettings", "Ports"), value, reason)
        for value in ({"5432/tcp": []}, {"5432/tcp": {}}, {"5432/tcp": "do-not-emit-this"},
                      {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25439"}]*2}):
            add("runtime_binding_"+str(len(cases)), ("NetworkSettings", "Ports"), value, "RUNTIME_PORT_PUBLICATION")
        return cases

    def change(self, obj, path, value):
        parent = obj
        for part in path[:-1]:
            parent = parent[part]
        if value is mock.sentinel.missing:
            del parent[path[-1]]
        else:
            parent[path[-1]] = value

    def test_only_unpublished_expose_metadata_is_accepted(self):
        _, obj, item, _ = self.configuration()
        for configured in ({}, None):
            for runtime in ({}, {"5432/tcp": None}):
                with self.subTest(configured=configured, runtime=runtime):
                    obj["HostConfig"]["PortBindings"] = configured
                    obj["NetworkSettings"]["Ports"] = runtime
                    self.assertIsNone(recovery.zero_publication_reason(obj))
                    self.assertTrue(recovery.configuration_ok(obj, item))

    def test_invalid_and_published_inspection_is_rejected_with_fixed_reasons(self):
        for label, path, value, reason in self.cases():
            with self.subTest(case=label):
                _, obj, _, _ = self.configuration()
                self.change(obj, path, value)
                self.assertEqual(recovery.zero_publication_reason(obj), reason)
                self.assertNotIn("do-not-emit-this", reason)
        for obj in (None, [], "do-not-emit-this"):
            self.assertEqual(recovery.zero_publication_reason(obj), "MISSING_OR_INVALID_INSPECTION")

    def test_main_and_watchdog_reject_the_same_zero_publication_cases(self):
        for label, path, value, reason in self.cases():
            with self.subTest(case=label):
                example, obj, item, net = self.configuration()
                example.image_id = obj["Image"]
                self.change(obj, path, value)
                with mock.patch.object(example, "create"), mock.patch.object(example, "journal"), \
                     mock.patch.object(example, "docker", return_value=(1, b"")), \
                     mock.patch.object(example, "inspect", side_effect=lambda kind, identifier: net if kind == "network" else obj), \
                     mock.patch.object(example, "query") as query, \
                     mock.patch.object(recovery.secrets, "token_urlsafe", return_value="unused-synthetic-value"):
                    with self.assertRaises(RuntimeError):
                        example.database("source")
                query.assert_not_called()
                rejected = [entry["check"] for entry in example.checks if not entry["passed"]]
                self.assertTrue(any(name.startswith("zero_published_ports") for name in rejected), rejected)
                watch, obj2, watch_item, watch_net = self.configuration()
                self.change(obj2, path, value)
                watch.owned, watch.done = [watch_item], mock.Mock()
                watch.done.wait.return_value = False
                with mock.patch.object(watch, "sample"), \
                     mock.patch.object(watch, "inspect", side_effect=lambda kind, identifier: watch_net if kind == "network" else obj2), \
                     mock.patch.object(watch, "stop_owned") as stop:
                    watch.watch()
                self.assertTrue(watch.abort.is_set())
                stop.assert_called_once_with()
                self.assertEqual(watch.failures[0]["check"], "watchdog_zero_publication")
                self.assertNotIn("do-not-emit-this", json.dumps(watch.failures))

    def test_runtime_inspection_is_rechecked_after_start_before_fixtures(self):
        for label, path, value, reason in self.cases():
            if path[0] != "NetworkSettings":
                continue
            with self.subTest(case=label):
                example, runtime, item, net = self.configuration()
                example.image_id = runtime["Image"]
                before_start = copy.deepcopy(runtime)
                self.change(runtime, path, value)
                inspections = iter((before_start, runtime))
                with mock.patch.object(example, "create"), mock.patch.object(example, "journal"), \
                     mock.patch.object(example, "docker", return_value=(1, b"")), \
                     mock.patch.object(example, "inspect", side_effect=lambda kind, identifier: net if kind == "network" else next(inspections)), \
                     mock.patch.object(example, "query") as query, \
                     mock.patch.object(example, "verify_postgres") as verify:
                    with self.assertRaises(RuntimeError):
                        example.database("source")
                query.assert_not_called()
                verify.assert_not_called()
                self.assertEqual(example.checks[-1]["check"], "zero_published_ports")
                self.assertFalse(example.checks[-1]["passed"])
                self.assertEqual(example.binding_diagnostics[-1]["reason"], reason)

    def test_external_network_added_after_start_prevents_fixtures(self):
        example, runtime, item, net = self.configuration()
        example.image_id = runtime["Image"]
        before_start = copy.deepcopy(runtime)
        runtime["NetworkSettings"]["Networks"]["external"] = {"NetworkID": "other-network"}
        inspections = iter((before_start, runtime))
        with mock.patch.object(example, "create"), mock.patch.object(example, "journal"), \
             mock.patch.object(example, "docker", return_value=(1, b"")), \
             mock.patch.object(example, "inspect", side_effect=lambda kind, identifier: net if kind == "network" else next(inspections)), \
             mock.patch.object(example, "query") as query, \
             mock.patch.object(example, "verify_postgres") as verify:
            with self.assertRaises(RuntimeError):
                example.database("source")
        self.assertEqual(example.checks[-1]["check"], "only_owned_internal_network")
        self.assertFalse(example.checks[-1]["passed"])
        query.assert_not_called()
        verify.assert_not_called()

    def test_watchdog_accepts_only_the_valid_unpublished_owned_network(self):
        for configured in ({}, None):
            for runtime in ({}, {"5432/tcp": None}):
                example, obj, item, net = self.configuration()
                obj["HostConfig"]["PortBindings"] = configured
                obj["NetworkSettings"]["Ports"] = runtime
                example.owned, example.done = [item], mock.Mock()
                example.done.wait.side_effect = (False, True)
                with mock.patch.object(example, "sample"), \
                     mock.patch.object(example, "inspect", side_effect=lambda kind, identifier: net if kind == "network" else obj), \
                     mock.patch.object(example, "stop_owned") as stop:
                    example.watch()
                self.assertFalse(example.abort.is_set())
                self.assertEqual(example.failures, [])
                stop.assert_not_called()

    def test_network_must_remain_owned_internal_bridge_with_ipv6_disabled(self):
        for key, value in (("Name", "external"), ("Id", ""), ("Driver", "host"), ("Driver", None),
                           ("Internal", False), ("Internal", 1), ("EnableIPv6", True), ("EnableIPv6", None),
                           ("Labels", {}), ("Labels", {"synthetic.recovery": "other"})):
            with self.subTest(key=key, value=value):
                example, obj, item, net = self.configuration()
                net[key] = value
                self.assertFalse(recovery.internal_network_ok(net, item["network"], example.tag))
                self.assertFalse(recovery.isolated_network_ok(obj, item, net, example.tag))
        for key in ("Name", "Id", "Driver", "Internal", "EnableIPv6", "Labels"):
            example, obj, item, net = self.configuration()
            del net[key]
            self.assertFalse(recovery.internal_network_ok(net, item["network"], example.tag))
        for value in (None, [], "do-not-emit-this"):
            self.assertFalse(recovery.internal_network_ok(value, "synthetic-net", "synthetic-tag"))

    def test_container_rejects_external_or_malformed_network_attachment(self):
        for value in (None, [], {}, {"external": {}}, {"own": {}, "external": {}},
                      "do-not-emit-this"):
            example, obj, item, net = self.configuration()
            obj["NetworkSettings"]["Networks"] = value
            self.assertFalse(recovery.isolated_network_ok(obj, item, net, example.tag))
        for endpoint in (None, [], {}, {"NetworkID": "other"}, {"NetworkID": None}):
            example, obj, item, net = self.configuration()
            obj["NetworkSettings"]["Networks"] = {item["network"]: endpoint}
            self.assertFalse(recovery.isolated_network_ok(obj, item, net, example.tag))
        example, obj, item, net = self.configuration()
        self.assertTrue(recovery.isolated_network_ok(obj, item, net, example.tag))
        obj["NetworkSettings"]["Networks"]["external"] = {"NetworkID": "external"}
        self.assertFalse(recovery.isolated_network_ok(obj, item, net, example.tag))
        del obj["NetworkSettings"]["Networks"]["external"]
        item["network_id"] = "other"
        self.assertFalse(recovery.isolated_network_ok(obj, item, net, example.tag))

    def test_watchdog_stops_after_network_is_changed(self):
        for field, value in (("Internal", False), ("EnableIPv6", True), ("Labels", {})):
            example, obj, item, net = self.configuration()
            net[field] = value
            example.owned, example.done = [item], mock.Mock()
            example.done.wait.return_value = False
            with mock.patch.object(example, "sample"), \
                 mock.patch.object(example, "inspect", side_effect=lambda kind, identifier: net if kind == "network" else obj), \
                 mock.patch.object(example, "stop_owned") as stop:
                example.watch()
            self.assertTrue(example.abort.is_set())
            stop.assert_called_once_with()
            self.assertEqual(example.failures[0]["check"], "watchdog_owned_internal_network")

    def test_diagnostics_remain_sanitized_bounded_and_survive_final_report(self):
        example, obj, item, net = self.configuration()
        sentinel = "do-not-emit-this"
        obj["Config"].update(Env=[sentinel], Labels={sentinel: sentinel})
        obj["State"]["Error"] = sentinel
        obj["HostConfig"].update(Binds=[sentinel], NetworkMode=sentinel)
        obj["NetworkSettings"]["Ports"] = {sentinel: [{"HostIp": sentinel, "HostPort": sentinel, "extra": sentinel}]}
        net.update(Name=sentinel, IPAM={sentinel: sentinel}, Options={sentinel: sentinel})
        snapshot = recovery.binding_diagnostic(obj, item, net)
        self.assertNotIn(sentinel, json.dumps(snapshot))
        self.assertTrue(snapshot["network_internal"])
        obj["NetworkSettings"]["Ports"] = {str(p)+"/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25439"}]*20
                                           for p in range(1, 21)}
        bounded = recovery.binding_diagnostic(obj, item, net)["runtime"]
        self.assertEqual(bounded["count"], 20)
        self.assertEqual(len(bounded["entries"]), 8)
        self.assertTrue(all(len(v["bindings"]) == 8 and v["binding_count"] == 20 for v in bounded["entries"]))
        example.binding_diagnostics.append({"stage": example.stage, "origin": "main", **snapshot})
        case = Diagnostics()
        with mock.patch.object(case, "example", return_value=example):
            code, result, raw = case.report(failure="guard")
        self.assertEqual(code, 2)
        self.assertEqual(result["binding_diagnostics"], example.binding_diagnostics)
        self.assertNotIn(sentinel, raw)
        self.assertTrue(result["cleanup_verified"])

    def test_database_creation_has_no_host_port_and_retains_authentication(self):
        example, obj, item, net = self.configuration()
        example.image_id = obj["Image"]
        example.abort = mock.Mock()
        example.abort.wait.return_value = False
        limits = (str(recovery.MEMORY)+"\n0\n100000 100000\n128\n").encode()
        def docker(*args, **options):
            if args[:2] == ("container", "inspect"):
                return 1, b""
            if args[0] == "exec" and "sh" in args:
                return 0, limits
            return 0, b""
        with mock.patch.object(example, "create") as create, mock.patch.object(example, "journal"), \
             mock.patch.object(example, "docker", side_effect=docker) as command, \
             mock.patch.object(example, "inspect", side_effect=lambda kind, identifier: net if kind == "network" else obj), \
             mock.patch.object(example, "sample"), mock.patch.object(example, "verify_postgres") as verify, \
             mock.patch.object(example, "query") as query, \
             mock.patch.object(recovery.secrets, "token_urlsafe", return_value="unused-synthetic-value"):
            returned = example.database("source")
        creates = [call.args for call in command.call_args_list if call.args[0] == "create"]
        self.assertEqual(len(creates), 1)
        args = creates[0]
        self.assertNotIn("--publish", args)
        self.assertNotIn("-p", args)
        self.assertNotIn("-P", args)
        self.assertNotIn("--publish-all", args)
        self.assertIn("listen_addresses=127.0.0.1", args)
        self.assertIn("password_encryption=scram-sha-256", args)
        self.assertIn("POSTGRES_HOST_AUTH_METHOD=scram-sha-256", args)
        self.assertIn("POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256", args)
        self.assertIn("--internal", create.call_args_list[0].args[2])
        self.assertNotIn("port", returned)
        verify.assert_called_once_with(returned)
        query.assert_called_once_with(returned, "postgres", "CREATE DATABASE specimen;")
        self.assertEqual(example.abort.wait.call_count, 30)


class PostgresAuthentication(unittest.TestCase):
    def expected(self):
        return ["127.0.0.1", "127.0.0.1", 5432, "postgres", "postgres", "scram-sha-256", True, True, True]

    def verify(self, result=None, negative=(2, b"")):
        example = Diagnostics().example()
        item = {"id": "synthetic-container"}
        example.passwords[item["id"]] = "unused-synthetic-value"
        result = self.expected() if result is None else result
        output = json.dumps(result).encode()
        with mock.patch.object(example, "query", return_value=(0, output)) as query, \
             mock.patch.object(example, "docker", return_value=negative) as docker, \
             mock.patch.object(recovery.secrets, "token_urlsafe", return_value="unused-incorrect-value"):
            example.verify_postgres(item)
        return example, query, docker

    def test_effective_loopback_tcp_connection_and_scram_are_all_checked(self):
        example, query, docker = self.verify()
        self.assertEqual([row["check"] for row in example.checks],
                         ["postgres_settings_readable", "postgres_loopback_listening", "authenticated_sql_connection",
                          "scram_authentication_required", "incorrect_password_rejected"])
        self.assertTrue(all(row["passed"] for row in example.checks))
        sql = query.call_args.args[2]
        for token in ("listen_addresses", "host(inet_server_addr())", "inet_server_port", "password_encryption",
                      "pg_hba_file_rules", "rolpassword"):
            self.assertIn(token, sql)
        probe = docker.call_args.args
        self.assertEqual(probe[0], "exec")
        self.assertIn("psql", probe)
        self.assertIn("127.0.0.1", probe)
        self.assertTrue(docker.call_args.kwargs["failure_ok"])
        self.assertEqual(docker.call_args.kwargs["extra"]["PGPASSWORD"], "unused-synthetic-value-invalid")
        self.assertNotIn("unused-synthetic-value", json.dumps(example.checks+example.failures))

    def test_unrestricted_listening_socket_connection_or_non_scram_are_rejected(self):
        changes = [(0, "*"), (0, "0.0.0.0"), (0, "::"), (0, "localhost"),
                   (1, None), (1, "0.0.0.0"), (1, "::1"), (2, 25439), (2, True),
                   (3, "other"), (4, "other"), (5, "md5"), (6, False), (7, False), (8, False),
                   (6, None), (7, None), (8, None), (6, 1), (7, 1), (8, 1)]
        for index, value in changes:
            with self.subTest(index=index, value=value):
                result = self.expected()
                result[index] = value
                with self.assertRaises(RuntimeError):
                    self.verify(result)

    def test_wrong_password_must_fail_and_return_no_partial_output(self):
        for negative in ((0, b""), (0, b"1\n"), (1, b""), (3, b""), (2, b"partial-output")):
            with self.subTest(exit_code=negative[0]):
                with self.assertRaises(RuntimeError):
                    self.verify(negative=negative)

    def test_malformed_postgres_settings_are_rejected(self):
        for result in ({}, "do-not-emit-this", [], self.expected()[:-1], self.expected()+[True]):
            with self.subTest(kind=type(result).__name__):
                with self.assertRaises(RuntimeError):
                    self.verify(result)

    def test_malformed_authenticated_sql_output_is_rejected_and_not_logged(self):
        example = Diagnostics().example()
        sentinel = "do-not-emit-this"
        with mock.patch.object(example, "query", return_value=(0, sentinel.encode())), \
             mock.patch.object(example, "docker") as docker:
            with self.assertRaises(json.JSONDecodeError) as caught:
                example.verify_postgres({"id": "synthetic"})
        example.record_failure(caught.exception)
        self.assertEqual(example.failures[0]["category"], "INVALID_OUTPUT")
        self.assertNotIn(sentinel, json.dumps(example.failures))
        docker.assert_not_called()

    def test_failed_authentication_verification_prevents_database_creation(self):
        case = ZeroPublication()
        example, obj, item, net = case.configuration()
        example.image_id = obj["Image"]
        example.abort = mock.Mock()
        example.abort.wait.return_value = False
        limits = (str(recovery.MEMORY)+"\n0\n100000 100000\n128\n").encode()
        def docker(*args, **options):
            if args[:2] == ("container", "inspect"):
                return 1, b""
            if args[0] == "exec" and "sh" in args:
                return 0, limits
            return 0, b""
        with mock.patch.object(example, "create"), mock.patch.object(example, "journal"), \
             mock.patch.object(example, "docker", side_effect=docker), \
             mock.patch.object(example, "inspect", side_effect=lambda kind, identifier: net if kind == "network" else obj), \
             mock.patch.object(example, "sample"), \
             mock.patch.object(example, "verify_postgres", side_effect=RuntimeError("SAFETY_CHECK_FAILED")), \
             mock.patch.object(example, "query") as query:
            with self.assertRaisesRegex(RuntimeError, "SAFETY_CHECK_FAILED"):
                example.database("source")
        query.assert_not_called()


if __name__ == "__main__":
    unittest.main()


