"""Offline guard tests. No Docker, downloads, keys, SQL, or cloud operations."""
import copy
import json
import unittest

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


if __name__ == "__main__":
    unittest.main()
