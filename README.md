# Synthetic PostgreSQL recovery example

**Synthetic recovery example. Source publication alone is not recovery evidence;
use the corresponding workflow run for actual execution results.**

This independent example contains no application source, application migrations,
designs, private snapshots, stored credentials, production connections, or real
customer data. It is not a backup service or evidence of application recovery.
Do not add real data, repository secrets, external account credentials, or artifacts.

## Intended demonstration

Only after separate execution approval, the example would create a tiny PostgreSQL
17 source with two synthetic organizations, three rows, integer minor units,
Unicode text, constraints, an index, an identity sequence, three non-login roles,
grants, and forced row-level security. It would:

1. Verify resource capacity before fetching code or dependencies.
2. Verify the public age 1.3.2 binary using its SHA-256 and the publisher's Sigsum
   proof. Reject a damaged binary before trusting it. Verify a digest-pinned
   official PostgreSQL image and its platform and size before use.
3. Create the source only after inspecting effective isolation and limits.
4. Capture real `pg_dump` SQL and selected `pg_dumpall` role definitions.
5. Encrypt an integrity-checked bundle using a newly generated disposable age key.
6. Reject an incorrect key, damaged/truncated ciphertext, malformed bundles,
   failed producers, and failed SQL. Never pipe partial decryption into a database.
7. Stop and verify the source before starting a separate, empty target.
8. Restore roles, schema, rows, owners, grants, policies, constraints, indexes,
   sequence state, and Unicode text; compare the recovered catalog exactly.
9. Verify synthetic role visibility, cross-organization denial, write denial,
   integer totals and constraint enforcement. Verify failed transactional restores
   leave neither partial schema nor partial roles.
10. Remove only positively identified owned resources and compare the remaining
    Docker resources with the original inventory. Accept only completed recovery
    **and** verified cleanup.

RLS checks use `SET ROLE` to non-superuser roles. They do not simulate a browser,
an identity provider, a signed session, or a real multi-tenant application's policy.
The three-row total checks integer preservation, not a financial reconciliation system.

## Unchanged resource gates

| Control | Requirement |
| --- | --- |
| Runner | Standard public `ubuntu-24.04`, Linux x64; no larger or self-hosted runner |
| CPU | At least four host and Docker-engine CPUs |
| RAM before downloads and again before tools | At least 15 GiB total and 6 GiB available |
| RAM during execution | Stop on a measured value below 4 GiB |
| Initial disk | At least 18 GiB free on every relevant filesystem |
| Disk stop margins | Stop at less than 10.5 GiB free or growth of 7.5 GiB; hard objectives remain 10 GiB and 8 GiB |
| Database | One active container at a time; 768 MiB memory and equal memory+swap limit, one CPU, 128 PIDs, 64 MiB shared memory |
| Ports | Only `127.0.0.1:25439:5432/tcp` and `127.0.0.1:25440:5432/tcp`, used sequentially |
| Networks | Separate labeled internal bridges, no host networking; explicit publish binding is also required |
| Storage | Separate labeled source/target volumes; no host directory mounts |
| Work deadline | 45 minutes from the initial capacity step, including downloads |
| Cleanup deadline | At most 270 seconds, ending by minute 51 |
| Independent outer timeout | One job, 60 minutes; no automatic retry, matrix, or scheduled trigger |

The watchdog samples memory, disk, Docker limits, running containers, published
bindings and OOM status every second. It terminates the current owned command and
requests owned database stops if a check fails. Sampling cannot guarantee that a
brief resource excursion is impossible; the stop margins reduce this risk.
No existing packages, images, caches or Docker resources are deleted to gain space.

A conservative incremental budget is approximately 6.8 GiB: 4 GiB for the selected
image, 0.4 GiB for compressed layers, 1.5 GiB for isolated Go module/build caches,
0.6 GiB for both tiny database volumes, and 0.3 GiB for tools, checkout and temporary
buffers. These are planning allowances, not measured results. Growth monitoring
aborts if an allowance is exceeded in aggregate; oversized image metadata is
rejected before pulling. No real backup size is inferred from these tiny fixtures.

## Capacity and cost limitation

GitHub documents the standard public Ubuntu runner as four CPUs, 16 GB RAM and
**14 GB SSD storage**. That does **not** guarantee the required 18 GiB free space.
The first inline step therefore aborts before checkout, downloads, keys, fixtures
or databases if capacity is insufficient. No threshold reduction, automatic paid
upgrade, disk-clearing trick or private-runner fallback is implemented.

GitHub states standard public runners are free. The example selects only that
runner class, requires a public manual event by the repository owner, grants no
token permissions, and fetches its exact public commit anonymously. It uses no
paid API, larger runner, artifact upload, package publication, prebuild or Codespace.
Actual capacity, image availability, anonymous registry rate limits and dependency
verification remain untested. A capacity failure would be a blocked test, not success.

## Execution and cleanup boundaries

The only trigger is `workflow_dispatch` on `main`, by the repository owner, first
attempt only, with explicit `SYNTHETIC_ONLY` approval. Only the five reviewed files
are fetched, with exact commit verification. The workflow has no third-party
actions or authenticated checkout; its initial gate is embedded inline so that it
can run without a preceding download. Workflow JSON is valid YAML; the `.yml` file
intentionally uses JSON syntax to permit dependency-free static inspection.

Subprocesses receive a minimal environment. Disposable database passwords and age
private keys are generated only during an approved run. They are not printed or
saved to ordinary key files. The private identity is supplied through an anonymous
Linux memory file. Core dumps are disabled. Database passwords exist transiently
in owned container metadata, and plaintext fixture data exists in owned volumes
and process memory. Memory may be paged by the host; Python cannot promise secure
erasure. These limitations are acceptable only for disposable synthetic data.

Only sanitized check results, timings and aggregate resource measurements are
printed. No raw command output, SQL, backups, identities or credentials are uploaded.
Deletion is scoped by fresh IDs, ownership labels and the current run's randomly
named temporary directory. Global prune, forced volume removal and broad host
cleanup are absent. Data deletion is not a guarantee of physical secure erasure.

Signal handling and the local watchdog attempt bounded cleanup on normal failures
and cancellation. GitHub's independent timeout destroys the hosted job environment
if the process becomes unresponsive. Forced runner termination may prevent cleanup
verification: that outcome must remain incomplete, never accepted as successful
recovery. Provider shutdown timing cannot be guaranteed by guest code.

## Review and future approval

The publication set is exactly:

- `.github/workflows/recovery.yml`
- `preflight.py`
- `recovery.py`
- `test_recovery.py`
- `README.md`

Review notes, local credential helpers and publication manifests belong outside
this set. Local static parsing is not an executed recovery
test. All seven offline guard tests passed locally; they exercise only pure
validation functions and do not generate keys, start Docker, access networks or
create databases. Do not publish or execute the draft without separate approval.

Even a successful future run cannot verify any application's migrations, stored
procedures, authorization, subscription restrictions, financial invariants,
authentication, MFA, sessions, hosted encryption, provider-managed backups, email
delivery or production recovery. Those require separate authorized verification
before real customer data is admitted.

## Public technical sources

- [GitHub runner specifications and public-runner pricing](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub workflow timeout syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes)
- [GitHub cancellation behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation)
- [PostgreSQL 17 dump](https://www.postgresql.org/docs/17/app-pgdump.html)
- [PostgreSQL 17 role backup](https://www.postgresql.org/docs/17/app-pg-dumpall.html)
- [PostgreSQL 17 transactional psql restore](https://www.postgresql.org/docs/17/app-psql.html)
- [Official PostgreSQL container](https://hub.docker.com/_/postgres)
- [age 1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2)
- [age publisher verification instructions](https://github.com/FiloSottile/age/blob/v1.3.2/SIGSUM.md)
