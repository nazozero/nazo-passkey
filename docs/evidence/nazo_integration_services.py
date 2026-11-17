#!/usr/bin/env python3
"""Run the scoped NazoAuth passkey/MFA regression against task-owned services."""
from pathlib import Path
import hashlib, json, os, re, socket, subprocess, sys, time
ROOT = Path(__file__).resolve().parent
REPO = ROOT / "NazoAuth"
RUNTIME = ROOT / "nazo-test-runtime"
RUNTIME.mkdir(exist_ok=True)
PG = ROOT / "postgresql-runtime" / "bin"
VK = ROOT / "valkey-build" / "src"
ENV = os.environ.copy()
ENV.update({
    "RUSTUP_HOME": str(ROOT / "rustup"),
    "PATH": "/home/agent/.cargo/bin:" + str(PG) + ":" + ENV["PATH"],
    "CARGO_BUILD_JOBS": "1", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_INCREMENTAL": "0",
    "TZ": "UTC", "CI": "true", "RUST_TEST_THREADS": "1", "CARGO_TERM_COLOR": "never",
    "DATABASE_URL": "postgresql://postgres@127.0.0.1:55432/oauth",
    "NAZO_TEST_DATABASE_URL": "postgresql://postgres@127.0.0.1:55432/oauth",
    "NAZO_AUDIT_TEST_DATABASE_URL": "postgresql://postgres@127.0.0.1:55432/nazo_audit_test",
    "VALKEY_URL": "redis://127.0.0.1:56379/0",
    "NAZO_TEST_VALKEY_URL": "redis://127.0.0.1:56379/0",
    "VALKEY_STATE_EPOCH": "019c8ca2-30a6-7000-8000-00000000e102",
    "VALKEY_COMMAND_TIMEOUT_MS": "1000", "BIND": "127.0.0.1:18000",
    "ISSUER": "http://127.0.0.1:18000", "MTLS_ENDPOINT_BASE_URL": "http://127.0.0.1:18000",
    "FRONTEND_BASE_URL": "http://127.0.0.1:3000", "CORS_ALLOWED_ORIGINS": "http://127.0.0.1:3000",
    "COOKIE_SECURE": "false", "SESSION_COOKIE_NAME": "nazo_oauth_session", "CSRF_COOKIE_NAME": "nazo_oauth_csrf",
    "EMAIL_DELIVERY": "disabled", "EMAIL_CODE_DEV_RESPONSE_ENABLED": "false",
    "AVATAR_STORAGE_DIR": str(RUNTIME / "avatars"), "SIGNING_KEY_ENCRYPTION_KEY_ID": "task-test-root",
    "SIGNING_KEY_ENCRYPTION_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "REQUIRE_PUSHED_AUTHORIZATION_REQUESTS": "false",
})
COMMANDS = [
    ("identity-unit", ["cargo", "test", "-p", "nazo-identity", "--lib"]),
    ("identity-authentication-contracts", ["cargo", "test", "-p", "nazo-identity", "--test", "policy", "--test", "authentication_method_authority", "--test", "password_authentication", "--test", "federation_authentication"]),
    ("postgres-passkey-jsonb", ["cargo", "test", "-p", "nazo-postgres", "--lib", "passkey"]),
    ("postgres-migrations", ["cargo", "test", "-p", "nazo-postgres", "--test", "migrations", "pending_migrations_create_all_runtime_module_state_tables"]),
    ("postgres-passkey-cas", ["cargo", "test", "-p", "nazo-postgres", "--test", "identity_repositories", "passkey"]),
    ("postgres-mfa", ["cargo", "test", "-p", "nazo-postgres", "--test", "identity_repositories", "mfa"]),
    ("postgres-totp", ["cargo", "test", "-p", "nazo-postgres", "--test", "identity_repositories", "totp"]),
    ("postgres-passkey-audit", ["cargo", "test", "-p", "nazo-postgres", "--test", "audit_commit_boundary", "identity_mutations_and_required_audit_share_the_commit_boundary"]),
    ("valkey-passkey", ["cargo", "test", "-p", "nazo-valkey", "--test", "remaining_contract", "passkey"]),
    ("valkey-session", ["cargo", "test", "-p", "nazo-valkey", "--test", "session_contract"]),
    ("valkey-authentication-state", ["cargo", "test", "-p", "nazo-valkey", "--test", "remaining_contract", "authentication_short_state"]),
    ("valkey-login-session", ["cargo", "test", "-p", "nazo-valkey", "--test", "remaining_contract", "login_session"]),
    ("valkey-mfa", ["cargo", "test", "-p", "nazo-valkey", "--test", "remaining_contract", "mfa_failure"]),
    ("http-passkey", ["cargo", "test", "-p", "nazoauth", "--lib", "passkey"]),
    ("http-mfa", ["cargo", "test", "-p", "nazoauth", "--lib", "mfa"]),
    ("http-configuration", ["cargo", "test", "-p", "nazoauth", "--lib", "config"]),
    ("server-passkey", ["cargo", "test", "-p", "nazo-server", "--lib", "passkey"]),
    ("server-mfa", ["cargo", "test", "-p", "nazo-server", "--lib", "mfa"]),
    ("server-settings", ["cargo", "test", "-p", "nazo-server", "--lib", "settings"]),
    ("server-all-targets-build", ["cargo", "test", "-p", "nazo-server", "--all-targets", "--all-features", "--no-run", "--locked"]),
    ("native-http-adapter", ["cargo", "test", "-p", "nazo-http-actix", "--lib"]),
    ("native-direct-tls", ["cargo", "test", "-p", "nazo-server", "--lib", "direct_tls_serves_real_https_and_mtls_without_trusting_forged_headers"]),
    ("identity-application-session", ["cargo", "test", "-p", "nazo-oauth-server", "--lib", "session"]),
    ("http-session", ["cargo", "test", "-p", "nazoauth", "--lib", "session"]),
    ("server-session", ["cargo", "test", "-p", "nazo-server", "--lib", "session"]),
    ("native-check", ["cargo", "check", "--locked", "--all-features", "-p", "nazo-identity", "-p", "nazo-postgres", "-p", "nazo-oauth-server", "-p", "nazoauth", "-p", "nazo-server"]),
    ("native-clippy", ["cargo", "clippy", "--locked", "--all-targets", "--all-features", "--keep-going", "-p", "nazo-identity", "-p", "nazo-postgres", "-p", "nazo-oauth-server", "-p", "nazoauth", "-p", "nazo-server", "--", "-D", "warnings"]),
    ("portable-passkey-consumers", ["python3", "-c", "import sys; sys.path.insert(0, 'scripts'); import check_wasm_portability as checks; checks.check(('nazo-identity', 'nazo-oauth-server', 'nazoauth'))"]),
]
selected = set(sys.argv[1:])
if selected:
    known = {name for name, _ in COMMANDS}
    if not selected <= known:
        raise SystemExit(f"Unknown groups: {selected - known}")
    COMMANDS = [(n, c) for n, c in COMMANDS if n in selected]
for port in (55432, 56379):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", port))
if not (RUNTIME / "pgdata" / "PG_VERSION").exists():
    with (RUNTIME / "initdb.log").open("w") as log:
        subprocess.run([str(PG / "initdb"), "-D", str(RUNTIME / "pgdata"), "-U", "postgres", "--auth=trust", "--no-locale", "--encoding=UTF8"], stdout=log, stderr=subprocess.STDOUT, check=True)
processes, logs = [], []
results_path = ROOT / "nazo-integration-results.json"
results = json.loads(results_path.read_text()) if results_path.exists() else []
source_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
source_diff_sha256 = hashlib.sha256(subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=REPO)).hexdigest()
passkey_revision = re.search(r'passkey-auth = \{ git = "https://github.com/nazozero/passkey-auth-rs", rev = "([0-9a-f]{40})"', (REPO / "Cargo.toml").read_text()).group(1)
try:
    for name, command in [
        ("postgres", [str(PG / "postgres"), "-D", str(RUNTIME / "pgdata"), "-h", "127.0.0.1", "-p", "55432", "-k", "", "-c", "max_connections=40", "-c", "shared_buffers=64MB"]),
        ("valkey", [str(VK / "valkey-server"), "--bind", "127.0.0.1", "--port", "56379", "--save", "", "--appendonly", "no", "--dir", str(RUNTIME), "--protected-mode", "yes"]),
    ]:
        log = (RUNTIME / f"{name}.log").open("a")
        logs.append(log)
        processes.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=ENV))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("Test service exited during startup; inspect runtime logs")
        pg_ready = subprocess.run([str(PG / "pg_isready"), "-h", "127.0.0.1", "-p", "55432", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        vk_ready = subprocess.run([str(VK / "valkey-cli"), "-p", "56379", "ping"], capture_output=True).stdout.strip() == b"PONG"
        if pg_ready and vk_ready:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("Test services did not become ready")
    for database in ("oauth", "nazo_audit_test"):
        existing = subprocess.run([str(PG / "psql"), "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", "-d", "postgres", "-At", "-c", f"SELECT 1 FROM pg_database WHERE datname='{database}'"], check=True, capture_output=True).stdout.strip()
        if not existing:
            subprocess.run([str(PG / "createdb"), "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", database], check=True)
    for name, command in COMMANDS:
        pause = ROOT / "nazo-pause-requested"
        ready = ROOT / "nazo-pause-ready"
        while pause.exists():
            ready.write_text(name + "\n")
            time.sleep(0.25)
        ready.unlink(missing_ok=True)
        started = time.monotonic()
        path = ROOT / f"nazo-{name}-{len(results) + 1:02d}.log"
        print(f"START {name}: {' '.join(command)}", flush=True)
        with path.open("w") as log:
            result = subprocess.run(command, cwd=REPO, env=ENV, stdout=log, stderr=subprocess.STDOUT)
        summaries = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored", path.read_text())
        passed = sum(int(row[1]) for row in summaries)
        failed = sum(int(row[2]) for row in summaries)
        ignored = sum(int(row[3]) for row in summaries)
        record = {"name": name, "command": command, "exit_code": result.returncode, "passed": passed, "failed": failed, "ignored": ignored, "seconds": round(time.monotonic() - started, 3), "log": str(path), "source_head": source_head, "source_diff_sha256": source_diff_sha256, "passkey_revision": passkey_revision}
        results.append(record)
        results_path.write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(record), flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)
        if command[1] == "test" and "--no-run" not in command and passed + failed == 0:
            raise SystemExit("No executed tests matched this required group")
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in reversed(processes):
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    for log in logs:
        log.close()
