"""verify_auth.py — walk the five credential/state-machine paths.

Scenarios:
  1. pkl 读取         (no toml -> source pkl, login reads pkl truth)
  2. 迁移成功          (first login -> atomic toml v1; second login reuses)
  3. 错口令            (wrong captcha and wrong password share one message)
  4. 损坏回退          (corrupt / missing-key toml -> pkl kept, fallback state)
  5. 中断重试          (fault leaves .tmp; retry -> toml v1)
Plus: concurrent first login (only one process migrates, others reuse)
and an HTTP smoke test against uvicorn app:app.

Exit code is non-zero if any check fails.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORRECT_USER = "pparker"
CORRECT_PW = "abc123"
GENERIC = "验证码或用户名/口令不正确，请重试"

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    results.append((PASS if ok else FAIL, name, detail))
    print(f"[{PASS if ok else FAIL}] {name}" + (f" -- {detail}" if detail else ""))


def fresh_setup(tmp: Path, *, toml: Path | None = None, fault: str = "", delay: str = ""):
    """Rebuild the auth package under an isolated AUTH_CONFIG_DIR."""
    sys.path.insert(0, str(ROOT))
    for mod in list(sys.modules):
        if mod == "auth" or mod.startswith("auth."):
            del sys.modules[mod]
    os.environ["AUTH_CONFIG_DIR"] = str(tmp)
    os.environ["AUTH_PKL_PATH"] = str(tmp / "seed.pkl")
    if fault:
        os.environ["AUTH_FAULT"] = fault
    else:
        os.environ.pop("AUTH_FAULT", None)
    if delay:
        os.environ["AUTH_MIGRATE_DELAY"] = delay
    else:
        os.environ.pop("AUTH_MIGRATE_DELAY", None)
    shutil.copyfile(ROOT / "hashed_pw.pkl", tmp / "seed.pkl")
    if toml is not None:
        (tmp / "credentials.toml").write_bytes(toml.read_bytes())
    import auth.service
    from auth.store import reset_store

    reset_store()
    auth.service.reset_board()
    return auth.service


def solved_captcha(auth_mod) -> tuple[str, str]:
    challenge = auth_mod.captcha_challenge()
    return challenge["token"], challenge["answer"]


def login(auth_mod, username, password, *, captcha_ok=True):
    token, answer = solved_captcha(auth_mod)
    guess = answer if captcha_ok else "ZZZZ"
    return auth_mod.check_login(username, password, token, guess)


def board_done_steps(auth_mod):
    return [s["key"] for s in auth_mod.status()["steps"]
            if s["status"] in ("done", "active", "failed")]


def scenario_1_pkl_read(tmp: Path):
    print("\n== 路径 1: pkl 读取 ==")
    auth_mod = fresh_setup(tmp)
    creds = auth_mod.credentials()
    record("无 toml 时来源为 pkl", creds["source"] == "pkl", creds["source"])
    record("仅暴露公开用户名，不泄漏哈希",
           "hash_pw" not in str(creds["users"]["pparker"]))
    result = login(auth_mod, CORRECT_USER, CORRECT_PW)
    record("凭 pkl 凭据校验通过", result["ok"], auth_mod.status()["state"])


def scenario_2_migration(tmp: Path):
    print("\n== 路径 2: 迁移成功（临时文件 + os.replace）==")
    toml = tmp / "credentials.toml"
    record("首次登录后生成 credentials.toml", toml.exists())
    import tomllib

    data = tomllib.load(toml.open("rb"))
    record("toml 带版本号 version=1", data.get("version") == 1, str(data.get("version")))
    users = data.get("credentials", {}).get("users", {})
    record("明文用户名配哈希口令",
           set(users) == {"pparker", "rmiller"} and users["pparker"]["hash_pw"].startswith("$2"))
    record("无残留临时文件", not list(tmp.glob("*.tmp")))
    record("pkl 只读、字节未改动",
           (tmp / "seed.pkl").read_bytes() == (ROOT / "hashed_pw.pkl").read_bytes())

    auth_mod = fresh_setup(tmp)
    creds = auth_mod.credentials()
    record("重载后唯一真值切到 toml", creds["source"] == "toml" and creds["single_truth"])
    result = login(auth_mod, CORRECT_USER, CORRECT_PW)
    record("再次登录复用 toml，无第二次迁移",
           result["ok"] and auth_mod.status()["version"] == 1)
    record("状态条逐条翻牌",
           board_done_steps(auth_mod) == ["unverified", "checking", "authenticated"])


def scenario_3_wrong_password(tmp: Path):
    print("\n== 路径 3: 错口令 / 错验证码 / 未知用户，同一句提示 ==")
    auth_mod = fresh_setup(tmp)
    bad_pw = login(auth_mod, CORRECT_USER, "wrong-password")
    record("错口令拒绝", not bad_pw["ok"])
    record("错口令对外提示统一", bad_pw["error"] == GENERIC, bad_pw["error"])
    bad_cap = login(auth_mod, CORRECT_USER, CORRECT_PW, captcha_ok=False)
    record("错验证码拒绝", not bad_cap["ok"])
    record("错验证码同一句提示", bad_cap["error"] == GENERIC)
    token, answer = solved_captcha(auth_mod)
    bad_user = auth_mod.check_login("nobody", "x", token, answer)
    record("未知用户同一句提示", not bad_user["ok"] and bad_user["error"] == GENERIC)
    record("失败后停留在未认证", auth_mod.status()["state"] == "unverified")
    record("失败不触发迁移", not (tmp / "credentials.toml").exists())


def scenario_4_corrupt_fallback(tmp: Path):
    print("\n== 路径 4: 损坏/缺键回退，原文件保留 ==")
    corrupt = tmp / "corrupt.toml"
    corrupt.write_text("version = 1\n[credentials.users\nthis is = = broken", encoding="utf-8")
    auth_mod = fresh_setup(tmp, toml=corrupt)
    creds = auth_mod.credentials()
    record("损坏 toml -> 回退 pkl", creds["source"] == "pkl", str(creds["fallback_reason"]))
    record("损坏文件原样保留", (tmp / "credentials.toml").read_bytes() == corrupt.read_bytes())

    missing = tmp / "missing.toml"
    missing.write_text('version = 1\n[credentials.users]\nfoo = "bar"\n', encoding="utf-8")
    auth_mod = fresh_setup(tmp, toml=missing)
    record("缺键 toml -> 回退 pkl", auth_mod.credentials()["source"] == "pkl")
    result = login(auth_mod, CORRECT_USER, CORRECT_PW)
    board = auth_mod.status()
    record("迁移尝试后进入回退态", board["state"] == "fallback" and result.get("degraded"))
    record("状态条翻到「回退」失败牌",
           any(s["status"] == "failed" and s["key"] == "fallback" for s in board["steps"]))
    record("失败原因可识别", "toml" in board["failure"])
    record("缺键原文件未被覆盖", (tmp / "credentials.toml").read_bytes() == missing.read_bytes())
    record("仍可校验口令（pkl 真值可用）", login(auth_mod, CORRECT_USER, CORRECT_PW)["ok"])


def scenario_5_interrupt_retry(tmp: Path):
    print("\n== 路径 5: 写入中断 -> 原地重试成功 ==")
    auth_mod = fresh_setup(tmp, fault="interrupt_after_tmp")
    result = login(auth_mod, CORRECT_USER, CORRECT_PW)
    board = auth_mod.status()
    record("中断 -> 回退态（登录结果降级）", board["state"] == "fallback" and result.get("degraded"))
    tmps = list(tmp.glob("credentials.toml.*.tmp"))
    record("临时文件保留在盘", len(tmps) == 1, str([t.name for t in tmps]))
    record("正式 toml 未生成，真值不丢", not (tmp / "credentials.toml").exists())
    record("失败原因为写入中断", "中断" in board["failure"])

    os.environ.pop("AUTH_FAULT", None)
    board2 = auth_mod.retry_migration()
    record("原地重试 -> 已认证", board2["state"] == "authenticated", board2["state"])
    record("重试产出 toml v1",
           (tmp / "credentials.toml").exists() and board2["version"] == 1)
    record("os.replace 消化临时文件", not list(tmp.glob("*.tmp")))
    import tomllib

    data = tomllib.load((tmp / "credentials.toml").open("rb"))
    record("重试结果即唯一真值",
           data["version"] == 1 and "pparker" in data["credentials"]["users"])


def _migrate_worker(cfg_dir: str, pkl_path: str, delay: str, q):
    os.environ["AUTH_CONFIG_DIR"] = cfg_dir
    os.environ["AUTH_PKL_PATH"] = pkl_path
    os.environ["AUTH_MIGRATE_DELAY"] = delay
    sys.path.insert(0, str(ROOT))
    for mod in list(sys.modules):
        if mod == "auth" or mod.startswith("auth."):
            del sys.modules[mod]
    import auth.service
    from auth.store import reset_store

    reset_store()
    challenge = auth.service.captcha_challenge()
    result = auth.service.check_login(CORRECT_USER, CORRECT_PW,
                                      challenge["token"], challenge["answer"])
    q.put({"ok": result["ok"], "migration": auth.service.status()["migration"],
           "state": auth.service.status()["state"]})


def scenario_concurrent(tmp: Path):
    print("\n== 并发首次登录：一个进程迁移，其余复用 ==")
    conc = tmp / "conc"
    conc.mkdir()
    shutil.copyfile(ROOT / "hashed_pw.pkl", conc / "seed.pkl")
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    procs = [
        ctx.Process(target=_migrate_worker,
                    args=(str(conc), str(conc / "seed.pkl"), "1.5" if i == 0 else "0", q))
        for i in range(3)
    ]
    for i, proc in enumerate(procs):
        proc.start()
        time.sleep(0.2)
    outcomes = [q.get(timeout=60) for _ in procs]
    for proc in procs:
        proc.join(timeout=60)
    migrated = sum(1 for o in outcomes if o["migration"].startswith("已迁移"))
    reused = sum(1 for o in outcomes if o["migration"].startswith("复用"))
    record("三进程全部认证成功",
           all(o["ok"] and o["state"] == "authenticated" for o in outcomes),
            str([(o["ok"], o["state"]) for o in outcomes]))
    record("恰有一个进程完成迁移", migrated == 1, f"migrated={migrated}")
    record("其余两个复用其结果（版本号判定）", reused == 2, f"reused={reused}")
    import tomllib

    data = tomllib.load((conc / "credentials.toml").open("rb"))
    record("只有一份真值 toml v1，无临时文件残留",
           data["version"] == 1 and not list(conc.glob("*.tmp")))


def scenario_http(tmp: Path):
    print("\n== HTTP 冒烟：uvicorn app:app 页面与凭据来源 ==")
    web = tmp / "web"
    web.mkdir()
    env = dict(os.environ)
    env["AUTH_CONFIG_DIR"] = str(web)
    env["AUTH_PKL_PATH"] = str(ROOT / "hashed_pw.pkl")
    env.pop("AUTH_FAULT", None)
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app", "--port", str(port)],
        cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        import urllib.request

        html = ""
        for _ in range(80):
            try:
                html = urllib.request.urlopen(base + "/", timeout=2).read().decode()
                break
            except OSError:
                time.sleep(0.5)
        record("GET / 返回登录页", 'name="username"' in html)
        record("顶部状态条显示「未认证」翻牌", "未认证" in html)
        record("状态条对照凭据来源 hashed_pw.pkl", "hashed_pw.pkl" in html)
        raw = urllib.request.urlopen(base + "/auth/status", timeout=2).read().decode()
        compact = raw.replace(" ", "").replace("\n", "")
        record("/auth/status 返回 pkl 来源与五步", '"source":"pkl"' in compact and '"fallback"' in compact)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="auth-verify-"))
    print(f"隔离工作目录: {work}")
    try:
        d12 = work / "s12"; d12.mkdir()
        d3 = work / "s3"; d3.mkdir()
        d4 = work / "s4"; d4.mkdir()
        d5 = work / "s5"; d5.mkdir()
        scenario_1_pkl_read(d12)
        scenario_2_migration(d12)
        scenario_3_wrong_password(d3)
        scenario_4_corrupt_fallback(d4)
        scenario_5_interrupt_retry(d5)
        scenario_concurrent(work)
        scenario_http(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n================ 汇总 ================")
    failed = [r for r in results if r[0] == FAIL]
    for status_name, name, detail in results:
        line = f"  [{status_name}] {name}"
        if status_name == FAIL and detail:
            line += f"  {detail}"
        print(line)
    print(f"\n共 {len(results)} 项，失败 {len(failed)} 项")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
