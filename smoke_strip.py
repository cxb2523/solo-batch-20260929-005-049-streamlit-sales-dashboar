from pathlib import Path
import shutil, sys
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
shutil.rmtree(ROOT / "config", ignore_errors=True)

at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
at.run()

def submit(user, pw, cap=None):
    answer = at.session_state["login_captcha_answer"] if cap is None else cap
    at.text_input[0].input(user).run()
    at.text_input[1].input(pw).run()
    at.text_input[2].input(answer).run()
    at.button[0].click().run()

submit("pparker", "abc123")
last = at.session_state["login_last_result"]
print("status:", last.status, "| source:", last.source)
for s in last.stages:
    print(f"  [{s.state:7s}] {s.stage:11s} {s.detail}")
assert [s.stage for s in last.stages] == ["credentials","captcha","verify","migrate","session"]
assert all(s.state == "done" for s in last.stages)

# logout and relogin: toml path, migrate step marked no-op done
at.sidebar.button[0].click().run()
submit("pparker", "abc123")
last = at.session_state["login_last_result"]
print("relogin status:", last.status, "| source:", last.source)
for s in last.stages:
    print(f"  [{s.state:7s}] {s.stage:11s} {s.detail}")

# Now force an interrupted migration against a copy of the repo state:
# corrupt-toml fallback + in-place retry, driven through the UI.
at.sidebar.button[0].click().run()
shutil.rmtree(ROOT / "config", ignore_errors=True)
# log in once to migrate so we can corrupt... instead simulate interruption:
import auth._store as store
orig = store.atomic_replace
store.atomic_replace = lambda tmp, dest: (_ for _ in ()).throw(OSError("boom"))
submit("pparker", "abc123")
store.atomic_replace = orig
last = at.session_state["login_last_result"]
print("interrupt status:", last.status, "| source:", last.source, "| reason:", last.reason)
for s in last.stages:
    print(f"  [{s.state:7s}] {s.stage:11s} {s.detail}")
assert last.status == "fallback"
# retry button is present and flips migration to done
labels = [b.label for b in at.button]
print("buttons:", labels)
assert any("重试迁移" in b for b in labels)
at.button[labels.index(next(b for b in labels if "重试迁移" in b))].click().run()
last = at.session_state["login_last_result"]
print("retry status:", last.status, "| source:", last.source)
mig = [s for s in last.stages if s.stage == "migrate"][0]
print("  migrate step:", mig.state, mig.detail)
assert last.status == "authenticated" and last.source == "toml"
print("STRIP OK")
