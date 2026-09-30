"""Drive the real app with streamlit.testing.v1.AppTest:

1. bad captcha (same message as bad password)
2. bad password
3. successful first login -> migration status strip cards flip through
4. logout -> back to login
5. second login uses toml directly
"""

from pathlib import Path
import shutil
import sys

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# Start from a pristine pkl-only state.
shutil.rmtree(ROOT / "config", ignore_errors=True)

GENERIC = "验证码或用户名/密码错误，请重试"

at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
at.run()
assert not at.exception, at.exception

# --- 1. wrong captcha ---
at.text_input[0].input("pparker").run()
at.text_input[1].input("abc123").run()
at.text_input[2].input("999").run()
at.button[0].click().run()
assert not at.exception, at.exception
errors = [e.value for e in at.error]
assert GENERIC in errors, errors
print("1) wrong captcha ->", errors)

# --- 2. wrong password (read the freshly rotated captcha answer) ---
answer = at.session_state["login_captcha_answer"]
at.text_input[0].input("pparker").run()
at.text_input[1].input("WRONGPW").run()
at.text_input[2].input(answer).run()
at.button[0].click().run()
assert not at.exception, at.exception
errors = [e.value for e in at.error]
assert GENERIC in errors, errors
print("2) wrong password ->", errors, "(same sentence)")

# --- 3. successful first login: migration cards ---
answer = at.session_state["login_captcha_answer"]
at.text_input[0].input("pparker").run()
at.text_input[1].input("abc123").run()
at.text_input[2].input(answer).run()
at.button[0].click().run()
assert not at.exception, at.exception

toml = ROOT / "config" / "credentials.toml"
assert toml.exists(), "migration should have created credentials.toml"
writes = [w.value for w in at.markdown]
welcome = [s.value for s in at.sidebar.title] if hasattr(at.sidebar, "title") else []
success = [s.value for s in at.success]
print("3) first login success:", success)
print("   welcome sidebar:", [s.value for s in at.sidebar.title])
assert any("Welcome Peter Parker" in s.value for s in at.sidebar.title)

# --- 4. logout ---
at.sidebar.button[0].click().run()
assert not at.exception, at.exception
print("4) after logout titles:", [h.value for h in at.title])
assert any("登录" in h.value for h in at.title)

# --- 5. second login uses toml (no migration) ---
answer = at.session_state["login_captcha_answer"]
at.text_input[0].input("rmiller").run()
at.text_input[1].input("def456").run()
at.text_input[2].input(answer).run()
at.button[0].click().run()
assert not at.exception, at.exception
assert any("Welcome Rebecca Miller" in s.value for s in at.sidebar.title)
print("5) second login via toml ->", [s.value for s in at.sidebar.title])

print("SMOKE OK")
