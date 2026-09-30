# Streamlit Sales Dashboard — with reusable `auth` package

A self-contained, UI-agnostic authentication package plus a Streamlit login
page and sales dashboard.

## Layout

```
auth/                  # reusable auth package (stdlib + argon2 only)
  __init__.py          #   public surface: check_login, logout, current_user, credentials
  _states.py           #   state machine vocabulary & result dataclasses
  _locks.py            #   fcntl lock (POSIX) / msvcrt equivalent (Windows)
  _store.py            #   toml truth, pkl compatibility source, atomic migration
login_page.py          # Streamlit login page (status strip)
app.py                 # thin gate + sales dashboard
config/credentials.toml# created on first login (single truth)
hashed_pw.pkl          # read-only compatibility source (argon2 hashes)
tests/test_auth.py     # pytest: 5 required paths + concurrency
generate_keys.py       # regenerate hashed_pw.pkl
```

## Credential migration

- Truth lives in `config/credentials.toml` (`version` + per-user `name`/
  argon2 `password`).
- `hashed_pw.pkl` is read-only and used only until the first successful login.
- Migration writes `credentials.toml.<pid>.tmp` and promotes it with
  `os.replace`; an interrupted/missing-key/corrupt write keeps the original
  file byte-for-byte and falls back to the pkl source, with in-place retry.
- Concurrent first logins: an advisory `fcntl.flock` lock (Windows: `msvcrt`)
  elects exactly one migrator; losers re-read the toml (version judgment) and
  reuse its result. There is never a second truth.

## State machine

`unauthenticated -> checking -> authenticated -> migrating -> fallback`

The status strip shows source, per-step progress (credentials/captcha/
verify/migrate/session) and failure reason; a wrong captcha and a wrong
password produce the same user-facing message.

## Accounts (demo)

| username | password |
|----------|----------|
| `pparker` | `abc123` |
| `rmiller` | `def456` |

## Run

```bash
pip install -r requirements.txt
python -m pytest tests/test_auth.py -q
streamlit run app.py
```
