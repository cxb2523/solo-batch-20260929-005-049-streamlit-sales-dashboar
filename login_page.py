"""Login page for the sales dashboard.

This is the only place that renders auth UI. All session/credential logic
lives in the reusable :mod:`auth` package; here we only turn its result object
into a status strip.
"""

from __future__ import annotations

import random
import time

import streamlit as st

import auth

# String values come from auth.LoginResult; the page owns its own labels.
STAGE_LABELS = {
    "credentials": "① 凭据来源",
    "captcha": "② 验证码",
    "verify": "③ 口令校验",
    "migrate": "④ 凭据迁移",
    "session": "⑤ 建立会话",
}

SOURCE_LABELS = {
    "toml": "config/credentials.toml（已迁移真值）",
    "pkl": "hashed_pw.pkl（只读兼容源）",
}


def _new_captcha() -> tuple[str, str]:
    left = random.randint(1, 9)
    right = random.randint(1, 9)
    return f"{left} + {right} = ?", str(left + right)


def _ensure_captcha() -> None:
    if st.session_state.pop("login_rotate", False):
        # Rotate before the captcha widget is instantiated: widget keys must
        # not be touched after widget creation within a run.
        question, answer = _new_captcha()
        st.session_state["login_captcha"] = question
        st.session_state["login_captcha_answer"] = answer
        st.session_state["login_captcha_input"] = ""
    if "login_captcha" not in st.session_state:
        question, answer = _new_captcha()
        st.session_state["login_captcha"] = question
        st.session_state["login_captcha_answer"] = answer


def _render_stage(stage) -> None:
    label = STAGE_LABELS.get(stage.stage, stage.stage)
    detail = f"— {stage.detail}" if stage.detail else ""
    if stage.state == "done":
        st.write(f"✅ {label}：{detail.lstrip('— ')}")
    elif stage.state == "failed":
        st.error(f"❌ {label}：{detail.lstrip('— ')}")
    elif stage.state == "active":
        st.write(f"⏳ {label}：{detail.lstrip('— ')}")
    else:
        st.write(f"⬜ {label}：等待中")


def _render_status(result: auth.LoginResult) -> None:
    st.caption(
        f"状态：`{result.status}` ｜ 来源："
        f"{SOURCE_LABELS.get(result.source, result.source) or '—'} ｜ "
        f"进度 {sum(s.state == "done" for s in result.stages)}/"
        f"{len(result.stages)}"
    )
    status_box = st.container(border=True)
    with status_box:
        for stage in result.stages:
            # Flip the cards in place so each step is visibly visited.
            if stage.state in ("done", "active"):
                time.sleep(0.05)
            _render_stage(stage)
            if stage.state == "failed":
                break
    if result.error and not result.authenticated:
        st.error(result.error)
    elif result.status == "fallback":
        st.warning(result.error or "迁移未完成，当前以 pkl 兼容源登录，可原地重试迁移。")
        if st.button("🔁 原地重试迁移", key="retry_migration_btn"):
            retried = auth.check_login(
                st.session_state, "", "", base_dir=None, retry_migration=True
            )
            st.session_state["login_last_result"] = retried
            st.rerun()
    elif result.authenticated and result.status == "authenticated":
        st.success("登录成功")


def render_login() -> bool:
    """Render the login page.

    Returns True only when the session is fully AUTHENTICATED. A FALLBACK
    session (logged in against pkl, migration unfinished) stays on this page
    so the status strip can offer the in-place retry.
    """
    existing = auth.current_user(st.session_state)
    if existing is not None:
        last = st.session_state.get("login_last_result")
        if last is not None and last.authenticated:
            st.title(":lock: 登录")
            st.info(f"已以兼容源登录：{existing.name}")
            _render_status(last)
            if st.button("退出登录", key="fallback_logout"):
                auth.logout(st.session_state)
                st.session_state.pop("login_last_result", None)
                st.rerun()
        if last is None:
            return True
        return last.status != "fallback"

    st.title(":lock: 登录")
    _ensure_captcha()

    with st.form("login_form", clear_on_submit=False):
        st.text_input("用户名", key="login_username")
        st.text_input("密码", type="password", key="login_password")
        st.text_input(
            f"验证码：{st.session_state['login_captcha']}",
            key="login_captcha_input",
        )
        submitted = st.form_submit_button("登录")

    if submitted:
        result = auth.check_login(
            st.session_state,
            st.session_state.get("login_username", ""),
            st.session_state.get("login_password", ""),
            st.session_state.get("login_captcha_input", ""),
            st.session_state.get("login_captcha_answer", ""),
        )
        st.session_state["login_last_result"] = result
        # Rotate the captcha on the next run so a failed attempt cannot be
        # replayed; wrong captcha and wrong password share the same message.
        st.session_state["login_rotate"] = True
        st.rerun()

    last = st.session_state.get("login_last_result")
    if last is not None:
        _render_status(last)
    return False
