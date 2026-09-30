
# Add a User Authentication Service (Login Form) in Streamlit

In this video, I will show you how to add a user authentication service (login form) in Streamlit so that your users can log in and see the content of your streamlit app. To implement the user authentication, we will use the ‘streamlit-authenticator’ library, a secure authentication module to validate user credentials in a Streamlit application.

## Video Tutorial
[![YouTube Video](https://img.youtube.com/vi/JoFGrSRj4X4/0.jpg)](https://youtu.be/JoFGrSRj4X4)

## Demo Website
⭐ https://userauth-dashboard.herokuapp.com/

## Screenshot
![Login Screenshot](/demo.jpg?raw=true "Login Form")

## Streamlit-authenticator
⭐ Check out the library here: https://github.com/mkhorasani/Streamlit-Authenticator

## Learn Excel Automation with Python
If this repo helped you, my [Excel Automation Course](https://pythonandvba.com/excel-automation-course/) teaches the full workflow from zero: Python for Excel users, xlwings, pandas and real projects.

Also check out my other [tools and templates](https://pythonandvba.com/solutions).

## Connect with Me
- **YouTube:** [CodingIsFun](https://youtube.com/c/CodingIsFun)
- **Website:** [PythonAndVBA](https://pythonandvba.com)
- **LinkedIn:** [Sven Bosau](https://www.linkedin.com/in/sven-bosau/)
- **Contact:** [Get in Touch](https://pythonandvba.com/contact)
## Support
If you find this project helpful, consider buying me a coffee. 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://pythonandvba.com/coffee-donation)

---

## 鉴权状态机（auth 包 + 单页 app.py）

登录鉴权收敛为「一库一页」：`auth/` 只暴露 `check_login`、`logout`、`current_user`、`credentials`，内部按 `未认证 → 校验中 → 已认证 → 迁移中 → 回退` 流转，不反向 import 任何 Web 框架/模板引擎；`app.py`（FastAPI + Jinja2，uvicorn 启动）只渲染登录页和顶部状态条。

- 真值：`config/credentials.toml`（明文用户名 + bcrypt 哈希口令，带 `version`）；`hashed_pw.pkl` 为只读兼容源。
- 首次登录成功后，临时文件 `credentials.toml.<pid>.tmp` + `os.replace` 原子替换；toml 缺键/损坏/写入中断一律保留原文件并回退 pkl，状态条显示来源、进度、失败原因与「原地重试」。
- 并发首次登录由 `config/credentials.lock`（Windows `msvcrt` / POSIX `fcntl`）加 `version` 判定串行化：一个进程迁移，其余复用结果，真值唯一。
- 验证码错误、口令错误、未知用户对外同一句提示。

运行：

```bash
python verify_auth.py                 # 五条路径 + 并发 + HTTP 冒烟，共 42 项
uvicorn app:app --port 8000          # 登录页与状态条（pparker / abc123）
```
