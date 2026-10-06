# GitHub 发布前安全检查

本项目的 `.env`、数据库、上传文件、网络抓包、运行输出和本地训练数据默认不会进入 Git。

## 首次发布

1. 立即在 DeepSeek 控制台吊销当前本机 `.env` 中的旧 API Key，并创建新 Key。
2. 只把新 Key 写入本机 `.env`；不要写入代码、文档、Issue、提交信息或截图。
3. 检查待提交文件：

   ```powershell
   git status --short
   git add --dry-run .
   git status --ignored --short
   ```

4. 确认 `.env`、`*.db`、`*.pcap`、`uploads/`、`captured_traffic/` 和 `outputs/` 显示为忽略项。
5. 提交并连接一个空的 GitHub 仓库：

   ```powershell
   git add .
   git commit -m "Initial public release"
   git remote add origin https://github.com/你的用户名/你的仓库名.git
   git push -u origin main
   ```

6. 推送后在 GitHub 的 Security 页面启用 Secret scanning、Push protection 和 Dependabot alerts（仓库类型支持时）。

## 克隆后的本地配置

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

把生成值填入 `SECRET_KEY`，再设置数据库和管理员凭据。管理员应通过 `python create_admin.py` 显式创建。需要 DeepSeek 时，才在本机 `.env` 中填写新 Key 并把 `DEEPSEEK_ENABLE` 改为 `true`。

## 如果密钥曾经进入提交历史

仅删除当前文件不够：先在服务商后台吊销密钥，再使用 `git filter-repo` 或 BFG 清理整个历史，强制推送，并通知所有协作者重新克隆。不要尝试继续使用已经公开过的密钥。
