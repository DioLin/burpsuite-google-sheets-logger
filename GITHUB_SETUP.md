# GitHub 上傳步驟

## 1. 設置 Git 用戶資訊（首次使用需要）

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

或者僅為此專案設置：

```bash
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

## 2. 創建初始提交

```bash
git commit -m "Initial commit: Burp Suite Google Sheets Logger Extension"
```

## 3. 在 GitHub 上創建新倉庫

1. 登入 GitHub
2. 點擊右上角的 "+" → "New repository"
3. 輸入倉庫名稱（例如：`burpsuite-google-sheets-logger`）
4. 選擇 Public 或 Private
5. **不要**勾選 "Initialize this repository with a README"（因為我們已經有文件）
6. 點擊 "Create repository"

## 4. 連接本地倉庫到 GitHub

複製 GitHub 提供的命令（類似以下），或手動執行：

```bash
git remote add origin https://github.com/YOUR_USERNAME/burpsuite-google-sheets-logger.git
git branch -M main
git push -u origin main
```

## 5. 如果使用 SSH（可選）

```bash
git remote add origin git@github.com:YOUR_USERNAME/burpsuite-google-sheets-logger.git
git branch -M main
git push -u origin main
```

## 注意事項

- `.gitignore` 文件已創建，會自動排除敏感文件（如 token 文件、.burp 文件等）
- 確保不要上傳包含個人 token 或敏感資訊的文件
- 如果已經有 token 文件，請確認它已被 `.gitignore` 排除

