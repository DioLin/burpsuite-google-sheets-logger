# Burp Suite Google Sheets Logger Extension

## 專案概述

這是一個 Burp Suite 擴充套件，用於將 HTTP 請求的參數和完整請求內容自動記錄到 Google Sheets 中。擴充套件支援兩種認證方式：
- **Google CLI (gcloud) 認證**：使用 gcloud CLI 獲取認證 token
- **OAuth 2.0 認證**：使用標準 OAuth 2.0 授權流程獲取 token

兩種認證方式完全獨立，可根據需求選擇使用。

## 前置需求

### 通用需求
1. **Burp Suite Professional** 或 **Community Edition**
2. **Google Sheets** 文件已創建，並具有適當的權限

### Google CLI 認證方式需求
1. **Google Cloud SDK (gcloud CLI)** 已安裝並配置

#### 安裝 Google Cloud CLI (Windows)
前往 Google 官方文件下載 Google Cloud CLI Installer for Windows：
👉 [點此下載 gcloud CLI 安裝程式 (.exe)](https://cloud.google.com/sdk/docs/install)

#### 初始化專案與權限 (關鍵設定)
執行以下命令來初始化專案並設定必要的權限：

```bash
# 1. 登入並設定應用程式預設憑證（包含必要的 API 範圍）
gcloud auth application-default login --scopes=https://www.googleapis.com/auth/spreadsheets,https://www.googleapis.com/auth/cloud-platform

# 2. 創建新的 Google Cloud 專案（名稱可自訂，例如：chtpt-burp-logger-001）
gcloud projects create chtpt-burp-logger-00X

# 3. 設定應用程式預設憑證的配額專案（使用步驟 2 創建的專案名稱）
gcloud auth application-default set-quota-project chtpt-burp-logger-00X

# 4. 啟用 Google Sheets API（使用步驟 2 創建的專案名稱）
gcloud services enable sheets.googleapis.com --project chtpt-burp-logger-00X

# 5. 驗證 token 是否正常運作（可選，用於測試）
gcloud auth application-default print-access-token
```

**注意事項**：
- 步驟 2 中的專案名稱（`chtpt-burp-logger-00X`）可以自訂，但請確保在所有後續步驟中使用相同的專案名稱
- 如果專案已存在，步驟 2 會失敗，可以直接跳過並使用現有專案名稱
- 步驟 5 會輸出一個 access token，如果看到 token 輸出表示設定成功

### OAuth 2.0 認證方式需求
1. **Google Cloud Console 專案**：需要創建 OAuth 2.0 Client ID 和 Client Secret
2. **不需要安裝 gcloud CLI**：OAuth 2.0 認證方式完全獨立，不需要 gcloud CLI

#### Google Cloud Console 設置步驟

1. **創建或選擇 Google Cloud 專案**
   - 前往 [Google Cloud Console](https://console.cloud.google.com/)
   - 創建新專案或選擇現有專案

2. **啟用必要的 API**
   - 前往「API 和服務」→「程式庫」
   - 啟用以下 API：
     - **Google Sheets API**
     - **Google Drive API**（用於讀取權限）

3. **設定 OAuth 同意畫面**
   - 前往「API 和服務」→「OAuth 同意畫面」
   - 選擇「外部」或「內部」（根據您的需求）
   - 填寫應用程式資訊：
     - 應用程式名稱
     - 使用者支援電子郵件
     - 開發人員連絡資訊
   - 新增測試使用者（如果應用程式處於測試階段）
   - 儲存並繼續

4. **建立 OAuth 2.0 用戶端 ID**
   - 前往「API 和服務」→「憑證」
   - 點擊「建立憑證」→「OAuth 用戶端 ID」
   - 選擇應用程式類型：「桌面應用程式」
   - 設定名稱（例如：Burp Suite Extension）
   - **重要**：在「已授權的重新導向 URI」中新增：
     ```
     http://localhost:8769/callback
     ```
   - 點擊「建立」
   - **保存 Client ID 和 Client Secret**（Client Secret 只會顯示一次）

5. **授予必要的 IAM 權限**
   - 前往「IAM 與管理」→「IAM」
   - 為用於授權的 Google 帳號添加以下角色：
     - `Service Usage Consumer`（`roles/serviceusage.serviceUsageConsumer`）
   - 或授予 `serviceusage.services.use` 權限

6. **測試使用者設定**（如果應用程式處於測試階段）
   - 前往「API 和服務」→「OAuth 同意畫面」
   - 在「測試使用者」區段新增需要授權的 Google 帳號

## 安裝步驟

1. 將 `gform_logger_gcloud_v5.py` 複製到本地目錄
   - **重要**: 請確保文件路徑**不包含中文字符或特殊字符**
   - 建議路徑範例：`C:\BurpExtensions\gform_logger_gcloud_v5.py` 或 `D:\tools\gform_logger_gcloud_v5.py`
   - 避免使用包含中文的路徑，例如：`C:\Users\...\Documents\01_資料夾\...`（可能會導致載入失敗）

2. 在 Burp Suite 中：
   - 進入 `Extender` → `Extensions` → `Add`
   - 選擇 `Extension type: Python`
   - 點擊 `Select file...` 選擇 `gform_logger_gcloud_v5.py`
   - 點擊 `Next` 確認載入成功

## 使用方法

### 選擇認證方式

根據您的環境和需求選擇認證方式：

- **Google CLI 認證**：適合已安裝並配置 gcloud CLI 的環境
- **OAuth 2.0 認證**：適合任何環境，無需安裝 gcloud CLI

**注意**：第一次執行 `[G-Sheet] Send to I/J/K/O/P` 時，如果沒有發現本地配置文件，會自動彈出對話框要求選擇認證方式。

### Google CLI 認證配置

1. 在 Burp Suite 中右鍵點擊任意 HTTP 請求
2. 選擇 `[G-Sheet] Google CLI Configuration`
3. 填寫以下資訊（按順序）：
   - **認證方式**: 顯示 "gcloud CLI"
   - **GCP Project ID**: Google Cloud Project ID（例如：`chtpt-burp-logger-001`）
   - **查詢 Email**（可選）: 輸入 email 地址，然後點擊「查詢 Spreadsheet 列表」按鈕
     - 查詢成功後，可從下拉選單中選擇 Spreadsheet，會自動填入 Spreadsheet ID
   - **可選 Spreadsheet**: 從查詢結果下拉選單中選擇 Spreadsheet（會自動填入 Spreadsheet ID）
   - **Spreadsheet ID**: Google Sheets 文件的 ID
     - 可從查詢結果下拉選單中選擇，或手動從 URL 中獲取
     - 例如：`1ktp1WhqJMHOUvriQ3voq3oERAPTJLMZrjI0SCjUSVhc`
   - **Target Sheet Name**: 目標工作表名稱（例如：`弱點清單`）
     - 從下拉選單選擇 Spreadsheet 時不會覆蓋此欄位
   - **OAuth Token**: 點擊「從 gcloud 獲取 Token」按鈕自動獲取
     - 獲取 token 後會自動顯示對應的 email，並自動填入「查詢 Email」欄位
   - **當前 Token Email**: 顯示當前 token 對應的 email（如果已獲取）

### OAuth 2.0 認證配置

1. 在 Burp Suite 中右鍵點擊任意 HTTP 請求
2. 選擇 `[G-Sheet] OAuth 2.0 Configuration`
3. 填寫以下資訊（按順序）：
   - **認證方式**: 顯示 "OAuth 2.0"
   - **OAuth 2.0 Client ID**: 從 Google Cloud Console 獲取的 Client ID
   - **OAuth 2.0 Client Secret**: 從 Google Cloud Console 獲取的 Client Secret
   - **OAuth 2.0 授權**: 點擊此按鈕啟動授權流程
     - 會自動打開瀏覽器進行授權
     - 授權成功後會自動獲取 token 並顯示對應的 email
   - **查詢 Email**（可選）: 輸入 email 地址，然後點擊「查詢 Spreadsheet 列表」按鈕
     - 如果已獲取 token，此欄位會自動填入 token 對應的 email
   - **可選 Spreadsheet**: 從查詢結果下拉選單中選擇 Spreadsheet（會自動填入 Spreadsheet ID）
   - **Spreadsheet ID**: Google Sheets 文件的 ID
     - 可從查詢結果下拉選單中選擇，或手動從 URL 中獲取
   - **Target Sheet Name**: 目標工作表名稱（例如：`弱點清單`）
   - **OAuth Token**: 顯示當前授權的 token（授權成功後自動填入）
   - **當前 Token Email**: 顯示當前 token 對應的 email（如果已獲取）

**注意**：
- OAuth 2.0 認證**不需要**設置 GCP Project ID
- OAuth 2.0 的授權範圍包括：
  - `https://www.googleapis.com/auth/spreadsheets`（讀寫 Google Sheets）
  - `https://www.googleapis.com/auth/drive.readonly`（讀取 Google Drive）
  - `https://www.googleapis.com/auth/userinfo.email`（獲取用戶 email）

### Spreadsheet 列表查詢

1. 在配置對話框中輸入 email 地址
2. 點擊「查詢 Spreadsheet 列表」按鈕
3. 等待查詢完成（會在背景執行）
4. 查詢成功後，從「可選 Spreadsheet」下拉選單中選擇目標 Spreadsheet
5. Spreadsheet ID 會自動填入，但 Target Sheet Name 不會被覆蓋

### Token 獲取

**Google CLI 認證**：
1. 確保已執行 `gcloud auth application-default login`
2. 在配置對話框中點擊「從 gcloud 獲取 Token」
3. 等待幾秒鐘，token 會自動填入並保存到本地
4. Token 獲取成功後會顯示對應的 email 資訊
5. Email 會自動填入「查詢 Email」欄位，方便後續查詢 Spreadsheet 列表

**OAuth 2.0 認證**：
1. 確保已設置 OAuth 2.0 Client ID 和 Client Secret
2. 在配置對話框中點擊「OAuth 2.0 授權」
3. 瀏覽器會自動打開授權頁面
4. 登入 Google 帳號並授權
5. 授權成功後，token 會自動填入並保存到本地
6. Token 獲取成功後會顯示對應的 email 資訊

**注意**: 
- **配置文件分離**：兩種認證方式使用不同的配置文件，互不影響
  - Google CLI 認證：
    - 配置：`~/.burp_google_config_gcloud.json`
    - Token：`~/.burp_google_token_gcloud.json`
  - OAuth 2.0 認證：
    - 配置：`~/.burp_google_config_oauth2.json`
    - Token：`~/.burp_google_token_oauth2.json`
- 配置會自動保存，下次開啟配置對話框時會自動載入
- OAuth 2.0 的 Client Secret 不會保存到配置文件（僅在記憶體中使用）

### 使用方式

#### 首次使用

1. 在 Burp Suite 的 Proxy、Repeater 或任何地方選擇一個 HTTP 請求
2. 右鍵點擊 → 選擇 `[G-Sheet] Send to I/J/K/O/P`
3. **如果沒有本地配置文件**，會自動彈出認證方式選擇對話框：
   - 選擇「Google CLI (gcloud)」或「OAuth 2.0」
   - 根據選擇的認證方式，打開對應的配置對話框
4. 按照上述配置說明完成設置

#### 日常使用

1. 在 Burp Suite 的 Proxy、Repeater 或任何地方選擇一個 HTTP 請求
2. 右鍵點擊 → 選擇 `[G-Sheet] Send to I/J/K/O/P`
3. 在彈出的對話框中：
   - 檢查或修改「項次（行號）」（預設為自動找到的第一個空行）
   - 檢查 URL（I 欄位）、參數（J 欄位）和請求內容（K 欄位）
   - 填寫或檢查「測試人員」（O 欄位）
   - 檢查「發現日期」（P 欄位，自動從請求時間戳記提取）
   - 點擊 `OK` 確認寫入
4. 如果指定的行號已有數據，會顯示覆蓋確認對話框
5. 顯示最終確認對話框，確認 Google 文件名稱、工作表名稱和行號
6. 寫入成功後會顯示提示訊息

**注意**：
- 如果 token 已過期，系統會根據配置的認證方式自動刷新 token
- 如果自動刷新失敗，請手動在配置對話框中重新獲取 token

## 更多資訊

詳細的技術文檔、錯誤處理、程式結構等說明，請參閱 [WIKI.md](WIKI.md)。

---

**最後更新**: 2025年12月
