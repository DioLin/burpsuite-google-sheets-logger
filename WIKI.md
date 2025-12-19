# Burp Suite Google Sheets Logger Extension - 技術文檔

本文檔包含擴充套件的詳細技術說明、程式結構、錯誤處理等資訊。

## 主要功能

### 1. HTTP 請求記錄
- 自動提取選中的 HTTP 請求資訊
- 提取 URL、參數列表和完整請求內容
- 自動提取發現日期（從 HTTP 請求時間戳記或當前日期）
- 將數據寫入 Google Sheets 的 I、J、K、O、P 欄位
  - **I 欄位**：URL
  - **J 欄位**：參數列表
  - **K 欄位**：完整請求內容
  - **O 欄位**：測試人員
  - **P 欄位**：發現日期

### 2. 雙認證方式支援

#### Google CLI 認證
- 透過 gcloud CLI 自動獲取 Google OAuth access token
- Token 本地緩存機制（保存至 `~/.burp_google_token_gcloud.json`）
- Token 有效性自動驗證和自動刷新機制
- Token 即將過期時（少於 5 分鐘）自動提前刷新
- 401 錯誤時自動嘗試刷新 token 並重試
- 顯示當前 token 的 email 資訊
- 支援 Windows、Linux、macOS 多平台

#### OAuth 2.0 認證
- 標準 OAuth 2.0 Authorization Code Flow with PKCE
- 瀏覽器授權流程，無需安裝 gcloud CLI
- 自動獲取 access_token 和 refresh_token
- Token 自動刷新機制（使用 refresh_token）
- Token 持久化儲存（保存至 `~/.burp_google_token_oauth2.json`）
- 本地回調伺服器（端口 8769）接收授權碼
- 401 錯誤時自動嘗試刷新 token 並重試
- 顯示當前 token 的 email 資訊（自動從 tokeninfo API 或 UserInfo API 獲取）
- 完全獨立於 gcloud CLI
- 授權範圍包括 `userinfo.email` scope，用於獲取用戶 email

### 3. Token 管理
- **自動刷新機制**：
  - Token 過期時自動刷新
  - Token 即將過期時（少於 5 分鐘）提前刷新
  - 401 錯誤時自動刷新並重試
- **持久化儲存**：
  - Token 保存至對應的 token 文件（`~/.burp_google_token_gcloud.json` 或 `~/.burp_google_token_oauth2.json`）
  - 配置保存至對應的配置文件（`~/.burp_google_config_gcloud.json` 或 `~/.burp_google_config_oauth2.json`，不包含敏感資訊）
- **Token 驗證**：
  - 自動驗證 token 有效性
  - 顯示 token 對應的 email 資訊

### 4. 智能行號管理
- 自動查找第一個 B、D、I 欄位都為空的行
- 支援自訂行號輸入
- 覆蓋保護機制：當自訂行號已有數據時，顯示確認對話框

### 5. 用戶界面
- **雙配置對話框**：
  - `[G-Sheet] Google CLI Configuration`：gcloud CLI 認證配置
  - `[G-Sheet] OAuth 2.0 Configuration`：OAuth 2.0 認證配置
- **配置功能**：
  - 設定 Spreadsheet ID、Sheet 名稱、Project ID、Token
  - 一鍵獲取 Token 按鈕（根據認證方式不同）
  - Email 查詢功能：通過 email 查詢可用的 Spreadsheet 列表
  - Spreadsheet 下拉選單：從查詢結果中選擇 Spreadsheet，自動填充 ID
- **數據預覽和編輯對話框**：
  - 包含測試人員和發現日期欄位
  - 最終確認對話框：顯示 Google 文件名稱、工作表名稱和行號
- **完整的錯誤提示和調試資訊**
- **Token Email 顯示**：在配置對話框中顯示當前 token 對應的 email

## 認證方式比較

| 特性 | Google CLI | OAuth 2.0 |
|------|-----------|-----------|
| **前置需求** | 需要安裝 gcloud CLI | 不需要 gcloud CLI |
| **Token 獲取** | 執行 gcloud 命令 | 瀏覽器授權流程 |
| **首次授權** | 執行 gcloud 命令（幾秒） | 瀏覽器授權（1-2 分鐘） |
| **Token 刷新** | 執行 gcloud 命令 | 使用 refresh_token API |
| **Refresh Token** | 不需要 | 需要保存 |
| **過期時間判斷** | 從 tokeninfo API 獲取 | 使用本地時間戳 |
| **獨立性** | 依賴 gcloud CLI | 完全獨立 |
| **適用場景** | 已配置 gcloud CLI 的環境 | 任何環境，無需 gcloud CLI |

### Token 差異說明

#### Google CLI Token
- **獲取方式**：執行 `gcloud auth application-default print-access-token`
- **Token 類型**：Application Default Credentials (ADC) token
- **Scope**：由 gcloud 登入時設定的 scope 決定
- **過期時間**：通常 1 小時，但可通過 gcloud 自動刷新
- **Refresh Token**：不需要，直接執行 gcloud 命令獲取新 token
- **持久化**：只保存 access_token

#### OAuth 2.0 Token
- **獲取方式**：OAuth 2.0 Authorization Code Flow with PKCE
- **Token 類型**：標準 OAuth 2.0 access token
- **Scope**：
  - `https://www.googleapis.com/auth/spreadsheets`（讀寫 Google Sheets）
  - `https://www.googleapis.com/auth/drive.readonly`（讀取 Google Drive）
  - `https://www.googleapis.com/auth/userinfo.email`（獲取用戶 email）
- **過期時間**：通常 1 小時，保存在 `token_expires_at`
- **Refresh Token**：需要保存，用於自動刷新 access token
- **持久化**：保存 access_token、refresh_token 和 token_expires_at
- **Email 獲取**：自動從 tokeninfo API 或 UserInfo API 獲取用戶 email

## 程式結構

### 類別架構

```
BurpExtender (主類別)
├── IBurpExtender (Burp Suite 擴充套件介面)
└── IContextMenuFactory (右鍵選單介面)
```

### 核心方法

#### 初始化方法
- `registerExtenderCallbacks(callbacks)`: 初始化擴充套件，載入配置和已保存的 token
- `createMenuItems(invocation)`: 創建右鍵選單項目

#### 配置管理
- `show_gcloud_config_dialog(event)`: 顯示 Google CLI 配置對話框
- `show_oauth2_config_dialog(event)`: 顯示 OAuth 2.0 配置對話框
- `_save_config_to_file()`: 保存配置到本地文件，根據認證方式使用對應的文件名，不包含敏感資訊如 access_token 和 oauth2_client_secret
- `_load_config_from_file()`: 從本地文件載入配置（sheet_id、project_id、sheet_name、email、auth_method、oauth2_client_id）

#### Token 管理方法

**Google CLI 認證**：
- `_get_gcloud_token()`: 從 gcloud CLI 獲取 access token
  - 先檢查本地緩存的 token 是否有效
  - 執行 `gcloud auth application-default print-access-token` 命令
  - 處理跨平台命令執行（Windows/Linux/macOS）
  - 設置環境變數和 PATH
  - 使用 ProcessBuilder 執行外部命令
  - 讀取命令輸出並提取 token
  - 驗證 token 有效性後保存到本地文件

**OAuth 2.0 認證**：
- `_oauth2_authorize(client_id, client_secret)`: 執行 OAuth 2.0 授權流程
  - 生成 PKCE 參數（state、code_verifier、code_challenge）
  - 啟動本地回調伺服器（端口 8769）
  - 構建授權 URL 並打開瀏覽器
  - 等待授權碼
  - 使用授權碼交換 access_token 和 refresh_token
  - 保存 tokens 到本地文件
- `_oauth2_exchange_code(authorization_code, client_id, client_secret, redirect_uri, code_verifier)`: 使用授權碼交換 token
- `_oauth2_refresh_token(refresh_token, client_id, client_secret)`: 使用 refresh_token 刷新 access_token
- `_start_callback_server(expected_state)`: 啟動本地回調伺服器
- `_wait_for_authorization_code(port, expected_state, timeout)`: 等待授權碼
- `_get_email_from_userinfo_api(access_token)`: 使用 Google UserInfo API 獲取 email（作為 tokeninfo API 的備用方案）

**通用 Token 管理**：
- `_save_token_to_file(token)`: 保存 token 到本地 JSON 文件
- `_load_token_from_file()`: 從本地文件載入 token，驗證有效性並獲取 email
- `_check_token_valid(token)`: 透過 Google tokeninfo API 驗證 token 有效性
- `_ensure_valid_token()`: 確保 token 有效，根據 `auth_method` 選擇正確的刷新方法
- `_get_token_info(token)`: 獲取 token 的詳細資訊（email、user_id、expires_in 等）
- `_get_gcloud_email()`: 使用 gcloud 命令獲取當前登錄的 email（僅用於 gcloud 認證）
- `_get_token_file_path(auth_method)`: 獲取 token 文件路徑（根據認證方式返回對應的文件名）
- `_get_config_file_path(auth_method)`: 獲取配置文件路徑（根據認證方式返回對應的文件名）
- `_create_token_fetcher(txt_token, txt_query_email)`: 創建「從 gcloud 獲取 Token」按鈕的事件處理器
- `_create_oauth2_authorizer(txt_token, txt_client_id, txt_client_secret, txt_query_email)`: 創建「OAuth 2.0 授權」按鈕的事件處理器

#### 表單讀取方法
- `_read_sheet_data()`: 讀取 Google Sheets 數據（A1:I1000 範圍）
  - 使用 Google Sheets API v4 讀取數據
  - 提取每行的 B、D、I 欄位值
  - 處理 403 權限錯誤並提供詳細指引
  - 401 錯誤時自動刷新 token 並重試
  - 根據認證方式條件性添加 `x-goog-user-project` header（僅 gcloud 認證）

- `_find_empty_row(rows_data)`: 找到第一個 B、D、I 都為空的行

#### Spreadsheet 查詢方法
- `_query_sheets_by_email(email)`: 通過 email 查詢可用的 Spreadsheet 列表
  - 調用外部 API 獲取 Spreadsheet 資訊
  - 返回包含 project、sheetid、status 的列表
- `_create_sheet_query_handler(txt_email, panel)`: 創建查詢 Spreadsheet 列表按鈕的事件處理器
- `_get_spreadsheet_info()`: 獲取 Google Spreadsheet 的資訊（名稱和工作表列表）
- `_get_spreadsheet_name()`: 獲取 Google Spreadsheet 的名稱

#### 數據寫入方法
- `send_to_sheet(event)`: 主入口方法，處理右鍵選單點擊事件
  - 驗證配置
  - 根據當前 `auth_method` 打開對應的配置對話框
  - 提取 HTTP 請求資訊（URL、參數、完整請求）
  - 自動提取發現日期（從請求時間戳記或當前日期）
  - 讀取表單數據並找到空行
  - 顯示數據預覽和編輯對話框（包含測試人員和發現日期欄位）
  - 處理自訂行號和覆蓋確認
  - 顯示最終確認對話框（包含 Google 文件名稱、工作表名稱和行號）
  - 啟動背景線程執行寫入操作

- `post_to_api(data)`: 將數據寫入 Google Sheets
  - 確保 token 有效（根據 `auth_method` 自動刷新）
  - 構建 API URL 分別寫入 I:K 和 O:P 欄位（例如：`弱點清單!I5:K5` 和 `弱點清單!O5:P5`）
  - 發送 PUT 請求更新指定範圍
  - 401 錯誤時自動刷新 token 並重試
  - 處理 API 回應和錯誤
  - 提供詳細的錯誤訊息和調試資訊
  - 根據認證方式條件性添加 `x-goog-user-project` header（僅 gcloud 認證）

#### 工具函數
- `safe_unicode_convert(val)`: 安全地將各種類型的值轉換為 Unicode
  - 處理 None、unicode、str 等不同類型
  - 支援 UTF-8、latin-1 等多種編碼
  - 錯誤容錯機制

## 技術細節

### 依賴項
- **Burp Suite API**: `IBurpExtender`, `IContextMenuFactory`, `IParameter`
- **Java Swing**: 用於 GUI 組件
- **Jython**: Python 2.7 運行環境（Burp Suite 內建）
- **Google Sheets API v4**: 用於讀寫 Google Sheets
- **gcloud CLI**: 用於 Google CLI 認證方式（可選）
- **OAuth 2.0**: 用於 OAuth 2.0 認證方式

### 使用的 API

#### Google Sheets API
- **讀取數據**: `GET /v4/spreadsheets/{spreadsheetId}/values/{range}`
- **更新數據**: `PUT /v4/spreadsheets/{spreadsheetId}/values/{range}?valueInputOption=USER_ENTERED`
- **認證**: Bearer Token (OAuth 2.0 Access Token)

#### Google OAuth Token Info API
- **驗證 Token**: `GET /oauth2/v1/tokeninfo?access_token={token}`

#### Google UserInfo API
- **獲取用戶資訊**: `GET /oauth2/v2/userinfo`（用於 OAuth 2.0 email 獲取的備用方案）

#### Google OAuth 2.0 API
- **授權端點**: `https://accounts.google.com/o/oauth2/v2/auth`
- **Token 交換端點**: `https://oauth2.googleapis.com/token`
- **Token 刷新端點**: `https://oauth2.googleapis.com/token`

### 數據流程

```
1. 用戶在 Burp Suite 中選擇 HTTP 請求
   ↓
2. 右鍵點擊 → 選擇 "[G-Sheet] Send to I/J/K/O/P"
   ↓
3. 驗證配置（sheet_id, access_token），必要時根據 auth_method 自動刷新 token
   ↓
4. 提取請求資訊（URL, 參數, 完整請求, 發現日期）
   ↓
5. 讀取 Google Sheets 數據（A1:I1000）
   ↓
6. 找到第一個空行（B、D、I 都為空）
   ↓
7. 顯示數據預覽對話框（可編輯行號、測試人員、發現日期）
   ↓
8. 檢查是否需要覆蓋確認
   ↓
9. 顯示最終確認對話框（Google 文件名稱、工作表名稱、行號）
   ↓
10. 確保 token 有效後（根據 auth_method 選擇刷新方法），發送 PUT 請求更新 Google Sheets
    - 先寫入 I、J、K 欄位（URL、參數、完整請求）
    - 再寫入 O、P 欄位（測試人員、發現日期）
   ↓
11. 如果 401 錯誤，根據 auth_method 自動刷新 token 並重試
   ↓
12. 顯示成功/錯誤訊息
```

### Token 獲取流程

#### Google CLI 認證流程

```
1. 用戶點擊「從 gcloud 獲取 Token」按鈕
   ↓
2. 檢查本地 token 文件（~/.burp_google_token_gcloud.json）
   ↓
3. 如果存在且有效，直接使用
   ↓
4. 否則執行 gcloud 命令：
   gcloud auth application-default print-access-token
   ↓
5. 讀取命令輸出（第一行即為 token）
   ↓
6. 驗證 token 有效性
   ↓
7. 保存 token 到本地文件
   ↓
8. 更新 UI 顯示 token
```

#### OAuth 2.0 認證流程

```
1. 用戶點擊「OAuth 2.0 授權」按鈕
   ↓
2. 生成 PKCE 參數（state, code_verifier, code_challenge）
   ↓
3. 啟動本地回調伺服器（端口 8769）
   ↓
4. 構建授權 URL 並打開瀏覽器
   ↓
5. 用戶在瀏覽器中登入並授權
   ↓
6. Google 重定向到本地回調伺服器
   ↓
7. 回調伺服器接收授權碼
   ↓
8. 使用授權碼交換 access_token 和 refresh_token
   ↓
9. 保存 tokens 到本地文件
   ↓
10. 更新 UI 顯示 token
```

## 錯誤處理

### 常見錯誤及解決方案

#### 1. Token 獲取失敗

**Google CLI 認證錯誤**：
- **錯誤訊息**: `gcloud 命令執行失敗` 或 `執行超時`
- **解決方案**:
  - 確認 gcloud CLI 已正確安裝
  - 執行 `gcloud auth application-default login` 進行認證
  - 檢查 PATH 環境變數是否包含 gcloud 路徑
  - 查看 Burp Suite 輸出標籤中的 DEBUG 訊息

**OAuth 2.0 認證錯誤**：
- **錯誤訊息**: `OAuth 2.0 授權失敗` 或 `未收到授權碼`
- **解決方案**:
  - 確認 Client ID 和 Client Secret 正確
  - 確認 Redirect URI 設置為 `http://localhost:8769/callback`
  - 確認 OAuth 同意畫面已正確設置
  - 確認測試使用者已添加到 OAuth 同意畫面
  - 確認已授予必要的 IAM 權限
  - 查看 Burp Suite 輸出標籤中的 DEBUG 訊息

#### 2. 權限錯誤 (403 Forbidden)

##### 2.1 Google Sheets API 未啟用
**錯誤訊息**: 
```
Google Sheets API has not been used in project {project_id} before or it is disabled. 
Enable it by visiting https://console.developers.google.com/apis/api/sheets.googleapis.com/overview?project={project_id}
```

**問題原因**:
- Google Sheets API 在指定的 Google Cloud Project 中未啟用
- 或 API 剛啟用但還未完成系統傳播（通常需要幾分鐘）

**解決方案**:
1. **使用 gcloud 命令啟用 API**（推薦）：
   ```bash
   gcloud services enable sheets.googleapis.com --project chtpt-burp-logger-050
   ```
   （將 `chtpt-burp-logger-050` 替換為您的實際專案 ID）

2. **或透過網頁控制台啟用**：
   - 前往錯誤訊息中提供的連結
   - 點擊「啟用」按鈕
   - 等待 1-3 分鐘讓 API 啟用狀態傳播到系統

3. **驗證 API 是否已啟用**：
   ```bash
   gcloud services list --enabled --project chtpt-burp-logger-050 | grep sheets
   ```
   如果看到 `sheets.googleapis.com` 表示已啟用

4. **確認專案 ID 正確**：
   - 檢查 Burp Suite 配置中的「GCP Project ID」是否與啟用 API 的專案一致
   - 檢查 token 對應的專案是否正確設定了 quota project

##### 2.2 一般權限錯誤
**錯誤訊息**: `權限錯誤 (403): Permission denied`（非 API 未啟用）

**解決方案**:
1. 確認 Google Cloud Project 已啟用 Google Sheets API（參考上述步驟）
2. 確認 Service Account 或 User Account 具有以下權限：
   - `roles/serviceusage.serviceUsageConsumer`
   - 或 `serviceusage.services.use`
3. 在 Google Cloud Console 中授予權限：
   - 前往：https://console.cloud.google.com/iam-admin/iam?project={project_id}
   - 為對應的帳號添加上述角色

#### 3. Token 過期

**錯誤訊息**: `Token 無效且無法刷新，請手動獲取新 token`

**解決方案**:
- **Google CLI 認證**：點擊「從 gcloud 獲取 Token」按鈕重新獲取
- **OAuth 2.0 認證**：
  - 如果 refresh_token 有效，會自動刷新
  - 如果 refresh_token 無效，點擊「OAuth 2.0 授權」按鈕重新授權

#### 4. 無法讀取表單數據
**錯誤訊息**: `無法讀取表單數據` 或 `讀取表單失敗`

**解決方案**:
- 確認 Spreadsheet ID 正確
- 確認 Sheet 名稱正確（區分大小寫）
- 確認 token 有效且有讀取權限
- 檢查 Google Sheets 文件是否為公開或已授予適當權限

#### 5. OAuth 2.0 授權失敗

**錯誤訊息**: `redirect_uri_mismatch` 或 `access_denied`

**解決方案**:
1. **確認 Redirect URI 設置**：
   - 在 Google Cloud Console 中，確認 OAuth 2.0 Client ID 的 Redirect URI 設置為：
     ```
     http://localhost:8769/callback
     ```
   - 注意：必須完全匹配，包括協議（http）、主機（localhost）、端口（8769）和路徑（/callback）

2. **確認 OAuth 同意畫面設置**：
   - 確認應用程式名稱、支援電子郵件等資訊已填寫
   - 確認測試使用者已添加到「測試使用者」列表

3. **確認 IAM 權限**：
   - 確認用於授權的 Google 帳號已授予 `Service Usage Consumer` 角色

#### 6. Unicode 編碼錯誤
**錯誤訊息**: `'ascii' codec can't encode/decode`

**解決方案**:
- 程式已內建 `safe_unicode_convert()` 函數處理此問題
- 如果仍出現錯誤，請檢查輸入數據的編碼格式

#### 7. 路徑錯誤 (Invalid argument)
**錯誤訊息**: 
```
OSError: (22, 'Invalid argument', 'C:\\Users\\...\\01_??\\burpsuite-google-sheets-logger-main')
```

**問題原因**:
- 腳本文件所在路徑包含**中文字符或特殊字符**
- Jython 在 Windows 上無法正確處理包含某些特殊字符的路徑

**解決方案**:
1. **將文件移到不包含中文字符的路徑**：
   - 建議路徑：`C:\BurpExtensions\gform_logger_gcloud_v5.py`
   - 或：`D:\tools\burpsuite\gform_logger_gcloud_v5.py`
   - 避免：`C:\Users\...\Documents\01_資料夾\...` ❌
   
2. **檢查文件夾名稱**：
   - 確保所有父目錄名稱都使用 ASCII 字符（英文、數字、底線、連字號）
   - 如果路徑中包含中文或其他特殊字符，請重命名文件夾或移動文件

3. **重新載入擴展**：
   - 在 Burp Suite 中移除舊的擴展
   - 使用新的路徑重新添加擴展

**預防措施**:
- 創建專用的擴展目錄，使用純英文路徑
- 例如：`C:\BurpExtensions\` 或 `D:\SecurityTools\BurpExtensions\`

#### 8. OAuth 2.0 無法取得 Email

**可能原因**:
1. **OAuth 2.0 Scope 缺少 email 權限**：已修復，現在包含 `userinfo.email` scope
2. **Tokeninfo API 未返回 email**：程式會自動嘗試使用 UserInfo API 作為備用方案
3. **授權時未勾選 email 權限**：重新執行 OAuth 2.0 授權流程

**解決方案**:
- 重新執行 OAuth 2.0 授權流程
- 確認授權頁面顯示 email 權限請求
- 查看 Burp Suite 輸出標籤中的 DEBUG 訊息，確認 email 獲取過程

## 調試資訊

程式包含詳細的 DEBUG 日誌，可在 Burp Suite 的 `Output` 標籤中查看：

- Token 獲取過程的詳細日誌
- 命令執行狀態和輸出
- API 請求 URL 和回應
- OAuth 2.0 授權流程的詳細日誌
- Email 獲取過程的詳細日誌
- 錯誤堆疊追蹤

## 文件結構

```
burpsuite-plugin/
├── gform_logger_gcloud_v5.py              # 主程式文件
├── README.md                              # 專案文件說明（簡化版）
├── WIKI.md                                # 技術文檔（本文件）
├── ~/.burp_google_token_gcloud.json      # Google CLI Token 緩存文件（自動生成）
├── ~/.burp_google_config_gcloud.json     # Google CLI 配置緩存文件（自動生成）
├── ~/.burp_google_token_oauth2.json      # OAuth 2.0 Token 緩存文件（自動生成）
└── ~/.burp_google_config_oauth2.json      # OAuth 2.0 配置緩存文件（自動生成，不包含 access_token 和 oauth2_client_secret）
```

## 配置參數說明

### config 字典

```python
{
    "sheet_id": "",              # Google Sheets 文件 ID
    "access_token": "",          # OAuth 2.0 Access Token（僅存在記憶體中，不保存到文件）
    "refresh_token": "",         # OAuth 2.0 Refresh Token（僅 OAuth 2.0 認證使用）
    "project_id": "chtpt-burp-logger-001",  # Google Cloud Project ID（僅 gcloud 認證使用）
    "sheet_name": u"弱點清單",   # 目標工作表名稱
    "email": "",                 # 當前 token 對應的 email（用於查詢 Spreadsheet 列表）
    "auth_method": "gcloud",     # 認證方式："gcloud" 或 "oauth2"
    "oauth2_client_id": "",      # OAuth 2.0 Client ID（僅 OAuth 2.0 認證使用）
    "oauth2_client_secret": "",  # OAuth 2.0 Client Secret（僅在記憶體中使用，不保存到文件）
    "token_expires_at": 0        # Token 過期時間戳（僅 OAuth 2.0 認證使用）
}
```

注意：
- **配置文件分離**：兩種認證方式使用不同的配置文件
  - Google CLI 認證：`~/.burp_google_config_gcloud.json` 和 `~/.burp_google_token_gcloud.json`
  - OAuth 2.0 認證：`~/.burp_google_config_oauth2.json` 和 `~/.burp_google_token_oauth2.json`
- `access_token` 和 `refresh_token` 保存在對應的 token 文件中
- `oauth2_client_secret` 不會保存到配置文件（僅在記憶體中使用）
- `project_id` 只有 gcloud 認證時才會保存到配置文件
- 其他配置會自動保存到對應的配置文件中

### Token 文件格式

**Google CLI Token 文件** (`~/.burp_google_token_gcloud.json`):
```json
{
    "access_token": "ya29.xxx...",
    "saved_at": 1234567890.123
}
```

**OAuth 2.0 Token 文件** (`~/.burp_google_token_oauth2.json`):
```json
{
    "access_token": "ya29.xxx...",
    "refresh_token": "1//xxx...",
    "token_expires_at": 1234567890,
    "saved_at": 1234567890.123
}
```

## 開發歷史

### 版本演進

- **v5** (當前版本): 最新功能更新
  - **雙認證方式支援**：
    - 新增 OAuth 2.0 認證方式（完全獨立於 gcloud CLI）
    - 保留 Google CLI 認證方式
    - 兩種認證方式完全獨立，互不影響
  - **OAuth 2.0 完整實現**：
    - OAuth 2.0 Authorization Code Flow with PKCE
    - 本地回調伺服器（端口 8769）
    - 自動 token 刷新機制（使用 refresh_token）
    - Token 持久化儲存
    - Email 自動獲取（tokeninfo API + UserInfo API 備用）
  - **分離的配置對話框**：
    - `[G-Sheet] Google CLI Configuration`：gcloud CLI 認證配置
    - `[G-Sheet] OAuth 2.0 Configuration`：OAuth 2.0 認證配置
  - **新增 O/P 欄位支援**：現在支援寫入測試人員（O 欄位）和發現日期（P 欄位）
  - **自動日期提取**：從 HTTP 請求時間戳記自動提取發現日期，無時間戳記時使用當前日期
  - **Spreadsheet 列表查詢功能**：通過 email 查詢可用的 Spreadsheet 列表，支援下拉選單選擇
  - **配置持久化**：配置（sheet_id、project_id、sheet_name、email、auth_method、oauth2_client_id）自動保存到對應的配置文件
  - **Token 自動刷新機制**：
    - 當 token 過期時自動刷新（根據 auth_method 選擇刷新方法）
    - token 即將過期（少於 5 分鐘）時提前刷新
    - API 請求遇到 401 錯誤時自動刷新並重試
  - **Email 管理功能**：
    - 顯示當前 token 對應的 email
    - email 自動保存到配置中
    - 支援從 tokeninfo API 獲取 email（OAuth 2.0 不再依賴 gcloud）
    - OAuth 2.0 使用 UserInfo API 作為備用方案
  - **最終確認對話框**：上傳前顯示 Google 文件名稱、工作表名稱和行號的確認資訊
  - **改進的錯誤處理**：更詳細的錯誤訊息和自動重試機制
  - **Spreadsheet 資訊查詢**：可獲取 Spreadsheet 名稱和工作表列表，用於錯誤診斷
  - **配置文件分離**：gcloud 和 OAuth 2.0 使用不同的配置文件，互不影響
  - **Project ID 條件使用**：OAuth 2.0 認證不需要 project_id，所有 API 請求都正確地只在 gcloud 認證時添加 `x-goog-user-project` header

- **v5** (初始): 基礎版本
  - 移除 OAuth 網頁授權功能
  - 改進 gcloud token 獲取機制
  - 添加 token 本地緩存和驗證
  - 添加自訂行號和覆蓋保護機制
  - 完整的 Unicode 處理
  - 詳細的錯誤處理和調試資訊

- **v4**: 添加 OAuth 網頁授權功能（已移除）

- **v3**: 添加 gcloud CLI 整合

- **v2**: 改進表單讀取和空行查找

- **v1**: 初始版本，基本功能實現

## 技術限制

1. **Jython 2.7**: 使用 Python 2.7 語法，不支援 Python 3 特性
2. **Unicode 處理**: 需要特別處理 Jython 的 ASCII 預設編碼問題
3. **外部命令執行**: Google CLI 認證方式依賴系統 PATH 環境變數，Windows 需要額外處理
4. **API 限制**: 受 Google Sheets API 配額限制（每分鐘請求數）
5. **OAuth 2.0 回調端口**: 固定使用端口 8769，如果端口被占用會自動嘗試下一個端口

## 安全性說明

### OAuth 2.0 Client Secret 安全
- **Client Secret 不會保存到配置文件**：僅在記憶體中使用
- **Client Secret 洩露風險**：如果 Client Secret 被洩露，攻擊者可以使用它來獲取 access token
- **建議**：
  - 定期輪換 Client Secret
  - 不要在公共場所或共享環境中暴露 Client Secret
  - 如果懷疑 Client Secret 已洩露，立即在 Google Cloud Console 中撤銷並重新生成

### Token 安全
- **Token 保存在本地文件**：
  - Google CLI 認證：`~/.burp_google_token_gcloud.json`
  - OAuth 2.0 認證：`~/.burp_google_token_oauth2.json`
- **建議**：
  - 保護本地 token 文件，避免被未授權訪問
  - 定期檢查 token 文件權限
  - 如果懷疑 token 已洩露，立即撤銷授權並重新獲取

## 授權與免責聲明

本擴充套件僅供學習和研究使用。使用時請遵守：
- Google Sheets API 使用條款
- Google OAuth 2.0 使用條款
- 相關數據保護法規
- 組織的資訊安全政策

## 聯絡與支援

如有問題或建議，請查看：
- Burp Suite 輸出標籤中的 DEBUG 訊息
- Google Cloud Console 的 API 使用日誌
- Google Sheets API 文件：https://developers.google.com/sheets/api
- Google OAuth 2.0 文件：https://developers.google.com/identity/protocols/oauth2

---

**最後更新**: 2025年1月



