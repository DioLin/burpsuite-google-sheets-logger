# Burp Suite Google Sheets Logger Extension

## 專案概述

這是一個 Burp Suite 擴充套件，用於將 HTTP 請求的參數和完整請求內容自動記錄到 Google Sheets 中。擴充套件支援從 gcloud CLI 獲取認證 token，並提供智能的空行查找和數據覆蓋保護機制。

## 前置需求

1. **Burp Suite Professional** 或 **Community Edition**
2. **Google Cloud SDK (gcloud CLI)** 已安裝並配置

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

3. **Google Sheets** 文件已創建，並具有適當的權限

## 主要功能

### 1. HTTP 請求記錄
- 自動提取選中的 HTTP 請求資訊
- 提取 URL、參數列表和完整請求內容
- 自動提取發現日期（從 HTTP 請求時間戳記或當前日期）
- 將數據寫入 Google Sheets 的 I、J、K、O、P 欄位（跳過受保護的 A-H 欄位）
  - I 欄位：URL
  - J 欄位：參數列表
  - K 欄位：完整請求內容
  - O 欄位：測試人員
  - P 欄位：發現日期

### 2. Token 管理
- 透過 gcloud CLI 自動獲取 Google OAuth access token
- Token 本地緩存機制（保存至 `~/.burp_google_token.json`）
- Token 有效性自動驗證和自動刷新機制
- Token 即將過期時（少於 5 分鐘）自動提前刷新
- 401 錯誤時自動嘗試刷新 token 並重試
- 顯示當前 token 的 email 資訊
- 支援 Windows、Linux、macOS 多平台

### 3. 智能行號管理
- 自動查找第一個 B、D、I 欄位都為空的行
- 支援自訂行號輸入
- 覆蓋保護機制：當自訂行號已有數據時，顯示確認對話框

### 4. 用戶界面
- 配置對話框：設定 Spreadsheet ID、Sheet 名稱、Project ID、Token
- 一鍵獲取 Token 按鈕
- Email 查詢功能：通過 email 查詢可用的 Spreadsheet 列表
- Spreadsheet 下拉選單：從查詢結果中選擇 Spreadsheet，自動填充 ID
- 數據預覽和編輯對話框（包含測試人員和發現日期欄位）
- 最終確認對話框：顯示 Google 文件名稱、工作表名稱和行號
- 完整的錯誤提示和調試資訊
- Token Email 顯示：在配置對話框中顯示當前 token 對應的 email

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
- `show_config_dialog(event)`: 顯示配置對話框，允許用戶設定 Spreadsheet ID、Sheet 名稱、Project ID 和 Token
- `_save_config_to_file()`: 保存配置到本地文件（`~/.burp_google_config.json`），不包含敏感資訊如 access_token
- `_load_config_from_file()`: 從本地文件載入配置（sheet_id、project_id、sheet_name、email）

#### Token 管理方法
- `_get_gcloud_token()`: 從 gcloud CLI 獲取 access token
  - 先檢查本地緩存的 token 是否有效
  - 執行 `gcloud auth application-default print-access-token` 命令
  - 處理跨平台命令執行（Windows/Linux/macOS）
  - 設置環境變數和 PATH
  - 使用 ProcessBuilder 執行外部命令
  - 讀取命令輸出並提取 token
  - 驗證 token 有效性後保存到本地文件

- `_save_token_to_file(token)`: 保存 token 到本地 JSON 文件
- `_load_token_from_file()`: 從本地文件載入 token，驗證有效性並獲取 email
- `_check_token_valid(token)`: 透過 Google tokeninfo API 驗證 token 有效性
- `_ensure_valid_token()`: 確保 token 有效，無效時自動刷新，即將過期時提前刷新
- `_get_token_info(token)`: 獲取 token 的詳細資訊（email、user_id、expires_in 等）
- `_get_gcloud_email()`: 使用 gcloud 命令獲取當前登錄的 email（作為備用方案）
- `_get_token_file_path()`: 獲取 token 文件路徑（`~/.burp_google_token.json`）
- `_create_token_fetcher(txt_token, txt_query_email)`: 創建「從 gcloud 獲取 Token」按鈕的事件處理器

#### 表單讀取方法
- `_read_sheet_data()`: 讀取 Google Sheets 數據（A1:I1000 範圍）
  - 使用 Google Sheets API v4 讀取數據
  - 提取每行的 B、D、I 欄位值
  - 處理 403 權限錯誤並提供詳細指引

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
  - 提取 HTTP 請求資訊（URL、參數、完整請求）
  - 自動提取發現日期（從請求時間戳記或當前日期）
  - 讀取表單數據並找到空行
  - 顯示數據預覽和編輯對話框（包含測試人員和發現日期欄位）
  - 處理自訂行號和覆蓋確認
  - 顯示最終確認對話框（包含 Google 文件名稱、工作表名稱和行號）
  - 啟動背景線程執行寫入操作

- `post_to_api(data)`: 將數據寫入 Google Sheets
  - 確保 token 有效（自動刷新）
  - 構建 API URL 分別寫入 I:K 和 O:P 欄位（例如：`弱點清單!I5:K5` 和 `弱點清單!O5:P5`）
  - 發送 PUT 請求更新指定範圍
  - 401 錯誤時自動刷新 token 並重試
  - 處理 API 回應和錯誤
  - 提供詳細的錯誤訊息和調試資訊

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
- **gcloud CLI**: 用於獲取 OAuth access token

### 使用的 API

#### Google Sheets API
- **讀取數據**: `GET /v4/spreadsheets/{spreadsheetId}/values/{range}`
- **更新數據**: `PUT /v4/spreadsheets/{spreadsheetId}/values/{range}?valueInputOption=USER_ENTERED`
- **認證**: Bearer Token (OAuth 2.0 Access Token)

#### Google OAuth Token Info API
- **驗證 Token**: `GET /oauth2/v1/tokeninfo?access_token={token}`

### 數據流程

```
1. 用戶在 Burp Suite 中選擇 HTTP 請求
   ↓
2. 右鍵點擊 → 選擇 "[G-Sheet] Send to I/J/K/O/P"
   ↓
3. 驗證配置（sheet_id, access_token），必要時自動刷新 token
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
10. 確保 token 有效後，發送 PUT 請求更新 Google Sheets
    - 先寫入 I、J、K 欄位（URL、參數、完整請求）
    - 再寫入 O、P 欄位（測試人員、發現日期）
   ↓
11. 如果 401 錯誤，自動刷新 token 並重試
   ↓
12. 顯示成功/錯誤訊息
```

### Token 獲取流程

```
1. 用戶點擊「從 gcloud 獲取 Token」按鈕
   ↓
2. 檢查本地 token 文件（~/.burp_google_token.json）
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

## 安裝與使用

### 安裝步驟

1. 將 `gform_logger_gcloud_v5.py` 複製到本地目錄
   - **重要**: 請確保文件路徑**不包含中文字符或特殊字符**
   - 建議路徑範例：`C:\BurpExtensions\gform_logger_gcloud_v5.py` 或 `D:\tools\gform_logger_gcloud_v5.py`
   - 避免使用包含中文的路徑，例如：`C:\Users\...\Documents\01_資料夾\...`（可能會導致載入失敗）
2. 在 Burp Suite 中：
   - 進入 `Extender` → `Extensions` → `Add`
   - 選擇 `Extension type: Python`
   - 點擊 `Select file...` 選擇 `gform_logger_gcloud_v5.py`
   - 點擊 `Next` 確認載入成功

### 配置說明

#### 首次配置

1. 在 Burp Suite 中右鍵點擊任意 HTTP 請求
2. 選擇 `[G-Sheet] Configuration`
3. 填寫以下資訊：
   - **查詢 Email**（可選）: 輸入 email 地址，然後點擊「查詢 Spreadsheet 列表」按鈕
     - 查詢成功後，可從下拉選單中選擇 Spreadsheet，會自動填入 Spreadsheet ID
   - **Spreadsheet ID**: Google Sheets 文件的 ID
     - 可從查詢結果下拉選單中選擇，或手動從 URL 中獲取
     - 例如：`1ktp1WhqJMHOUvriQ3voq3oERAPTJLMZrjI0SCjUSVhc`
   - **Target Sheet Name**: 目標工作表名稱（例如：`弱點清單`）
     - 從下拉選單選擇 Spreadsheet 時不會覆蓋此欄位
   - **GCP Project ID**: Google Cloud Project ID（例如：`chtpt-burp-logger-001`）
   - **OAuth Token**: 點擊「從 gcloud 獲取 Token」按鈕自動獲取
     - 獲取 token 後會自動顯示對應的 email，並自動填入「查詢 Email」欄位

#### Spreadsheet 列表查詢

1. 在配置對話框中輸入 email 地址
2. 點擊「查詢 Spreadsheet 列表」按鈕
3. 等待查詢完成（會在背景執行）
4. 查詢成功後，從「可選 Spreadsheet」下拉選單中選擇目標 Spreadsheet
5. Spreadsheet ID 會自動填入，但 Target Sheet Name 不會被覆蓋

#### Token 獲取

1. 確保已執行 `gcloud auth application-default login`
2. 在配置對話框中點擊「從 gcloud 獲取 Token」
3. 等待幾秒鐘，token 會自動填入並保存到本地
4. Token 獲取成功後會顯示對應的 email 資訊
5. Email 會自動填入「查詢 Email」欄位，方便後續查詢 Spreadsheet 列表

**注意**: 配置會自動保存到 `~/.burp_google_config.json`，下次開啟配置對話框時會自動載入（但 token 不會保存到配置文件中）。

### 使用方式

1. 在 Burp Suite 的 Proxy、Repeater 或任何地方選擇一個 HTTP 請求
2. 右鍵點擊 → 選擇 `[G-Sheet] Send to I/J/K/O/P`
3. 在彈出的對話框中：
   - 檢查或修改「項次（行號）」（預設為自動找到的第一個空行）
   - 檢查 URL（I 欄位）、參數（J 欄位）和請求內容（K 欄位）
   - 填寫或檢查「測試人員」（O 欄位）
   - 檢查「發現日期」（P 欄位，自動從請求時間戳記提取，可編輯）
   - 點擊 `OK` 確認寫入
4. 如果指定的行號已有數據，會顯示覆蓋確認對話框
5. 顯示最終確認對話框，確認 Google 文件名稱、工作表名稱和行號
6. 寫入成功後會顯示提示訊息

## 錯誤處理

### 常見錯誤及解決方案

#### 1. Token 獲取失敗
**錯誤訊息**: `gcloud 命令執行失敗` 或 `執行超時`

**解決方案**:
- 確認 gcloud CLI 已正確安裝
- 執行 `gcloud auth application-default login` 進行認證
- 檢查 PATH 環境變數是否包含 gcloud 路徑
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
   - 前往錯誤訊息中提供的連結（例如：https://console.developers.google.com/apis/api/sheets.googleapis.com/overview?project=chtpt-burp-logger-050）
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
**錯誤訊息**: `文件中的 token 已過期，需要重新獲取`

**解決方案**:
- 點擊「從 gcloud 獲取 Token」按鈕重新獲取
- 或手動執行 `gcloud auth application-default print-access-token` 獲取新 token

#### 4. 無法讀取表單數據
**錯誤訊息**: `無法讀取表單數據` 或 `讀取表單失敗`

**解決方案**:
- 確認 Spreadsheet ID 正確
- 確認 Sheet 名稱正確（區分大小寫）
- 確認 token 有效且有讀取權限
- 檢查 Google Sheets 文件是否為公開或已授予適當權限

#### 5. Unicode 編碼錯誤
**錯誤訊息**: `'ascii' codec can't encode/decode`

**解決方案**:
- 程式已內建 `safe_unicode_convert()` 函數處理此問題
- 如果仍出現錯誤，請檢查輸入數據的編碼格式

#### 6. 路徑錯誤 (Invalid argument)
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

## 調試資訊

程式包含詳細的 DEBUG 日誌，可在 Burp Suite 的 `Output` 標籤中查看：

- Token 獲取過程的詳細日誌
- 命令執行狀態和輸出
- API 請求 URL 和回應
- 錯誤堆疊追蹤

## 文件結構

```
burpsuite-plugin/
├── gform_logger_gcloud_v5.py    # 主程式文件
├── README.md                    # 專案文件說明（本文件）
├── ~/.burp_google_token.json    # Token 緩存文件（自動生成）
└── ~/.burp_google_config.json   # 配置緩存文件（自動生成，不包含 access_token）
```

## 配置參數說明

### config 字典

```python
{
    "sheet_id": "",              # Google Sheets 文件 ID
    "access_token": "",          # OAuth 2.0 Access Token（僅存在記憶體中，不保存到文件）
    "project_id": "chtpt-burp-logger-001",  # Google Cloud Project ID（可選）
    "sheet_name": u"弱點清單",   # 目標工作表名稱
    "email": ""                  # 當前 token 對應的 email（用於查詢 Spreadsheet 列表）
}
```

注意：`access_token` 不會保存到配置文件中（僅保存在 `~/.burp_google_token.json`），其他配置會自動保存到 `~/.burp_google_config.json`。

### Token 文件格式

`~/.burp_google_token.json`:
```json
{
    "access_token": "ya29.xxx...",
    "saved_at": 1234567890.123
}
```

## 開發歷史

### 版本演進

- **v5** (當前版本): 最新功能更新
  - **新增 O/P 欄位支援**：現在支援寫入測試人員（O 欄位）和發現日期（P 欄位）
  - **自動日期提取**：從 HTTP 請求時間戳記自動提取發現日期，無時間戳記時使用當前日期
  - **Spreadsheet 列表查詢功能**：通過 email 查詢可用的 Spreadsheet 列表，支援下拉選單選擇
  - **配置持久化**：配置（sheet_id、project_id、sheet_name、email）自動保存到 `~/.burp_google_config.json`
  - **Token 自動刷新機制**：
    - 當 token 過期時自動刷新
    - token 即將過期（少於 5 分鐘）時提前刷新
    - API 請求遇到 401 錯誤時自動刷新並重試
  - **Email 管理功能**：
    - 顯示當前 token 對應的 email
    - email 自動保存到配置中
    - 支援從 tokeninfo API 或 gcloud 命令獲取 email
  - **最終確認對話框**：上傳前顯示 Google 文件名稱、工作表名稱和行號的確認資訊
  - **改進的錯誤處理**：更詳細的錯誤訊息和自動重試機制
  - **Spreadsheet 資訊查詢**：可獲取 Spreadsheet 名稱和工作表列表，用於錯誤診斷

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
3. **外部命令執行**: 依賴系統 PATH 環境變數，Windows 需要額外處理
4. **API 限制**: 受 Google Sheets API 配額限制（每分鐘請求數）

## 授權與免責聲明

本擴充套件僅供學習和研究使用。使用時請遵守：
- Google Sheets API 使用條款
- 相關數據保護法規
- 組織的資訊安全政策

## 聯絡與支援

如有問題或建議，請查看：
- Burp Suite 輸出標籤中的 DEBUG 訊息
- Google Cloud Console 的 API 使用日誌
- Google Sheets API 文件：https://developers.google.com/sheets/api

---

**最後更新**: 2025年12月

