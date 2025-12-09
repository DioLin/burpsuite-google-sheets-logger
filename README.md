# Burp Suite Google Sheets Logger Extension

## 專案概述

這是一個 Burp Suite 擴充套件，用於將 HTTP 請求的參數和完整請求內容自動記錄到 Google Sheets 中。擴充套件支援從 gcloud CLI 獲取認證 token，並提供智能的空行查找和數據覆蓋保護機制。

## 主要功能

### 1. HTTP 請求記錄
- 自動提取選中的 HTTP 請求資訊
- 提取 URL、參數列表和完整請求內容
- 將數據寫入 Google Sheets 的 I、J、K 欄位（跳過受保護的 A-H 欄位）

### 2. Token 管理
- 透過 gcloud CLI 自動獲取 Google OAuth access token
- Token 本地緩存機制（保存至 `~/.burp_google_token.json`）
- Token 有效性自動驗證
- 支援 Windows、Linux、macOS 多平台

### 3. 智能行號管理
- 自動查找第一個 B、D、I 欄位都為空的行
- 支援自訂行號輸入
- 覆蓋保護機制：當自訂行號已有數據時，顯示確認對話框

### 4. 用戶界面
- 配置對話框：設定 Spreadsheet ID、Sheet 名稱、Project ID、Token
- 一鍵獲取 Token 按鈕
- 數據預覽和編輯對話框
- 完整的錯誤提示和調試資訊

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

#### Token 管理方法
- `_get_gcloud_token()`: 從 gcloud CLI 獲取 access token
  - 先檢查本地緩存的 token 是否有效
  - 執行 `gcloud auth application-default print-access-token` 命令
  - 處理跨平台命令執行（Windows/Linux/macOS）
  - 設置環境變數和 PATH
  - 使用 ProcessBuilder 執行外部命令
  - 讀取命令輸出並提取 token
  - 保存 token 到本地文件

- `_save_token_to_file(token)`: 保存 token 到本地 JSON 文件
- `_load_token_from_file()`: 從本地文件載入 token
- `_check_token_valid(token)`: 透過 Google tokeninfo API 驗證 token 有效性
- `_get_token_file_path()`: 獲取 token 文件路徑（`~/.burp_google_token.json`）
- `_create_token_fetcher(txt_token)`: 創建「從 gcloud 獲取 Token」按鈕的事件處理器

#### 表單讀取方法
- `_read_sheet_data()`: 讀取 Google Sheets 數據（A1:I1000 範圍）
  - 使用 Google Sheets API v4 讀取數據
  - 提取每行的 B、D、I 欄位值
  - 處理 403 權限錯誤並提供詳細指引

- `_find_empty_row(rows_data)`: 找到第一個 B、D、I 都為空的行

#### 數據寫入方法
- `send_to_sheet(event)`: 主入口方法，處理右鍵選單點擊事件
  - 驗證配置
  - 提取 HTTP 請求資訊（URL、參數、完整請求）
  - 讀取表單數據並找到空行
  - 顯示數據預覽和編輯對話框
  - 處理自訂行號和覆蓋確認
  - 啟動背景線程執行寫入操作

- `post_to_api(data)`: 將數據寫入 Google Sheets
  - 構建 API URL（例如：`弱點清單!I5:K5`）
  - 發送 PUT 請求更新指定範圍
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
2. 右鍵點擊 → 選擇 "[G-Sheet] Send to I/J/K"
   ↓
3. 驗證配置（sheet_id, access_token）
   ↓
4. 提取請求資訊（URL, 參數, 完整請求）
   ↓
5. 讀取 Google Sheets 數據（A1:I1000）
   ↓
6. 找到第一個空行（B、D、I 都為空）
   ↓
7. 顯示數據預覽對話框（可編輯行號）
   ↓
8. 檢查是否需要覆蓋確認
   ↓
9. 發送 PUT 請求更新 Google Sheets（I、J、K 欄位）
   ↓
10. 顯示成功/錯誤訊息
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

### 前置需求

1. **Burp Suite Professional** 或 **Community Edition**
2. **Google Cloud SDK (gcloud CLI)** 已安裝並配置
   - 下載：https://cloud.google.com/sdk/docs/install
   - 執行 `gcloud auth application-default login` 進行認證
3. **Google Cloud Project** 已啟用 Google Sheets API
4. **Google Sheets** 文件已創建，並具有適當的權限

### 安裝步驟

1. 將 `gform_logger_gcloud_v5.py` 複製到本地目錄
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
   - **Spreadsheet ID**: Google Sheets 文件的 ID（從 URL 中獲取）
     - 例如：`1ktp1WhqJMHOUvriQ3voq3oERAPTJLMZrjI0SCjUSVhc`
   - **Target Sheet Name**: 目標工作表名稱（例如：`弱點清單`）
   - **GCP Project ID**: Google Cloud Project ID（例如：`chtpt-burp-logger-001`）
   - **OAuth Token**: 點擊「從 gcloud 獲取 Token」按鈕自動獲取

#### Token 獲取

1. 確保已執行 `gcloud auth application-default login`
2. 在配置對話框中點擊「從 gcloud 獲取 Token」
3. 等待幾秒鐘，token 會自動填入並保存到本地

### 使用方式

1. 在 Burp Suite 的 Proxy、Repeater 或任何地方選擇一個 HTTP 請求
2. 右鍵點擊 → 選擇 `[G-Sheet] Send to I/J/K (Skip Protected)`
3. 在彈出的對話框中：
   - 檢查或修改「項次（行號）」（預設為自動找到的第一個空行）
   - 檢查 URL、參數和請求內容
   - 點擊 `OK` 確認寫入
4. 如果指定的行號已有數據，會顯示確認對話框
5. 寫入成功後會顯示提示訊息

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
**錯誤訊息**: `權限錯誤 (403): Permission denied`

**解決方案**:
1. 確認 Google Cloud Project 已啟用 Google Sheets API
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
└── ~/.burp_google_token.json    # Token 緩存文件（自動生成）
```

## 配置參數說明

### config 字典

```python
{
    "sheet_id": "",              # Google Sheets 文件 ID
    "access_token": "",          # OAuth 2.0 Access Token
    "project_id": "chtpt-burp-logger-001",  # Google Cloud Project ID（可選）
    "sheet_name": u"弱點清單"    # 目標工作表名稱
}
```

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

- **v5**: 當前版本
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

**最後更新**: 2024年

