# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IParameter
from javax.swing import JMenuItem, JOptionPane, JPanel, JLabel, JTextField, Box, BoxLayout, JTextArea, JScrollPane, JButton, JComboBox
from java.util import ArrayList
from java.awt import Dimension
from java.lang import ProcessBuilder, Runtime
import urllib
import urllib2
import threading
import json
import os
import time
import codecs
from java.io import BufferedReader, InputStreamReader, File

def safe_unicode_convert(val):
    """安全地將各種類型的值轉換為 Unicode"""
    if val is None:
        return u""
    if isinstance(val, unicode):
        return val
    if isinstance(val, str):
        # 在 Jython 中，str 可能是 bytes
        try:
            # 先嘗試 UTF-8 解碼
            return unicode(val, 'utf-8', errors='ignore')
        except (UnicodeDecodeError, UnicodeError):
            try:
                # 如果 UTF-8 失敗，嘗試 latin-1
                return unicode(val, 'latin-1', errors='ignore')
            except (UnicodeDecodeError, UnicodeError):
                try:
                    # 最後嘗試使用 repr 然後解碼
                    repr_val = repr(val)
                    return unicode(repr_val, 'utf-8', errors='ignore')
                except:
                    return u"[無法解碼]"
    # 對於其他類型，先轉為字符串
    try:
        # 使用 repr 來安全地轉換
        repr_val = repr(val)
        try:
            return unicode(repr_val, 'utf-8', errors='ignore')
        except:
            try:
                return unicode(repr_val, 'latin-1', errors='ignore')
            except:
                return u"[轉換失敗]"
    except:
        return u"[無法轉換]"

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("G-Sheet logger v1")
        self._callbacks.registerContextMenuFactory(self)
        
        # 設定預設值
        self.config = {
            "sheet_id": "",
            "access_token": "",
            "project_id": "chtpt-burp-logger-001",
            "sheet_name": u"弱點清單",
            "email": ""
        }
        
        # 載入已保存的配置
        self._load_config_from_file()
        
        # 載入已保存的 token
        self._load_token_from_file()
        
    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_send = JMenuItem(u"[G-Sheet] Send to I/J/K/O/P", actionPerformed=self.send_to_sheet)
        menu_config = JMenuItem(u"[G-Sheet] Configuration", actionPerformed=self.show_config_dialog)
        menu_list.add(menu_send)
        menu_list.add(menu_config)
        return menu_list

    def show_config_dialog(self, event=None):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        
        txt_id = JTextField(self.config["sheet_id"], 40)
        txt_sheet_name = JTextField(safe_unicode_convert(self.config["sheet_name"]), 40)
        txt_project = JTextField(self.config["project_id"], 40)
        txt_token = JTextArea(safe_unicode_convert(self.config["access_token"]))
        txt_token.setLineWrap(True)
        scroll_token = JScrollPane(txt_token)
        scroll_token.setPreferredSize(Dimension(400, 100))
        
        # 顯示當前 token 的 email（優先使用配置中的 email）
        token_email_label = JLabel(u"")
        current_email = self.config.get("email", "")
        if self.config.get("access_token"):
            # 優先使用配置中已保存的 email
            if current_email:
                token_email_label.setText(u"當前 Token Email: " + current_email)
            else:
                # 如果配置中沒有 email，則從 token 獲取
                token_info = self._get_token_info(self.config["access_token"])
                if token_info and token_info.get("email"):
                    email = token_info["email"]
                    self.config["email"] = email
                    self._save_config_to_file()
                    current_email = email
                    token_email_label.setText(u"當前 Token Email: " + email)
                else:
                    token_email_label.setText(u"當前 Token Email: 無法獲取")
        else:
            token_email_label.setText(u"當前 Token Email: 未設置")
        
        # 查詢 Spreadsheet 列表相關組件（需要在 btn_get_token 之前定義）
        txt_query_email = JTextField(current_email, 40)
        
        btn_get_token = JButton(u"從 gcloud 獲取 Token", actionPerformed=self._create_token_fetcher(txt_token, txt_query_email))
        combo_sheets = JComboBox([u"請先查詢 Spreadsheet 列表"])
        combo_sheets.setEnabled(False)
        
        # 將 combo_sheets 存儲在 panel 的 client property 中，以便在查詢處理器中訪問
        panel.putClientProperty("combo_sheets", combo_sheets)
        panel.putClientProperty("txt_id", txt_id)
        panel.putClientProperty("txt_sheet_name", txt_sheet_name)
        
        btn_query_sheets = JButton(u"查詢 Spreadsheet 列表", actionPerformed=self._create_sheet_query_handler(txt_query_email, panel))
        
        # 當選擇下拉式選單項目時，只自動填充 sheet_id（不覆蓋 Target Sheet Name）
        def on_combo_change(event):
            selected_item = combo_sheets.getSelectedItem()
            if selected_item and selected_item != u"請先查詢 Spreadsheet 列表":
                # selected_item 格式: "display_text|sheetid|project"
                if "|" in selected_item:
                    parts = selected_item.split("|")
                    if len(parts) >= 2:
                        # parts[0] 是顯示文本，parts[1] 是 sheetid
                        sheetid = parts[1]
                        txt_id.setText(sheetid)
                        # 不覆蓋 Target Sheet Name，保持預設值"弱點清單"
        
        combo_sheets.addActionListener(on_combo_change)
        
        panel.add(JLabel(u"查詢 Email:"))
        panel.add(txt_query_email)
        panel.add(Box.createVerticalStrut(5))
        panel.add(btn_query_sheets)
        panel.add(Box.createVerticalStrut(5))
        panel.add(JLabel(u"可選 Spreadsheet:"))
        panel.add(combo_sheets)
        panel.add(Box.createVerticalStrut(5))
        panel.add(JLabel(u"Spreadsheet ID:"))
        panel.add(txt_id)
        panel.add(Box.createVerticalStrut(5))
        panel.add(JLabel(u"Target Sheet Name:"))
        panel.add(txt_sheet_name)
        panel.add(Box.createVerticalStrut(5))
        panel.add(JLabel(u"GCP Project ID:"))
        panel.add(txt_project)
        panel.add(Box.createVerticalStrut(5))
        panel.add(JLabel(u"OAuth Token:"))
        panel.add(scroll_token)
        panel.add(Box.createVerticalStrut(5))
        panel.add(token_email_label)
        panel.add(Box.createVerticalStrut(5))
        panel.add(btn_get_token)

        result = JOptionPane.showConfirmDialog(None, panel, u"API Settings", JOptionPane.OK_CANCEL_OPTION)

        if result == JOptionPane.OK_OPTION:
            self.config["sheet_id"] = txt_id.getText().strip()
            self.config["sheet_name"] = txt_sheet_name.getText().strip()
            self.config["project_id"] = txt_project.getText().strip()
            self.config["access_token"] = txt_token.getText().strip()
            
            # 保存配置到文件
            self._save_config_to_file()
            
            return True
        return False

    def _get_config_file_path(self):
        """獲取配置文件路徑"""
        home = os.path.expanduser("~")
        return os.path.join(home, ".burp_google_config.json")
    
    def _get_token_file_path(self):
        """獲取 token 文件路徑"""
        home = os.path.expanduser("~")
        return os.path.join(home, ".burp_google_token.json")
    
    def _save_config_to_file(self):
        """保存配置到本地文件"""
        try:
            config_file = self._get_config_file_path()
            # 只保存非敏感配置（不包含 access_token）
            # 確保所有值都是 unicode 字符串
            config_to_save = {
                "sheet_id": safe_unicode_convert(self.config.get("sheet_id", "")),
                "project_id": safe_unicode_convert(self.config.get("project_id", "")),
                "sheet_name": safe_unicode_convert(self.config.get("sheet_name", "")),
                "email": safe_unicode_convert(self.config.get("email", "")),
                "saved_at": time.time()
            }
            
            # 確保所有字符串值都是 unicode（json.dump 需要）
            for key, value in config_to_save.items():
                if key != "saved_at" and not isinstance(value, unicode):
                    if isinstance(value, str):
                        try:
                            config_to_save[key] = unicode(value, 'utf-8')
                        except:
                            config_to_save[key] = safe_unicode_convert(value)
                    else:
                        config_to_save[key] = safe_unicode_convert(value)
            
            with codecs.open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_to_save, f, ensure_ascii=False)
            print((u"DEBUG: Configuration saved to: " + config_file).encode('utf-8'))
        except Exception as e:
            error_msg = u"Failed to save configuration: " + safe_unicode_convert(str(e))
            print((u"DEBUG: " + error_msg).encode('utf-8'))
    
    def _load_config_from_file(self):
        """從本地文件載入配置"""
        try:
            config_file = self._get_config_file_path()
            if os.path.exists(config_file):
                with codecs.open(config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                    # 載入配置（不覆蓋 access_token）
                    if "sheet_id" in config_data:
                        self.config["sheet_id"] = safe_unicode_convert(config_data.get("sheet_id", ""))
                    if "project_id" in config_data:
                        self.config["project_id"] = safe_unicode_convert(config_data.get("project_id", ""))
                    if "sheet_name" in config_data:
                        self.config["sheet_name"] = safe_unicode_convert(config_data.get("sheet_name", ""))
                    if "email" in config_data:
                        self.config["email"] = safe_unicode_convert(config_data.get("email", ""))
                    print("DEBUG: Configuration loaded from file")
        except Exception as e:
            print("DEBUG: Failed to load configuration: " + str(e))
    
    def _save_token_to_file(self, token):
        """保存 token 到本地文件"""
        try:
            token_file = self._get_token_file_path()
            token_data = {
                "access_token": safe_unicode_convert(token),
                "saved_at": time.time()
            }
            with codecs.open(token_file, 'w', encoding='utf-8') as f:
                json.dump(token_data, f, ensure_ascii=False)
            print(("DEBUG: Token saved to: " + token_file).encode('utf-8'))
        except Exception as e:
            error_msg = u"Failed to save token: " + safe_unicode_convert(str(e))
            print(("DEBUG: " + error_msg).encode('utf-8'))
    
    def _load_token_from_file(self):
        """從本地文件載入 token"""
        try:
            token_file = self._get_token_file_path()
            if os.path.exists(token_file):
                with codecs.open(token_file, 'r', encoding='utf-8') as f:
                    token_data = json.load(f)
                    token = token_data.get("access_token", "")
                    if token:
                        # 確保 token 是字符串類型
                        token = safe_unicode_convert(token)
                        # 檢查 token 是否有效
                        if self._check_token_valid(token):
                            self.config["access_token"] = token
                            # 獲取並保存 email
                            token_info = self._get_token_info(token)
                            if token_info and token_info.get("email"):
                                self.config["email"] = token_info["email"]
                                self._save_config_to_file()
                            print("DEBUG: Valid token loaded from file".encode('utf-8'))
                        else:
                            print("DEBUG: Token in file has expired, need to re-acquire".encode('utf-8'))
        except Exception as e:
            error_msg = u"Failed to load token: " + safe_unicode_convert(str(e))
            print(("DEBUG: " + error_msg).encode('utf-8'))
            import traceback
            print(("DEBUG: Detailed stack trace: " + traceback.format_exc()).encode('utf-8'))
    
    def _get_token_info(self, token):
        """獲取 token 的詳細信息（包括 email）"""
        try:
            # 確保 token 是字符串類型
            token_str = safe_unicode_convert(token)
            url = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + urllib.quote(token_str.encode('utf-8'))
            debug_url = u"DEBUG: Attempting to get token info, URL: " + safe_unicode_convert(url[:100]) + u"..."
            print(debug_url.encode('utf-8'))
            req = urllib2.Request(url)
            response = urllib2.urlopen(req)
            response_body = response.read()
            response_body_str = safe_unicode_convert(response_body)
            debug_response = u"DEBUG: Token info API response: " + response_body_str[:200]
            print(debug_response.encode('utf-8'))
            result = json.loads(response_body_str)
            
            if "error" in result:
                error_msg = safe_unicode_convert(result.get("error", u"Unknown error"))
                debug_error = u"DEBUG: Token info API returned error: " + error_msg
                print(debug_error.encode('utf-8'))
                return None
            
            # 檢查是否有 email 字段
            email = result.get("email", "")
            if not email:
                # 嘗試使用 gcloud 命令獲取當前用戶信息
                print("DEBUG: No email in token info, attempting to get from gcloud command...".encode('utf-8'))
                gcloud_email = self._get_gcloud_email()
                if gcloud_email:
                    email = gcloud_email
                    email_unicode = safe_unicode_convert(email)
                    debug_email = u"DEBUG: Got email from gcloud: " + email_unicode
                    print(debug_email.encode('utf-8'))
            
            token_info = {
                "email": safe_unicode_convert(email),
                "user_id": safe_unicode_convert(result.get("user_id", "")),
                "expires_in": result.get("expires_in", 0),
                "scope": safe_unicode_convert(result.get("scope", "")),
                "audience": safe_unicode_convert(result.get("audience", ""))
            }
            return token_info
        except urllib2.HTTPError as e:
            error_body = ""
            try:
                error_body = safe_unicode_convert(e.read())
            except:
                pass
            debug_http = u"DEBUG: HTTP error " + safe_unicode_convert(str(e.code)) + u": " + error_body[:200]
            print(debug_http.encode('utf-8'))
            if e.code == 400:
                # 嘗試使用 gcloud 命令獲取 email
                print("DEBUG: Token info API returned 400, attempting to get email from gcloud command...".encode('utf-8'))
                gcloud_email = self._get_gcloud_email()
                if gcloud_email:
                    return {"email": gcloud_email, "user_id": "", "expires_in": 0, "scope": "", "audience": ""}
            return None
        except Exception as e:
            try:
                error_msg = safe_unicode_convert(str(e))
                debug_msg = u"DEBUG: Error occurred while getting token info: " + error_msg
                print(debug_msg.encode('utf-8'))
            except:
                print("DEBUG: Error occurred while getting token info (unable to display details)".encode('utf-8'))
            try:
                import traceback
                traceback_str = safe_unicode_convert(traceback.format_exc())
                debug_trace = u"DEBUG: Detailed stack trace: " + traceback_str
                print(debug_trace.encode('utf-8'))
            except:
                print("DEBUG: Unable to display detailed stack trace".encode('utf-8'))
            # 嘗試使用 gcloud 命令獲取 email
            gcloud_email = self._get_gcloud_email()
            if gcloud_email:
                return {"email": gcloud_email, "user_id": "", "expires_in": 0, "scope": "", "audience": ""}
            return None
    
    def _get_gcloud_email(self):
        """使用 gcloud 命令獲取當前登錄的 email"""
        try:
            # 檢測操作系統
            is_windows = False
            is_mac = False
            if os.name == 'nt' or os.path.sep == '\\' or os.environ.get('WINDIR'):
                is_windows = True
            elif os.name == 'posix':
                # 檢測 macOS
                try:
                    import platform
                    if platform.system() == 'Darwin':
                        is_mac = True
                except:
                    # 備用方法：檢查常見的 macOS 路徑
                    if os.path.exists('/Applications') or os.path.exists('/usr/local/Caskroom'):
                        is_mac = True
            
            # 構建命令：gcloud config get-value account
            cmd_base = ["gcloud", "config", "get-value", "account"]
            if is_windows:
                cmd = ["cmd", "/c"] + cmd_base
            else:
                cmd = cmd_base
            
            cmd_str = u" ".join([safe_unicode_convert(c) for c in cmd])
            debug_cmd = u"DEBUG: Executing command to get gcloud email: " + cmd_str
            print(debug_cmd.encode('utf-8'))
            
            # 執行命令
            process = ProcessBuilder(cmd)
            process.redirectErrorStream(True)
            
            # 設置環境變量（確保 gcloud 在 PATH 中）
            env = process.environment()
            path_var = env.get("PATH")
            if path_var is None:
                path_var = ""
            
            # 添加常見的 gcloud 安裝路徑
            common_paths = []
            if is_windows:
                # Windows: 添加常見的 gcloud 路徑
                common_paths = [
                    os.path.join(os.environ.get('APPDATA', ''), '..', 'Local', 'Google', 'Cloud SDK', 'google-cloud-sdk', 'bin'),
                    os.path.join(os.environ.get('ProgramFiles', ''), 'Google', 'Cloud SDK', 'google-cloud-sdk', 'bin'),
                ]
            elif is_mac:
                # macOS: 添加常見的 gcloud 路徑
                common_paths = [
                    os.path.join(os.path.expanduser("~"), "google-cloud-sdk", "bin"),
                    "/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin",
                    "/usr/local/bin"
                ]
            else:
                # Linux/Unix: 添加常見的 gcloud 路徑
                common_paths = [
                    os.path.join(os.path.expanduser("~"), "google-cloud-sdk", "bin"),
                    "/usr/local/bin"
                ]
            
            for p in common_paths:
                if os.path.exists(p) and p not in path_var:
                    path_var = p + os.pathsep + path_var
            
            if path_var != env.get("PATH"):
                env.put("PATH", path_var)
            
            proc = process.start()
            
            # 讀取輸出
            reader = BufferedReader(InputStreamReader(proc.getInputStream(), "UTF-8"))
            output_lines = []
            line = reader.readLine()
            while line is not None:
                output_lines.append(line)
                line = reader.readLine()
            
            proc.waitFor()
            
            if proc.exitValue() == 0 and output_lines:
                email = output_lines[0].strip()
                if email and "@" in email:
                    email_unicode = safe_unicode_convert(email)
                    debug_email = u"DEBUG: Got email from gcloud: " + email_unicode
                    print(debug_email.encode('utf-8'))
                    return email_unicode
            
            print(u"DEBUG: gcloud command did not return valid email".encode('utf-8'))
            return None
            
        except Exception as e:
            try:
                error_msg = safe_unicode_convert(str(e))
                debug_error = u"DEBUG: Error occurred while getting gcloud email: " + error_msg
                print(debug_error.encode('utf-8'))
            except:
                print(u"DEBUG: Error occurred while getting gcloud email (unable to display details)".encode('utf-8'))
            return None
    
    def _check_token_valid(self, token):
        """檢查 token 是否有效"""
        token_info = self._get_token_info(token)
        return token_info is not None
    
    def _ensure_valid_token(self):
        """確保 token 有效，如果無效則自動刷新"""
        try:
            current_token = self.config.get("access_token", "")
            if not current_token:
                debug_msg = u"DEBUG: [Token Refresh] Token does not exist, attempting to get new token..."
                print(debug_msg.encode('utf-8'))
                token, error = self._get_gcloud_token()
                if token:
                    # 驗證新獲取的 token 是否有效
                    if self._check_token_valid(token):
                        self.config["access_token"] = token
                        self._save_token_to_file(token)
                        debug_success = u"DEBUG: [Token Refresh] Successfully obtained and validated new token"
                        print(debug_success.encode('utf-8'))
                        return True
                    else:
                        error_msg = u"DEBUG: [Token Refresh] Newly obtained token is invalid"
                        print(error_msg.encode('utf-8'))
                        return False
                else:
                    error_msg = u"DEBUG: [Token Refresh] Unable to get token: " + safe_unicode_convert(error or u"Unknown error")
                    print(error_msg.encode('utf-8'))
                    return False
            
            # 檢查 token 是否有效
            debug_check = u"DEBUG: [Token Refresh] Checking current token validity..."
            print(debug_check.encode('utf-8'))
            is_valid = self._check_token_valid(current_token)
            debug_valid = u"DEBUG: [Token Refresh] Token validity check result: " + (u"Valid" if is_valid else u"Invalid")
            print(debug_valid.encode('utf-8'))
            
            if is_valid:
                # 檢查 token 是否即將過期（提前 5 分鐘刷新）
                token_info = self._get_token_info(current_token)
                if token_info and token_info.get("expires_in", 0) > 0:
                    expires_in = token_info.get("expires_in", 0)
                    debug_expires = u"DEBUG: [Token Refresh] Token remaining time: " + str(expires_in) + u" seconds"
                    print(debug_expires.encode('utf-8'))
                    if expires_in < 300:  # 少於 5 分鐘，提前刷新
                        debug_msg = u"DEBUG: [Token Refresh] Token expiring soon (remaining " + str(expires_in) + u" seconds), auto-refreshing..."
                        print(debug_msg.encode('utf-8'))
                        token, error = self._get_gcloud_token()
                        if token:
                            # 驗證新獲取的 token 是否有效
                            if self._check_token_valid(token):
                                self.config["access_token"] = token
                                self._save_token_to_file(token)
                                debug_success = u"DEBUG: [Token Refresh] Successfully refreshed and validated new token"
                                print(debug_success.encode('utf-8'))
                                return True
                            else:
                                error_msg = u"DEBUG: [Token Refresh] Newly refreshed token is invalid"
                                print(error_msg.encode('utf-8'))
                                return False
                        else:
                            error_msg = u"DEBUG: [Token Refresh] Unable to get new token: " + safe_unicode_convert(error or u"Unknown error")
                            print(error_msg.encode('utf-8'))
                            return False
                debug_ok = u"DEBUG: [Token Refresh] Token is valid and not expired, no refresh needed"
                print(debug_ok.encode('utf-8'))
                return True
            else:
                # Token 無效，嘗試刷新
                debug_msg = u"DEBUG: [Token Refresh] Token is invalid, attempting to refresh..."
                print(debug_msg.encode('utf-8'))
                token, error = self._get_gcloud_token()
                if token:
                    # 驗證新獲取的 token 是否有效
                    if self._check_token_valid(token):
                        self.config["access_token"] = token
                        self._save_token_to_file(token)
                        debug_success = u"DEBUG: [Token Refresh] Successfully refreshed and validated new token"
                        print(debug_success.encode('utf-8'))
                        return True
                    else:
                        error_msg = u"DEBUG: [Token Refresh] Newly refreshed token is invalid, failed validation"
                        print(error_msg.encode('utf-8'))
                        return False
                else:
                    error_msg = u"DEBUG: [Token Refresh] Unable to refresh token: " + safe_unicode_convert(error or u"Unknown error")
                    print(error_msg.encode('utf-8'))
                    return False
        except Exception as e:
            error_msg = u"DEBUG: [Token Refresh] Exception occurred while ensuring token validity: " + safe_unicode_convert(str(e))
            print(error_msg.encode('utf-8'))
            import traceback
            try:
                traceback_str = safe_unicode_convert(traceback.format_exc())
                debug_trace = u"DEBUG: [Token Refresh] Detailed stack trace: " + traceback_str
                print(debug_trace.encode('utf-8'))
            except:
                print("DEBUG: [Token Refresh] Unable to display detailed stack trace".encode('utf-8'))
            return False
    
    def _get_gcloud_token(self):
        """從 gcloud CLI 獲取 access token"""
        print("DEBUG: ========== Starting to get gcloud token ==========")
        
        # 先檢查本地是否有有效的 token
        try:
            token_file = self._get_token_file_path()
            if os.path.exists(token_file):
                with open(token_file, 'r') as f:
                    token_data = json.load(f)
                    token = token_data.get("access_token", "")
                    if token and self._check_token_valid(token):
                        print("DEBUG: Using cached local token")
                        return (token, None)
        except Exception as e:
            print("DEBUG: Error checking local token: " + str(e))
        
        print("DEBUG: Need to get new token from gcloud...")
        
        # 檢測作業系統
        is_windows = False
        is_mac = False
        if os.name == 'nt' or os.path.sep == '\\' or os.environ.get('WINDIR'):
            is_windows = True
        elif os.name == 'posix':
            # 檢測 macOS
            try:
                import platform
                if platform.system() == 'Darwin':
                    is_mac = True
            except:
                # 備用方法：檢查常見的 macOS 路徑
                if os.path.exists('/Applications') or os.path.exists('/usr/local/Caskroom'):
                    is_mac = True
        
        print("DEBUG: sys.platform: " + str(os.name))
        print("DEBUG: os.name: " + str(os.name))
        if is_windows:
            print("DEBUG: Detected Windows system via path separator")
        elif is_mac:
            print("DEBUG: Detected macOS system")
        else:
            print("DEBUG: Detected Unix/Linux system")
        
        # 構建命令
        cmd_base = ["gcloud", "auth", "application-default", "print-access-token"]
        if is_windows:
            cmd = ["cmd", "/c"] + cmd_base
            print("DEBUG: Windows system, using full command: " + " ".join(cmd))
        else:
            cmd = cmd_base
            print("DEBUG: Unix/Linux/Mac system, using original command")
        
        print("DEBUG: Preparing to execute command: " + " ".join(cmd))
        
        try:
            # 設置工作目錄
            home_dir = os.path.expanduser("~")
            print("DEBUG: Working directory: " + home_dir)
            
            # 創建 ProcessBuilder
            pb = ProcessBuilder(cmd)
            pb.directory(File(home_dir))
            
            # 設置環境變數（需要添加 gcloud 到 PATH）
            env = pb.environment()
            path_val = env.get("PATH")
            if path_val is None:
                path_val = ""
            
            # 添加常見的 gcloud 安裝路徑
            common_paths = []
            if is_windows:
                common_paths = [
                    os.path.join(os.path.expanduser("~"), "AppData", "Local", "Google", "Cloud SDK", "google-cloud-sdk", "bin"),
                    "C:\\Program Files (x86)\\Google\\Cloud SDK\\google-cloud-sdk\\bin",
                    "C:\\Program Files\\Google\\Cloud SDK\\google-cloud-sdk\\bin"
                ]
            elif is_mac:
                # macOS 常見的 gcloud 安裝路徑
                common_paths = [
                    os.path.join(os.path.expanduser("~"), "google-cloud-sdk", "bin"),
                    "/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin",
                    "/usr/local/bin"
                ]
            else:
                # Linux/Unix 常見的 gcloud 安裝路徑
                common_paths = [
                    os.path.join(os.path.expanduser("~"), "google-cloud-sdk", "bin"),
                    "/usr/local/bin"
                ]
            
            for p in common_paths:
                if os.path.exists(p) and p not in path_val:
                    path_val = p + os.pathsep + path_val
            
            if path_val != env.get("PATH"):
                env.put("PATH", path_val)
                print("DEBUG: Updated PATH environment variable")
            
            # 啟動進程
            process = pb.start()
            
            # 獲取 PID（用於調試）
            try:
                pid_val = process.pid
                if callable(pid_val):
                    pid_info = str(pid_val())
                else:
                    pid_info = str(pid_val)
                print("DEBUG: Process PID: " + pid_info)
            except:
                print("DEBUG: Unable to get process PID")
            
            # 使用單一線程：先等待進程完成，再讀取輸出
            output_lines = []
            error_lines = []
            
            def wait_and_read():
                try:
                    # 等待進程完成（最多 30 秒）
                    finished = process.waitFor()
                    print("DEBUG: Process finished, exit code: " + str(finished))
                    
                    # 讀取標準輸出
                    stdout_reader = BufferedReader(InputStreamReader(process.getInputStream(), "UTF-8"))
                    line = stdout_reader.readLine()
                    while line is not None:
                        output_lines.append(line)
                        print("DEBUG: stdout: " + safe_unicode_convert(line))
                        line = stdout_reader.readLine()
                    stdout_reader.close()
                    
                    # 讀取標準錯誤
                    stderr_reader = BufferedReader(InputStreamReader(process.getErrorStream(), "UTF-8"))
                    line = stderr_reader.readLine()
                    while line is not None:
                        error_lines.append(line)
                        print("DEBUG: stderr: " + safe_unicode_convert(line))
                        line = stderr_reader.readLine()
                    stderr_reader.close()
                    
                except Exception as e:
                    print("DEBUG: Error reading output: " + str(e))
            
            # 啟動讀取線程
            read_thread = threading.Thread(target=wait_and_read)
            read_thread.daemon = True
            read_thread.start()
            
            # 等待讀取線程完成（最多 35 秒）
            read_thread.join(35)
            
            if read_thread.isAlive():
                print("DEBUG: Process execution timeout, attempting to terminate...")
                process.destroy()
                error_msg = u"Execution timeout (exceeded 30 seconds)"
                if error_lines:
                    error_msg += u"\nError message: " + safe_unicode_convert("\n".join(error_lines))
                return (None, error_msg)
            
            # 處理結果
            exit_code = process.exitValue()
            debug_exit = u"DEBUG: [gcloud] Process exit code: " + str(exit_code)
            print(debug_exit.encode('utf-8'))
            debug_output_count = u"DEBUG: [gcloud] stdout line count: " + str(len(output_lines))
            print(debug_output_count.encode('utf-8'))
            debug_error_count = u"DEBUG: [gcloud] stderr line count: " + str(len(error_lines))
            print(debug_error_count.encode('utf-8'))
            
            if exit_code == 0 and output_lines:
                token = output_lines[0].strip()
                if token:
                    debug_token_len = u"DEBUG: [gcloud] Successfully got token, length: " + str(len(token))
                    print(debug_token_len.encode('utf-8'))
                    debug_token_preview = u"DEBUG: [gcloud] Token preview: " + token[:20] + u"..."
                    print(debug_token_preview.encode('utf-8'))
                    
                    # 驗證 token 是否有效
                    debug_validate = u"DEBUG: [gcloud] Validating obtained token..."
                    print(debug_validate.encode('utf-8'))
                    if self._check_token_valid(token):
                        # 保存 token 到文件
                        self._save_token_to_file(token)
                        debug_success = u"DEBUG: [gcloud] Token validation successful, saved"
                        print(debug_success.encode('utf-8'))
                        return (token, None)
                    else:
                        error_msg = u"Obtained token failed validation"
                        debug_error = u"DEBUG: [gcloud] " + error_msg
                        print(debug_error.encode('utf-8'))
                        return (None, error_msg)
                else:
                    error_msg = u"gcloud command did not return token (output is empty)"
                    debug_error = u"DEBUG: [gcloud] " + error_msg
                    print(debug_error.encode('utf-8'))
                    return (None, error_msg)
            else:
                error_msg = u"gcloud command execution failed"
                if error_lines:
                    error_details = safe_unicode_convert("\n".join(error_lines))
                    error_msg += u"\nError message: " + error_details
                    debug_error_details = u"DEBUG: [gcloud] Error details: " + error_details
                    print(debug_error_details.encode('utf-8'))
                if exit_code != 0:
                    error_msg += u"\nExit code: " + str(exit_code)
                debug_error = u"DEBUG: [gcloud] " + error_msg
                print(debug_error.encode('utf-8'))
                return (None, error_msg)
                
        except Exception as e:
            error_msg = u"Execution error: " + safe_unicode_convert(str(e))
            print("DEBUG: Exception occurred: " + str(e))
            import traceback
            print("DEBUG: Detailed stack trace: " + traceback.format_exc())
            return (None, error_msg)
    
    def _query_sheets_by_email(self, email):
        """通過 email 查詢可用的 Spreadsheet 列表"""
        try:
            # 構建 API URL
            api_url = "https://script.google.com/macros/s/AKfycbzj-5-dbEE5em0BcALz1f5cmZzaMDM6nrPUs9MFFP-qS6CtxlDQdjUiRu7jaGq8y2OFVQ/exec"
            params = {
                "querytype": "burp",
                "email": email
            }
            url = api_url + "?" + urllib.urlencode(params)
            
            debug_msg = u"DEBUG: Querying Spreadsheet list, Email: " + safe_unicode_convert(email)
            print(debug_msg.encode('utf-8'))
            debug_url = u"DEBUG: API URL: " + safe_unicode_convert(url)
            print(debug_url.encode('utf-8'))
            
            # 發送請求
            req = urllib2.Request(url)
            response = urllib2.urlopen(req)
            response_body = response.read()
            response_body_str = safe_unicode_convert(response_body)
            
            debug_response = u"DEBUG: API response: " + response_body_str[:500]
            print(debug_response.encode('utf-8'))
            
            # 解析 JSON
            result = json.loads(response_body_str)
            
            if result.get("status") == "ok" and "items" in result:
                items = result["items"]
                sheets_list = []
                for item in items:
                    project = safe_unicode_convert(item.get("project", ""))
                    sheetid = safe_unicode_convert(item.get("sheetid", ""))
                    status = safe_unicode_convert(item.get("status", ""))
                    # 格式: "project_name|sheetid"
                    display_text = project + u" (" + status + u")"
                    sheets_list.append((display_text, sheetid, project))
                
                debug_count = u"DEBUG: Parsed " + str(len(sheets_list)) + u" Spreadsheets"
                print(debug_count.encode('utf-8'))
                return sheets_list
            else:
                error_msg = safe_unicode_convert(result.get("error", u"Unknown error"))
                debug_error = u"DEBUG: API returned error: " + error_msg
                print(debug_error.encode('utf-8'))
                return None
                
        except urllib2.HTTPError as e:
            error_code = safe_unicode_convert(str(e.code))
            error_msg = u"HTTP error " + error_code
            debug_http = u"DEBUG: " + error_msg
            print(debug_http.encode('utf-8'))
            return None
        except Exception as e:
            try:
                error_msg = safe_unicode_convert(str(e))
                debug_error = u"DEBUG: Query exception: " + error_msg
                print(debug_error.encode('utf-8'))
            except:
                print("DEBUG: Query exception (unable to display details)".encode('utf-8'))
            try:
                import traceback
                traceback_str = safe_unicode_convert(traceback.format_exc())
                debug_trace = u"DEBUG: Detailed stack trace: " + traceback_str
                print(debug_trace.encode('utf-8'))
            except:
                print("DEBUG: Unable to display detailed stack trace".encode('utf-8'))
            return None
    
    def _create_sheet_query_handler(self, txt_email, panel):
        """創建查詢 Spreadsheet 列表按鈕的事件處理器"""
        def query_sheets(event):
            email = txt_email.getText().strip()
            if not email:
                JOptionPane.showMessageDialog(None, u"請輸入 Email 地址", u"錯誤", JOptionPane.ERROR_MESSAGE)
                return
            
            debug_msg = u"DEBUG: Button click event triggered, starting to query Spreadsheet list..."
            print(debug_msg.encode('utf-8'))
            print("DEBUG: Starting background thread for query".encode('utf-8'))
            
            def query_in_thread():
                try:
                    sheets_list = self._query_sheets_by_email(email)
                    if sheets_list:
                        # 在 Swing 事件線程中更新 UI
                        from javax.swing import SwingUtilities
                        def update_ui():
                            # 從 panel 的 client property 中獲取組件引用
                            combo = panel.getClientProperty("combo_sheets")
                            txt_id = panel.getClientProperty("txt_id")
                            txt_sheet_name = panel.getClientProperty("txt_sheet_name")
                            
                            if combo is None:
                                return
                            
                            combo.removeAllItems()
                            for display_text, sheetid, project in sheets_list:
                                # 存儲格式: "display_text|sheetid|project"
                                combo.addItem(display_text + u"|" + sheetid + u"|" + project)
                            combo.setEnabled(True)
                            JOptionPane.showMessageDialog(None, u"查詢成功！找到 " + str(len(sheets_list)) + u" 個 Spreadsheet", u"成功", JOptionPane.INFORMATION_MESSAGE)
                        SwingUtilities.invokeLater(update_ui)
                    else:
                        from javax.swing import SwingUtilities
                        def show_error():
                            combo = panel.getClientProperty("combo_sheets")
                            if combo is not None:
                                combo.removeAllItems()
                                combo.addItem(u"查詢失敗，請重試")
                                combo.setEnabled(False)
                            JOptionPane.showMessageDialog(None, u"查詢失敗，請檢查 Email 或網路連接", u"錯誤", JOptionPane.ERROR_MESSAGE)
                        SwingUtilities.invokeLater(show_error)
                except Exception as e:
                    print(("DEBUG: query_sheets exception: " + safe_unicode_convert(str(e))).encode('utf-8'))
                    import traceback
                    print(("DEBUG: Detailed stack trace: " + safe_unicode_convert(traceback.format_exc())).encode('utf-8'))
            
            # 啟動背景線程
            thread = threading.Thread(target=query_in_thread)
            thread.daemon = True
            thread.start()
        
        return query_sheets
    
    def _create_token_fetcher(self, txt_token, txt_query_email):
        """創建 token 獲取按鈕的事件處理器"""
        def fetch_token(event):
            debug_msg1 = u"DEBUG: Button click event triggered, starting to get token..."
            print(debug_msg1.encode('utf-8'))
            debug_msg2 = u"DEBUG: Starting background thread to get token"
            print(debug_msg2.encode('utf-8'))
            
            def fetch_in_thread():
                try:
                    token, error = self._get_gcloud_token()
                    if token:
                        # 獲取 token 的 email 信息
                        token_info = self._get_token_info(token)
                        email_info = u""
                        email = None
                        if token_info and token_info.get("email"):
                            email = token_info["email"]
                            email_info = u"\n\nToken Email: " + email
                            # 保存 email 到配置
                            self.config["email"] = email
                            self._save_config_to_file()
                        
                        # 在 Swing 事件線程中更新 UI
                        from javax.swing import SwingUtilities
                        def update_ui():
                            txt_token.setText(token)
                            # 如果有 email，同時填入查詢 Email 欄位
                            if email:
                                txt_query_email.setText(email)
                                debug_email_filled = u"DEBUG: Filled email into query Email field: " + email
                                print(debug_email_filled.encode('utf-8'))
                            success_msg = u"Token 獲取成功！" + email_info
                            JOptionPane.showMessageDialog(None, success_msg, u"成功", JOptionPane.INFORMATION_MESSAGE)
                        SwingUtilities.invokeLater(update_ui)
                    else:
                        error_msg = error or u"未知錯誤"
                        from javax.swing import SwingUtilities
                        def show_error():
                            JOptionPane.showMessageDialog(None, u"Token 獲取失敗:\n" + safe_unicode_convert(error_msg), u"錯誤", JOptionPane.ERROR_MESSAGE)
                        SwingUtilities.invokeLater(show_error)
                except Exception as e:
                    print("DEBUG: fetch_token exception: " + str(e))
                    import traceback
                    print("DEBUG: Detailed stack trace: " + traceback.format_exc())
                    from javax.swing import SwingUtilities
                    def show_error():
                        JOptionPane.showMessageDialog(None, u"Token 獲取時發生異常:\n" + safe_unicode_convert(str(e)), u"錯誤", JOptionPane.ERROR_MESSAGE)
                    SwingUtilities.invokeLater(show_error)
            
            thread = threading.Thread(target=fetch_in_thread)
            thread.daemon = True
            thread.start()
        
        return fetch_token

    def _get_spreadsheet_info(self):
        """獲取 Google Spreadsheet 的資訊（名稱和工作表列表）"""
        try:
            api_url = "https://sheets.googleapis.com/v4/spreadsheets/{}".format(
                self.config["sheet_id"]
            )
            
            req = urllib2.Request(api_url)
            req.add_header("Authorization", "Bearer " + self.config["access_token"])
            if self.config.get("project_id"):
                req.add_header("x-goog-user-project", self.config["project_id"])
            
            response = urllib2.urlopen(req)
            response_body = response.read()
            response_body_str = safe_unicode_convert(response_body)
            result = json.loads(response_body_str)
            
            spreadsheet_name = u"未知文件"
            sheet_names = []
            
            if "properties" in result and "title" in result["properties"]:
                spreadsheet_name = safe_unicode_convert(result["properties"]["title"])
            
            if "sheets" in result:
                for sheet in result["sheets"]:
                    if "properties" in sheet and "title" in sheet["properties"]:
                        sheet_names.append(safe_unicode_convert(sheet["properties"]["title"]))
            
            return spreadsheet_name, sheet_names
        except Exception as e:
            error_msg = u"獲取 Spreadsheet 資訊失敗: " + safe_unicode_convert(str(e))
            print(("DEBUG: " + error_msg).encode('utf-8'))
            return u"未知文件", []
    
    def _get_spreadsheet_name(self):
        """獲取 Google Spreadsheet 的名稱"""
        spreadsheet_name, _ = self._get_spreadsheet_info()
        return spreadsheet_name
    
    def _read_sheet_data(self):
        """讀取表單數據，返回行數據列表"""
        try:
            # 檢查必要的配置
            if not self.config.get("sheet_id"):
                error_msg = u"Sheet ID 未設置"
                print(("DEBUG: " + error_msg).encode('utf-8'))
                JOptionPane.showMessageDialog(None, error_msg, u"錯誤", JOptionPane.ERROR_MESSAGE)
                return []
            
            if not self.config.get("access_token"):
                error_msg = u"Access Token 未設置"
                print(("DEBUG: " + error_msg).encode('utf-8'))
                JOptionPane.showMessageDialog(None, error_msg, u"錯誤", JOptionPane.ERROR_MESSAGE)
                return []
            
            target_sheet = self.config.get("sheet_name", u"弱點清單")
            sheet_id = self.config.get("sheet_id", "")
            debug_separator = u"DEBUG: ========== Starting to read sheet data =========="
            print(debug_separator.encode('utf-8'))
            debug_sheet_id = u"DEBUG: Spreadsheet ID: " + safe_unicode_convert(sheet_id)
            print(debug_sheet_id.encode('utf-8'))
            debug_sheet_name = u"DEBUG: Sheet name: " + safe_unicode_convert(target_sheet)
            print(debug_sheet_name.encode('utf-8'))
            debug_project = u"DEBUG: Project ID: " + safe_unicode_convert(self.config.get("project_id", ""))
            print(debug_project.encode('utf-8'))
            
            # 讀取 A1:I1000 範圍的數據
            # 工作表名稱需要正確進行 URL 編碼
            target_sheet_unicode = safe_unicode_convert(target_sheet)
            # 構建範圍字符串：工作表名稱!A1:I1000
            range_str = target_sheet_unicode + u"!A1:I1000"
            # 將 unicode 字符串編碼為 UTF-8 bytes，然後進行 URL 編碼
            encoded_range = urllib.quote(range_str.encode('utf-8'))
            
            api_url = "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}".format(
                self.config["sheet_id"],
                encoded_range
            )
            
            debug_url = u"DEBUG: API URL: " + safe_unicode_convert(api_url)
            print(debug_url.encode('utf-8'))
            
            # 確保 token 有效
            if not self._ensure_valid_token():
                error_msg = u"Token 無效且無法刷新，請手動獲取新 token"
                print(("DEBUG: " + error_msg).encode('utf-8'))
                JOptionPane.showMessageDialog(None, error_msg, u"錯誤", JOptionPane.ERROR_MESSAGE)
                return []
            
            req = urllib2.Request(api_url)
            req.add_header("Authorization", "Bearer " + self.config["access_token"])
            if self.config.get("project_id"):
                req.add_header("x-goog-user-project", self.config["project_id"])
            
            response = urllib2.urlopen(req)
            response_body = response.read()
            
            # 使用 safe_unicode_convert 安全地處理回應
            response_body_str = safe_unicode_convert(response_body)
            
            debug_len = u"DEBUG: API response length: " + safe_unicode_convert(str(len(response_body_str)))
            print(debug_len.encode('utf-8'))
            
            result = json.loads(response_body_str)
            
            rows_data = []
            if "values" in result:
                debug_rows = u"DEBUG: Found " + safe_unicode_convert(str(len(result["values"]))) + u" rows of data"
                print(debug_rows.encode('utf-8'))
                for idx, row in enumerate(result["values"], start=1):
                    row_dict = {
                        "row_num": idx,
                        "B": safe_unicode_convert(row[1] if len(row) > 1 else ""),
                        "D": safe_unicode_convert(row[3] if len(row) > 3 else ""),
                        "I": safe_unicode_convert(row[8] if len(row) > 8 else "")
                    }
                    rows_data.append(row_dict)
            else:
                print("DEBUG: API response does not contain 'values' field".encode('utf-8'))
                debug_content = u"DEBUG: API response content: " + safe_unicode_convert(response_body_str[:200])
                print(debug_content.encode('utf-8'))
            
            debug_success = u"DEBUG: Successfully read " + safe_unicode_convert(str(len(rows_data))) + u" rows of data"
            print(debug_success.encode('utf-8'))
            return rows_data
            
        except urllib2.HTTPError as e:
            error_body = e.read()
            error_code = e.code
            debug_http_error = u"DEBUG: HTTP error " + safe_unicode_convert(str(error_code))
            print(debug_http_error.encode('utf-8'))
            
            # 使用 safe_unicode_convert 安全地處理錯誤回應
            error_body_str = safe_unicode_convert(error_body)
            
            error_msg = "Unknown error"
            try:
                error_json = json.loads(error_body_str)
                error_detail = error_json.get("error", {})
                error_msg = error_detail.get("message", "Unknown error")
                error_status = error_detail.get("status", "")
                error_msg_unicode = safe_unicode_convert(error_msg)
                debug_error_detail = u"DEBUG: Error details: " + error_msg_unicode
                if error_status:
                    debug_error_detail += u" (status: " + safe_unicode_convert(error_status) + u")"
                print(debug_error_detail.encode('utf-8'))
                # 輸出完整的錯誤回應以便調試
                debug_full_error = u"DEBUG: Full error response: " + safe_unicode_convert(error_body_str[:500])
                print(debug_full_error.encode('utf-8'))
            except Exception as parse_error:
                error_msg = "Unknown error"
                try:
                    error_body_display = safe_unicode_convert(error_body)
                    print(("DEBUG: Unable to parse error response: " + error_body_display[:500]).encode('utf-8'))
                except:
                    print("DEBUG: Unable to parse error response (encoding error)".encode('utf-8'))
            
            if error_code == 400:
                # 嘗試獲取實際的工作表名稱列表
                try:
                    _, sheet_names = self._get_spreadsheet_info()
                    sheet_names_str = u", ".join(sheet_names) if sheet_names else u"無法獲取"
                except:
                    sheet_names_str = u"無法獲取"
                
                error_msg_display = u"請求格式錯誤 (400)\n\n"
                error_msg_display += u"錯誤訊息: " + safe_unicode_convert(error_msg) + u"\n\n"
                error_msg_display += u"配置的工作表名稱: " + safe_unicode_convert(self.config.get("sheet_name", "")) + u"\n"
                error_msg_display += u"實際的工作表名稱: " + sheet_names_str + u"\n\n"
                error_msg_display += u"可能的原因：\n"
                error_msg_display += u"1. 工作表名稱不正確（請檢查上方的工作表名稱列表）\n"
                error_msg_display += u"2. 範圍格式錯誤\n"
                error_msg_display += u"3. Spreadsheet ID 格式不正確\n\n"
                error_msg_display += u"請確認配置中的工作表名稱與實際名稱完全一致（區分大小寫）。"
                JOptionPane.showMessageDialog(None, error_msg_display, u"請求錯誤", JOptionPane.ERROR_MESSAGE)
            elif error_code == 403:
                detailed_msg = u"權限錯誤 (403): " + safe_unicode_convert(error_msg) + u"\n\n"
                detailed_msg += u"請確認：\n"
                detailed_msg += u"1. Google Cloud Project 已啟用 Google Sheets API\n"
                detailed_msg += u"2. Service Account 或 User Account 具有以下權限：\n"
                detailed_msg += u"   - roles/serviceusage.serviceUsageConsumer\n"
                detailed_msg += u"   - 或 serviceusage.services.use\n"
                detailed_msg += u"3. 在 Google Cloud Console 中授予權限：\n"
                if self.config.get("project_id"):
                    detailed_msg += u"   https://console.cloud.google.com/iam-admin/iam?project=" + self.config["project_id"]
                
                JOptionPane.showMessageDialog(None, detailed_msg, u"權限錯誤", JOptionPane.ERROR_MESSAGE)
            elif error_code == 404:
                error_msg_display = u"找不到 Spreadsheet (404)\n\n"
                error_msg_display += u"請確認：\n"
                error_msg_display += u"1. Spreadsheet ID 是否正確\n"
                error_msg_display += u"2. 工作表名稱是否正確: " + safe_unicode_convert(self.config.get("sheet_name", ""))
                JOptionPane.showMessageDialog(None, error_msg_display, u"錯誤", JOptionPane.ERROR_MESSAGE)
            elif error_code == 401:
                # Token 過期，嘗試自動刷新並重試一次
                debug_msg = u"DEBUG: Encountered 401 error, attempting to auto-refresh token and retry..."
                print(debug_msg.encode('utf-8'))
                
                if self._ensure_valid_token():
                    try:
                        # 重試請求
                        req_retry = urllib2.Request(api_url)
                        req_retry.add_header("Authorization", "Bearer " + self.config["access_token"])
                        if self.config.get("project_id"):
                            req_retry.add_header("x-goog-user-project", self.config["project_id"])
                        
                        response_retry = urllib2.urlopen(req_retry)
                        response_body_retry = response_retry.read()
                        response_body_str_retry = safe_unicode_convert(response_body_retry)
                        
                        result_retry = json.loads(response_body_str_retry)
                        rows_data = []
                        if "values" in result_retry:
                            for idx, row in enumerate(result_retry["values"], start=1):
                                row_dict = {
                                    "row_num": idx,
                                    "B": safe_unicode_convert(row[1] if len(row) > 1 else ""),
                                    "D": safe_unicode_convert(row[3] if len(row) > 3 else ""),
                                    "I": safe_unicode_convert(row[8] if len(row) > 8 else "")
                                }
                                rows_data.append(row_dict)
                        
                        debug_success = u"DEBUG: Token refresh retry successful, read " + safe_unicode_convert(str(len(rows_data))) + u" rows of data"
                        print(debug_success.encode('utf-8'))
                        return rows_data
                    except Exception as retry_error:
                        error_msg_retry = u"Token refresh retry failed: " + safe_unicode_convert(str(retry_error))
                        print(("DEBUG: " + error_msg_retry).encode('utf-8'))
                
                error_msg_display = u"認證失敗 (401)\n\n"
                error_msg_display += u"Token 已過期且自動刷新失敗，請手動重新獲取 Token"
                JOptionPane.showMessageDialog(None, error_msg_display, u"錯誤", JOptionPane.ERROR_MESSAGE)
            else:
                error_msg_display = u"讀取表單失敗: HTTP " + str(error_code) + u"\n"
                error_msg_display += u"錯誤訊息: " + safe_unicode_convert(error_msg)
                JOptionPane.showMessageDialog(None, error_msg_display, u"錯誤", JOptionPane.ERROR_MESSAGE)
            return []
        except Exception as e:
            # 安全地處理異常訊息
            try:
                # 先嘗試獲取異常類型
                error_type = type(e).__name__
                # 安全地獲取異常訊息
                try:
                    error_str = str(e)
                    error_msg_unicode = safe_unicode_convert(error_str)
                except:
                    error_msg_unicode = u"Unknown error"
                
                error_msg = u"Failed to read sheet: " + error_type + u" - " + error_msg_unicode
            except:
                error_msg = u"Failed to read sheet: Unable to parse error message"
            
            try:
                print(("DEBUG: " + error_msg).encode('utf-8'))
            except:
                print("DEBUG: Failed to read sheet (unable to output error message)".encode('utf-8'))
            
            # 嘗試輸出 traceback
            import traceback
            try:
                traceback_str = traceback.format_exc()
                # 安全地處理 traceback
                traceback_unicode = safe_unicode_convert(traceback_str)
                try:
                    print(("DEBUG: Detailed stack trace: " + traceback_unicode).encode('utf-8'))
                except:
                    # 如果還是無法輸出，至少輸出部分信息
                    print("DEBUG: Detailed stack trace: [Unable to output full stack]".encode('utf-8'))
            except:
                print("DEBUG: Unable to output detailed stack trace".encode('utf-8'))
            
            JOptionPane.showMessageDialog(None, error_msg, u"錯誤", JOptionPane.ERROR_MESSAGE)
            return []
    
    def _find_empty_row(self, rows_data):
        """找到第一個 B、D、I 都為空的行"""
        for row in rows_data:
            if not row["B"] and not row["D"] and not row["I"]:
                return row["row_num"]
        # 如果沒有空行，返回下一行
        if rows_data:
            return rows_data[-1]["row_num"] + 1
        return 1

    def send_to_sheet(self, event):
        if not self.config["sheet_id"] or not self.config["access_token"]:
            if not self.show_config_dialog(): return

        http_traffic = self.context.getSelectedMessages()
        if not http_traffic: return

        request_info = http_traffic[0]
        full_url = str(request_info.getUrl())
        
        # 獲取時間戳記並轉換為日期格式
        from java.util import Date, Calendar
        from java.text import SimpleDateFormat
        
        discovery_date = ""
        try:
            # 嘗試使用 getTime() 方法獲取時間戳記
            if hasattr(request_info, 'getTime'):
                timestamp_ms = request_info.getTime()
                if timestamp_ms:
                    date_obj = Date(timestamp_ms)
                    date_format = SimpleDateFormat("yyyy-MM-dd")
                    discovery_date = date_format.format(date_obj)
        except:
            pass
        
        # 如果無法獲取時間，使用當前日期
        if not discovery_date:
            try:
                cal = Calendar.getInstance()
                date_format = SimpleDateFormat("yyyy-MM-dd")
                discovery_date = date_format.format(cal.getTime())
            except Exception as e:
                # 最後備用：使用 Python 的日期格式
                import datetime
                discovery_date = datetime.datetime.now().strftime("%Y-%m-%d")
                print("DEBUG: Using Python datetime as date fallback: " + str(e))
        
        analyzed_req = self._helpers.analyzeRequest(request_info)
        parameters = analyzed_req.getParameters()
        param_list = []
        seen_params = set()
        target_types = [IParameter.PARAM_URL, IParameter.PARAM_BODY, IParameter.PARAM_MULTIPART_ATTR, IParameter.PARAM_JSON]
        for p in parameters:
            if p.getType() in target_types and p.getName() not in seen_params:
                param_list.append(p.getName())
                seen_params.add(p.getName())
        
        full_req = request_info.getRequest().tostring()

        # 讀取表單數據以找到空行
        rows_data = self._read_sheet_data()
        if not rows_data:
            JOptionPane.showMessageDialog(None, u"無法讀取表單數據", u"錯誤", JOptionPane.ERROR_MESSAGE)
            return
        
        empty_row = self._find_empty_row(rows_data)
        
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        txt_url = JTextField(full_url, 40)
        txt_param = JTextField(", ".join(param_list), 40)
        txt_syntax = JTextArea(full_req)
        txt_syntax.setLineWrap(True)
        scroll_syntax = JScrollPane(txt_syntax)
        scroll_syntax.setPreferredSize(Dimension(500, 200))
        
        # 添加項次（行號）輸入框
        txt_row = JTextField(str(empty_row), 10)
        panel.add(JLabel(u"項次（行號）:"))
        panel.add(txt_row)
        panel.add(Box.createVerticalStrut(5))
        panel.add(JLabel(u"URL (I):"))
        panel.add(txt_url)
        panel.add(JLabel(u"Param (J):"))
        panel.add(txt_param)
        panel.add(JLabel(u"Request (K):"))
        panel.add(scroll_syntax)
        panel.add(Box.createVerticalStrut(5))
        # 添加測試人員輸入框
        txt_tester = JTextField("", 40)
        panel.add(JLabel(u"測試人員 (O):"))
        panel.add(txt_tester)
        panel.add(Box.createVerticalStrut(5))
        # 添加發現日期顯示（只讀）
        txt_date = JTextField(discovery_date, 40)
        txt_date.setEditable(False)
        panel.add(JLabel(u"發現日期 (P):"))
        panel.add(txt_date)

        if JOptionPane.showConfirmDialog(None, panel, u"Send to " + safe_unicode_convert(self.config["sheet_name"]), JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION:
            target_row = txt_row.getText().strip()
            try:
                target_row = int(target_row)
            except:
                target_row = empty_row
            
            # 檢查是否為自訂行號，以及是否需要覆蓋確認
            is_custom_row = (target_row != empty_row)
            need_overwrite_confirm = False
            overwrite_data = None
            
            if is_custom_row and target_row <= len(rows_data):
                target_row_data = rows_data[target_row - 1]
                d_value = safe_unicode_convert(target_row_data.get("D", ""))
                i_value = safe_unicode_convert(target_row_data.get("I", ""))
                
                if d_value or i_value:
                    need_overwrite_confirm = True
                    overwrite_data = {
                        "row": target_row,
                        "D": d_value,
                        "I": i_value
                    }
            
            if need_overwrite_confirm:
                confirm_msg = u"行 " + str(target_row) + u" 已有資料：\n"
                confirm_msg += u"D 欄: " + overwrite_data["D"] + u"\n"
                confirm_msg += u"I 欄: " + overwrite_data["I"] + u"\n\n"
                confirm_msg += u"確定要覆蓋嗎？"
                
                if JOptionPane.showConfirmDialog(None, confirm_msg, u"確認覆蓋", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION:
                    return
            
            # 最終確認：顯示要寫入的 Google 文件名稱、工作表名稱和行號
            spreadsheet_name = self._get_spreadsheet_name()
            final_confirm_msg = u"確認上傳資料\n\n"
            final_confirm_msg += u"Google 文件名稱: " + spreadsheet_name + u"\n"
            final_confirm_msg += u"工作表名稱: " + safe_unicode_convert(self.config["sheet_name"]) + u"\n"
            final_confirm_msg += u"寫入行號: 第 " + str(target_row) + u" 列\n\n"
            final_confirm_msg += u"確定要上傳嗎？"
            
            if JOptionPane.showConfirmDialog(None, final_confirm_msg, u"確認上傳", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION:
                return
            
            data = {
                "url": txt_url.getText(),
                "param": txt_param.getText(),
                "syntax": txt_syntax.getText(),
                "tester": txt_tester.getText().strip(),
                "discovery_date": discovery_date,
                "target_row": target_row,
                "is_custom_row": is_custom_row
            }
            t = threading.Thread(target=self.post_to_api, args=(data,))
            t.start()

    def post_to_api(self, data):
        try:
            # 確保 token 有效
            if not self._ensure_valid_token():
                error_msg = u"Token 無效且無法刷新，請手動獲取新 token"
                print(("DEBUG: " + error_msg).encode('utf-8'))
                from javax.swing import SwingUtilities
                def show_error():
                    JOptionPane.showMessageDialog(None, error_msg, u"錯誤", JOptionPane.ERROR_MESSAGE)
                SwingUtilities.invokeLater(show_error)
                return
            
            target_sheet = self.config["sheet_name"]
            target_row = data["target_row"]
            is_custom_row = data.get("is_custom_row", False)
            
            # 如果不是自訂行號，重新讀取表單數據以確認空行
            if not is_custom_row:
                rows_data = self._read_sheet_data()
                if rows_data:
                    target_row = self._find_empty_row(rows_data)
            
            # 先寫入 I:K 欄位
            # 確保工作表名稱是 unicode，然後構建範圍字符串
            target_sheet_unicode = safe_unicode_convert(target_sheet)
            range_str_ijk = target_sheet_unicode + u"!I" + safe_unicode_convert(str(target_row)) + u":K" + safe_unicode_convert(str(target_row))
            # 將 unicode 字符串編碼為 UTF-8 bytes，然後進行 URL 編碼
            encoded_range_ijk = urllib.quote(range_str_ijk.encode('utf-8'))
            
            debug_ijk = u"DEBUG: Preparing to write to row " + safe_unicode_convert(str(target_row)) + u", range I:K: " + range_str_ijk
            print(debug_ijk.encode('utf-8'))
            
            api_url_ijk = "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}?valueInputOption=USER_ENTERED".format(
                self.config["sheet_id"],
                encoded_range_ijk
            )
            
            debug_url_ijk = u"DEBUG: API URL I:K: " + safe_unicode_convert(api_url_ijk)
            print(debug_url_ijk.encode('utf-8'))
            
            row_values_ijk = [data["url"], data["param"], data["syntax"]]
            json_data_ijk = json.dumps({"values": [row_values_ijk]})
            
            # 定義寫入 O:P 欄位的變量（用於重試）
            range_str_op = target_sheet_unicode + u"!O" + safe_unicode_convert(str(target_row)) + u":P" + safe_unicode_convert(str(target_row))
            encoded_range_op = urllib.quote(range_str_op.encode('utf-8'))
            api_url_op = "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}?valueInputOption=USER_ENTERED".format(
                self.config["sheet_id"],
                encoded_range_op
            )
            row_values_op = [data["tester"], data["discovery_date"]]
            json_data_op = json.dumps({"values": [row_values_op]})
            
            req_ijk = urllib2.Request(api_url_ijk, json_data_ijk)
            req_ijk.add_header("Content-Type", "application/json")
            req_ijk.add_header("Authorization", "Bearer " + self.config["access_token"])
            
            if self.config["project_id"]:
                req_ijk.add_header("x-goog-user-project", self.config["project_id"])
            
            req_ijk.get_method = lambda: 'PUT'
            
            response_ijk = urllib2.urlopen(req_ijk)
            response_body_ijk = response_ijk.read()
            result_ijk = json.loads(response_body_ijk)
            
            # 再寫入 O:P 欄位
            # 確保工作表名稱是 unicode，然後構建範圍字符串
            range_str_op = target_sheet_unicode + u"!O" + safe_unicode_convert(str(target_row)) + u":P" + safe_unicode_convert(str(target_row))
            # 將 unicode 字符串編碼為 UTF-8 bytes，然後進行 URL 編碼
            encoded_range_op = urllib.quote(range_str_op.encode('utf-8'))
            
            debug_op = u"DEBUG: Preparing to write to row " + safe_unicode_convert(str(target_row)) + u", range O:P: " + range_str_op
            print(debug_op.encode('utf-8'))
            
            api_url_op = "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}?valueInputOption=USER_ENTERED".format(
                self.config["sheet_id"],
                encoded_range_op
            )
            
            debug_url_op = u"DEBUG: API URL O:P: " + safe_unicode_convert(api_url_op)
            print(debug_url_op.encode('utf-8'))
            
            row_values_op = [data["tester"], data["discovery_date"]]
            json_data_op = json.dumps({"values": [row_values_op]})
            
            req_op = urllib2.Request(api_url_op, json_data_op)
            req_op.add_header("Content-Type", "application/json")
            req_op.add_header("Authorization", "Bearer " + self.config["access_token"])
            
            if self.config["project_id"]:
                req_op.add_header("x-goog-user-project", self.config["project_id"])
            
            req_op.get_method = lambda: 'PUT'
            
            response_op = urllib2.urlopen(req_op)
            response_body_op = response_op.read()
            result_op = json.loads(response_body_op)
            
            if "updatedCells" in result_ijk and "updatedCells" in result_op:
                success_msg = u"成功寫入到 " + safe_unicode_convert(target_sheet) + u" 行 " + str(target_row) + u" (欄位 I, J, K, O, P)!"
                print(safe_unicode_convert(success_msg).encode('utf-8'))
                self._callbacks.issueAlert(safe_unicode_convert(success_msg))
            else:
                print("DEBUG: API response I:K: " + response_body_ijk)
                print("DEBUG: API response O:P: " + response_body_op)
                
        except urllib2.HTTPError as e:
            error_body = e.read()
            error_code = e.code
            
            # 如果是 401 錯誤，嘗試自動刷新 token 並重試
            if error_code == 401:
                debug_msg = u"DEBUG: Encountered 401 error while writing, attempting to auto-refresh token and retry..."
                print(debug_msg.encode('utf-8'))
                
                if self._ensure_valid_token():
                    try:
                        # 重試寫入 I:K 欄位
                        req_ijk_retry = urllib2.Request(api_url_ijk, json_data_ijk)
                        req_ijk_retry.add_header("Content-Type", "application/json")
                        req_ijk_retry.add_header("Authorization", "Bearer " + self.config["access_token"])
                        if self.config.get("project_id"):
                            req_ijk_retry.add_header("x-goog-user-project", self.config["project_id"])
                        req_ijk_retry.get_method = lambda: 'PUT'
                        
                        response_ijk_retry = urllib2.urlopen(req_ijk_retry)
                        response_body_ijk_retry = response_ijk_retry.read()
                        result_ijk_retry = json.loads(response_body_ijk_retry)
                        
                        # 重試寫入 O:P 欄位
                        req_op_retry = urllib2.Request(api_url_op, json_data_op)
                        req_op_retry.add_header("Content-Type", "application/json")
                        req_op_retry.add_header("Authorization", "Bearer " + self.config["access_token"])
                        if self.config.get("project_id"):
                            req_op_retry.add_header("x-goog-user-project", self.config["project_id"])
                        req_op_retry.get_method = lambda: 'PUT'
                        
                        response_op_retry = urllib2.urlopen(req_op_retry)
                        response_body_op_retry = response_op_retry.read()
                        result_op_retry = json.loads(response_body_op_retry)
                        
                        if "updatedCells" in result_ijk_retry and "updatedCells" in result_op_retry:
                            success_msg = u"Token 刷新後重試成功！成功寫入到 " + safe_unicode_convert(target_sheet) + u" 行 " + str(target_row) + u" (欄位 I, J, K, O, P)!"
                            print(safe_unicode_convert(success_msg).encode('utf-8'))
                            self._callbacks.issueAlert(safe_unicode_convert(success_msg))
                            return
                    except Exception as retry_error:
                        error_msg_retry = u"Token 刷新後重試失敗: " + safe_unicode_convert(str(retry_error))
                        print(("DEBUG: " + error_msg_retry).encode('utf-8'))
            
            error_msg = u"HTTP 錯誤 " + str(error_code) + u": "
            
            try:
                error_json = json.loads(error_body)
                error_detail = error_json.get("error", {})
                error_msg += safe_unicode_convert(error_detail.get("message", "Unknown error"))
                
                if error_code == 401:
                    error_msg += u"\n\nToken 已過期且自動刷新失敗，請手動重新獲取 Token"
                elif error_code == 403:
                    error_msg += u"\n\n權限錯誤，請確認：\n"
                    error_msg += u"1. Google Cloud Project 已啟用 Google Sheets API\n"
                    error_msg += u"2. Service Account 或 User Account 具有以下權限：\n"
                    error_msg += u"   - roles/serviceusage.serviceUsageConsumer\n"
                    error_msg += u"   - 或 serviceusage.services.use\n"
                    error_msg += u"3. 在 Google Cloud Console 中授予權限：\n"
                    if self.config["project_id"]:
                        error_msg += u"   https://console.cloud.google.com/iam-admin/iam?project=" + self.config["project_id"]
            except:
                error_msg += safe_unicode_convert(error_body)
            
            print("Error: " + safe_unicode_convert(error_msg).encode('utf-8'))
            self._callbacks.issueAlert(safe_unicode_convert(error_msg))
            
        except Exception as e:
            error_msg = u"錯誤: " + safe_unicode_convert(str(e))
            print("Error: " + safe_unicode_convert(error_msg).encode('utf-8'))
            import traceback
            print("DEBUG: Detailed stack trace: " + traceback.format_exc())
            self._callbacks.issueAlert(safe_unicode_convert(error_msg))
