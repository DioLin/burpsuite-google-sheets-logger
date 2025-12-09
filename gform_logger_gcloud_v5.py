# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IParameter
from javax.swing import JMenuItem, JOptionPane, JPanel, JLabel, JTextField, Box, BoxLayout, JTextArea, JScrollPane, JButton
from java.util import ArrayList
from java.awt import Dimension
from java.lang import ProcessBuilder, Runtime
import urllib
import urllib2
import threading
import json
import os
import time
from java.io import BufferedReader, InputStreamReader, File

def safe_unicode_convert(val):
    """安全地將各種類型的值轉換為 Unicode"""
    if val is None:
        return u""
    if isinstance(val, unicode):
        return val
    if isinstance(val, str):
        try:
            return unicode(val, 'utf-8', errors='ignore')
        except:
            try:
                return unicode(val, 'latin-1', errors='ignore')
            except:
                return unicode(str(val), errors='ignore')
    try:
        str_val = str(val)
        try:
            return unicode(str_val, 'utf-8', errors='ignore')
        except:
            return unicode(str_val, errors='ignore')
    except:
        return unicode(repr(val), errors='ignore')

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
            "sheet_name": u"弱點清單"
        }
        
        # 載入已保存的 token
        self._load_token_from_file()
        
    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_send = JMenuItem(u"[G-Sheet] Send to I/J/K (Skip Protected)", actionPerformed=self.send_to_sheet)
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
        
        btn_get_token = JButton(u"從 gcloud 獲取 Token", actionPerformed=self._create_token_fetcher(txt_token))
        
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
        panel.add(btn_get_token)

        result = JOptionPane.showConfirmDialog(None, panel, u"API Settings", JOptionPane.OK_CANCEL_OPTION)

        if result == JOptionPane.OK_OPTION:
            self.config["sheet_id"] = txt_id.getText().strip()
            self.config["sheet_name"] = txt_sheet_name.getText().strip()
            self.config["project_id"] = txt_project.getText().strip()
            self.config["access_token"] = txt_token.getText().strip()
            return True
        return False

    def _get_token_file_path(self):
        """獲取 token 文件路徑"""
        home = os.path.expanduser("~")
        return os.path.join(home, ".burp_google_token.json")
    
    def _save_token_to_file(self, token):
        """保存 token 到本地文件"""
        try:
            token_file = self._get_token_file_path()
            token_data = {
                "access_token": token,
                "saved_at": time.time()
            }
            with open(token_file, 'w') as f:
                json.dump(token_data, f)
            print("DEBUG: Token 已保存到: " + token_file)
        except Exception as e:
            print("DEBUG: 保存 token 失敗: " + str(e))
    
    def _load_token_from_file(self):
        """從本地文件載入 token"""
        try:
            token_file = self._get_token_file_path()
            if os.path.exists(token_file):
                with open(token_file, 'r') as f:
                    token_data = json.load(f)
                    token = token_data.get("access_token", "")
                    if token:
                        # 檢查 token 是否有效
                        if self._check_token_valid(token):
                            self.config["access_token"] = token
                            print("DEBUG: 已從文件載入有效的 token")
                        else:
                            print("DEBUG: 文件中的 token 已過期，需要重新獲取")
        except Exception as e:
            print("DEBUG: 載入 token 失敗: " + str(e))
    
    def _check_token_valid(self, token):
        """檢查 token 是否有效"""
        try:
            url = "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + urllib.quote(token)
            req = urllib2.Request(url)
            response = urllib2.urlopen(req)
            result = json.loads(response.read())
            if "error" in result:
                return False
            return True
        except urllib2.HTTPError as e:
            if e.code == 400:
                return False
            # 其他錯誤可能是網路問題，暫時認為有效
            return True
        except Exception as e:
            print("DEBUG: 檢查 token 時發生錯誤: " + str(e))
            return True  # 網路錯誤時假設有效
    
    def _get_gcloud_token(self):
        """從 gcloud CLI 獲取 access token"""
        print("DEBUG: ========== 開始獲取 gcloud token ==========")
        
        # 先檢查本地是否有有效的 token
        try:
            token_file = self._get_token_file_path()
            if os.path.exists(token_file):
                with open(token_file, 'r') as f:
                    token_data = json.load(f)
                    token = token_data.get("access_token", "")
                    if token and self._check_token_valid(token):
                        print("DEBUG: 使用本地緩存的 token")
                        return (token, None)
        except Exception as e:
            print("DEBUG: 檢查本地 token 時發生錯誤: " + str(e))
        
        print("DEBUG: 需要從 gcloud 獲取新的 token...")
        
        # 檢測作業系統
        is_windows = False
        if os.name == 'nt' or os.path.sep == '\\' or os.environ.get('WINDIR'):
            is_windows = True
        
        print("DEBUG: sys.platform: " + str(os.name))
        print("DEBUG: os.name: " + str(os.name))
        if is_windows:
            print("DEBUG: 通過路徑分隔符檢測到 Windows 系統")
        
        # 構建命令
        cmd_base = ["gcloud", "auth", "application-default", "print-access-token"]
        if is_windows:
            cmd = ["cmd", "/c"] + cmd_base
            print("DEBUG: Windows 系統，使用完整命令: " + " ".join(cmd))
        else:
            cmd = cmd_base
            print("DEBUG: Unix/Linux/Mac 系統，使用原始命令")
        
        print("DEBUG: 準備執行命令: " + " ".join(cmd))
        
        try:
            # 設置工作目錄
            home_dir = os.path.expanduser("~")
            print("DEBUG: 工作目錄: " + home_dir)
            
            # 創建 ProcessBuilder
            pb = ProcessBuilder(cmd)
            pb.directory(File(home_dir))
            
            # 設置環境變數（Windows 需要添加 gcloud 到 PATH）
            env = pb.environment()
            if is_windows:
                path_val = env.get("PATH")
                if path_val is None:
                    path_val = ""
                # 添加常見的 gcloud 安裝路徑
                common_paths = [
                    os.path.join(os.path.expanduser("~"), "AppData", "Local", "Google", "Cloud SDK", "google-cloud-sdk", "bin"),
                    "C:\\Program Files (x86)\\Google\\Cloud SDK\\google-cloud-sdk\\bin",
                    "C:\\Program Files\\Google\\Cloud SDK\\google-cloud-sdk\\bin"
                ]
                for p in common_paths:
                    if os.path.exists(p) and p not in path_val:
                        path_val = path_val + os.pathsep + p
                env.put("PATH", path_val)
                print("DEBUG: 已更新 PATH 環境變數")
            
            # 啟動進程
            process = pb.start()
            
            # 獲取 PID（用於調試）
            try:
                pid_val = process.pid
                if callable(pid_val):
                    pid_info = str(pid_val())
                else:
                    pid_info = str(pid_val)
                print("DEBUG: 進程 PID: " + pid_info)
            except:
                print("DEBUG: 無法獲取進程 PID")
            
            # 使用單一線程：先等待進程完成，再讀取輸出
            output_lines = []
            error_lines = []
            
            def wait_and_read():
                try:
                    # 等待進程完成（最多 30 秒）
                    finished = process.waitFor()
                    print("DEBUG: 進程完成，退出碼: " + str(finished))
                    
                    # 讀取標準輸出
                    stdout_reader = BufferedReader(InputStreamReader(process.getInputStream(), "UTF-8"))
                    line = stdout_reader.readLine()
                    while line is not None:
                        output_lines.append(line)
                        print("DEBUG: 標準輸出: " + safe_unicode_convert(line))
                        line = stdout_reader.readLine()
                    stdout_reader.close()
                    
                    # 讀取標準錯誤
                    stderr_reader = BufferedReader(InputStreamReader(process.getErrorStream(), "UTF-8"))
                    line = stderr_reader.readLine()
                    while line is not None:
                        error_lines.append(line)
                        print("DEBUG: 標準錯誤: " + safe_unicode_convert(line))
                        line = stderr_reader.readLine()
                    stderr_reader.close()
                    
                except Exception as e:
                    print("DEBUG: 讀取輸出時發生錯誤: " + str(e))
            
            # 啟動讀取線程
            read_thread = threading.Thread(target=wait_and_read)
            read_thread.daemon = True
            read_thread.start()
            
            # 等待讀取線程完成（最多 35 秒）
            read_thread.join(35)
            
            if read_thread.isAlive():
                print("DEBUG: 進程執行超時，嘗試終止...")
                process.destroy()
                error_msg = u"執行超時（超過 30 秒）"
                if error_lines:
                    error_msg += u"\n錯誤訊息: " + safe_unicode_convert("\n".join(error_lines))
                return (None, error_msg)
            
            # 處理結果
            if process.exitValue() == 0 and output_lines:
                token = output_lines[0].strip()
                if token:
                    # 保存 token 到文件
                    self._save_token_to_file(token)
                    print("DEBUG: 成功獲取 token，長度: " + str(len(token)))
                    return (token, None)
                else:
                    return (None, u"gcloud 命令未返回 token")
            else:
                error_msg = u"gcloud 命令執行失敗"
                if error_lines:
                    error_msg += u"\n錯誤訊息: " + safe_unicode_convert("\n".join(error_lines))
                if process.exitValue() != 0:
                    error_msg += u"\n退出碼: " + str(process.exitValue())
                return (None, error_msg)
                
        except Exception as e:
            error_msg = u"執行錯誤: " + safe_unicode_convert(str(e))
            print("DEBUG: 異常發生: " + str(e))
            import traceback
            print("DEBUG: 詳細堆疊: " + traceback.format_exc())
            return (None, error_msg)
    
    def _create_token_fetcher(self, txt_token):
        """創建 token 獲取按鈕的事件處理器"""
        def fetch_token(event):
            print("DEBUG: 按鈕點擊事件觸發，開始獲取 token...")
            print("DEBUG: 啟動背景執行緒獲取 token")
            
            def fetch_in_thread():
                try:
                    token, error = self._get_gcloud_token()
                    if token:
                        # 在 Swing 事件線程中更新 UI
                        from javax.swing import SwingUtilities
                        def update_ui():
                            txt_token.setText(token)
                            JOptionPane.showMessageDialog(None, u"Token 獲取成功！", u"成功", JOptionPane.INFORMATION_MESSAGE)
                        SwingUtilities.invokeLater(update_ui)
                    else:
                        error_msg = error or u"未知錯誤"
                        from javax.swing import SwingUtilities
                        def show_error():
                            JOptionPane.showMessageDialog(None, u"Token 獲取失敗:\n" + safe_unicode_convert(error_msg), u"錯誤", JOptionPane.ERROR_MESSAGE)
                        SwingUtilities.invokeLater(show_error)
                except Exception as e:
                    print("DEBUG: fetch_token 異常: " + str(e))
                    import traceback
                    print("DEBUG: 詳細堆疊: " + traceback.format_exc())
                    from javax.swing import SwingUtilities
                    def show_error():
                        JOptionPane.showMessageDialog(None, u"Token 獲取時發生異常:\n" + safe_unicode_convert(str(e)), u"錯誤", JOptionPane.ERROR_MESSAGE)
                    SwingUtilities.invokeLater(show_error)
            
            thread = threading.Thread(target=fetch_in_thread)
            thread.daemon = True
            thread.start()
        
        return fetch_token

    def _read_sheet_data(self):
        """讀取表單數據，返回行數據列表"""
        try:
            target_sheet = self.config["sheet_name"]
            # 讀取 A1:I1000 範圍的數據
            range_str = target_sheet.encode('utf-8') + "!A1:I1000"
            encoded_range = urllib.quote(range_str)
            
            api_url = "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}".format(
                self.config["sheet_id"],
                encoded_range
            )
            
            req = urllib2.Request(api_url)
            req.add_header("Authorization", "Bearer " + self.config["access_token"])
            if self.config["project_id"]:
                req.add_header("x-goog-user-project", self.config["project_id"])
            
            response = urllib2.urlopen(req)
            result = json.loads(response.read())
            
            rows_data = []
            if "values" in result:
                for idx, row in enumerate(result["values"], start=1):
                    row_dict = {
                        "row_num": idx,
                        "B": row[1] if len(row) > 1 else "",
                        "D": row[3] if len(row) > 3 else "",
                        "I": row[8] if len(row) > 8 else ""
                    }
                    rows_data.append(row_dict)
            
            return rows_data
            
        except urllib2.HTTPError as e:
            if e.code == 403:
                error_body = e.read()
                try:
                    error_json = json.loads(error_body)
                    error_msg = error_json.get("error", {}).get("message", "Permission denied")
                except:
                    error_msg = "Permission denied"
                
                detailed_msg = u"權限錯誤 (403): " + safe_unicode_convert(error_msg) + u"\n\n"
                detailed_msg += u"請確認：\n"
                detailed_msg += u"1. Google Cloud Project 已啟用 Google Sheets API\n"
                detailed_msg += u"2. Service Account 或 User Account 具有以下權限：\n"
                detailed_msg += u"   - roles/serviceusage.serviceUsageConsumer\n"
                detailed_msg += u"   - 或 serviceusage.services.use\n"
                detailed_msg += u"3. 在 Google Cloud Console 中授予權限：\n"
                detailed_msg += u"   https://console.cloud.google.com/iam-admin/iam?project=" + self.config["project_id"]
                
                JOptionPane.showMessageDialog(None, detailed_msg, u"權限錯誤", JOptionPane.ERROR_MESSAGE)
            else:
                JOptionPane.showMessageDialog(None, u"讀取表單失敗: HTTP " + str(e.code), u"錯誤", JOptionPane.ERROR_MESSAGE)
            return []
        except Exception as e:
            JOptionPane.showMessageDialog(None, u"讀取表單失敗: " + safe_unicode_convert(str(e)), u"錯誤", JOptionPane.ERROR_MESSAGE)
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
                print("DEBUG: 使用 Python datetime 作為日期備用方案: " + str(e))
        
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
            target_sheet = self.config["sheet_name"]
            target_row = data["target_row"]
            is_custom_row = data.get("is_custom_row", False)
            
            # 如果不是自訂行號，重新讀取表單數據以確認空行
            if not is_custom_row:
                rows_data = self._read_sheet_data()
                if rows_data:
                    target_row = self._find_empty_row(rows_data)
            
            # 先寫入 I:K 欄位
            range_str_ijk = target_sheet.encode('utf-8') + "!I" + str(target_row) + ":K" + str(target_row)
            encoded_range_ijk = urllib.quote(range_str_ijk)
            
            print("DEBUG: 準備寫入到行 " + str(target_row) + ", 範圍 I:K: " + range_str_ijk)
            
            api_url_ijk = "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}?valueInputOption=USER_ENTERED".format(
                self.config["sheet_id"],
                encoded_range_ijk
            )
            
            print("DEBUG: API URL I:K: " + api_url_ijk)
            
            row_values_ijk = [data["url"], data["param"], data["syntax"]]
            json_data_ijk = json.dumps({"values": [row_values_ijk]})
            
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
            range_str_op = target_sheet.encode('utf-8') + "!O" + str(target_row) + ":P" + str(target_row)
            encoded_range_op = urllib.quote(range_str_op)
            
            print("DEBUG: 準備寫入到行 " + str(target_row) + ", 範圍 O:P: " + range_str_op)
            
            api_url_op = "https://sheets.googleapis.com/v4/spreadsheets/{}/values/{}?valueInputOption=USER_ENTERED".format(
                self.config["sheet_id"],
                encoded_range_op
            )
            
            print("DEBUG: API URL O:P: " + api_url_op)
            
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
                print("DEBUG: API 回應 I:K: " + response_body_ijk)
                print("DEBUG: API 回應 O:P: " + response_body_op)
                
        except urllib2.HTTPError as e:
            error_body = e.read()
            error_msg = u"HTTP 錯誤 " + str(e.code) + u": "
            
            try:
                error_json = json.loads(error_body)
                error_detail = error_json.get("error", {})
                error_msg += safe_unicode_convert(error_detail.get("message", "Unknown error"))
                
                if e.code == 403:
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
            print("DEBUG: 詳細堆疊: " + traceback.format_exc())
            self._callbacks.issueAlert(safe_unicode_convert(error_msg))
