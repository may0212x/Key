import sys
import json
import os
import struct
from pathlib import Path
from steam.client import SteamClient
from steam.enums.common import EResult

# 引入最基礎的 AES-CBC 與 Padding 組件
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class DepotAppListBuilder:
    # ✨【全新獨立金鑰源】
    # 使用了全新生成的 256-bit 隨機十六進位字串，與你其他專案的 Salt 完全切離，專門給 applist 使用
    _APPLIST_KEY_SOURCE = b"8f3d2c1a9f5b4d7e0c6a8b2d1e4f3a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f"

    def __init__(self, depot_json="depotkeys.json", token_file="appaccesstokens.json", final_json="applist.json",
                 skipped_json="skipped_appids.json"):
        self.depot_json = Path(depot_json)
        self.final_json = Path(final_json)
        self.skipped_json = Path(skipped_json)
        self.access_tokens = self._load_access_tokens(token_file)
        self.client = SteamClient()
        self.applist_data = {}
        self.skipped_data = set()

        # ✨【初始化金鑰】透過 SHA256 永遠得到同一個固定的 32 位元組 AES-256 金鑰
        import hashlib
        self.aes_key = hashlib.sha256(self._APPLIST_KEY_SOURCE).digest()

        # 1. 讀取已有的成功進度（自動相容二進位密文與原始明文）
        if self.final_json.exists():
            try:
                with open(self.final_json, 'rb') as f:
                    file_data = f.read()

                # 結構檢查：AES-CBC 至少需要 16 位元組的 IV + 密文
                if len(file_data) >= 16:
                    iv = file_data[:16]
                    ciphertext = file_data[16:]

                    # 使用固定金鑰與檔案頭部的 IV 進行解密
                    cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
                    decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    self.applist_data = json.loads(decrypted_bytes.decode('utf-8'))
                    print(f"🔓 [二進位密文] 成功解密並載入現有進度，已存在 {len(self.applist_data)} 個記錄。")
                else:
                    raise ValueError("檔案長度不足")

            except Exception as e:
                # 如果解密失敗（例如檔案目前還是你上傳的那種純明文明細），自動退回明文讀取
                print(f"⚠️ 無法以加密格式讀取，正在嘗試以明文格式讀取... (原因: {e})")
                try:
                    with open(self.final_json, 'r', encoding='utf-8') as f:
                        self.applist_data = json.load(f)

                    if not isinstance(self.applist_data, dict) or len(self.applist_data) == 0:
                        raise ValueError("讀取到的 JSON 內容格式不正確")

                    print(f"📄 [純明文] 成功相容並載入明文，內含 {len(self.applist_data)} 個記錄！")
                    print("   💾 正在將此明文檔案安全轉換為 AES-CBC 加密二進位格式...")
                    self._save_json_directly()
                    print("   🔒 安全升級完成！")

                except Exception as json_err:
                    print(f"\n❌ 嚴重錯誤：檔案既無法解密，也無法當作明文讀取！原因: {json_err}")
                    sys.exit(1)

        # 2. 讀取已有的跳過進度
        if self.skipped_json.exists():
            try:
                with open(self.skipped_json, 'r', encoding='utf-8') as f:
                    raw_skipped = json.load(f)
                    if isinstance(raw_skipped, dict):
                        self.skipped_data = {int(k) for k in raw_skipped.keys() if str(k).isdigit()}
                    elif isinstance(raw_skipped, list):
                        self.skipped_data = {int(x) for x in raw_skipped}
                print(f"成功載入跳過進度，已存在 {len(self.skipped_data)} 個無效記錄。")
            except Exception:
                self.skipped_data = set()

    def _load_access_tokens(self, token_file: str) -> dict:
        file_path = Path(token_file)
        if not file_path.exists():
            return {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return {k: int(v) for k, v in json.load(f).items() if str(v).isdigit()}
        except Exception as e:
            print(f"載入 token 檔案錯誤: {e}")
            return {}

    def _login(self):
        print("正在連接 Steam (匿名登入)...")
        result = self.client.anonymous_login()
        if result != EResult.OK:
            raise ConnectionError(f"Steam 連接失敗: {result}")
        print("Steam 連接成功")

    def _clean_hash(self, raw_path: str) -> str:
        if not raw_path:
            return ""
        clean_str = raw_path.split('/')[0] if '/' in raw_path else raw_path
        clean_str = clean_str.strip()
        if len(clean_str) == 40 and all(c in '0123456789abcdefABCDEF' for c in clean_str):
            return clean_str
        return ""

    def load_appids_from_depots(self) -> list:
        if not self.depot_json.exists():
            print(f"錯誤：找不到 {self.depot_json}")
            return []
        try:
            with open(self.depot_json, 'r', encoding='utf-8') as f:
                data = json.load(f)

            appids = set()
            for key in data.keys():
                if key.isdigit():
                    depot_id = int(key)
                    appid = (depot_id // 10) * 10
                    appids.add(appid)

            result_list = sorted(list(appids))
            print(f"從 Depot 檔案中提取並去重後，共計 {len(result_list)} 個基礎 AppID。")
            return result_list
        except Exception as e:
            print(f"解析 depotkeys.json 失敗: {e}")
            return []

    def _get_app_info_block(self, appid: int, raw_data: dict) -> dict:
        if not raw_data:
            return {}
        app_str = str(appid)
        if 'apps' in raw_data:
            return raw_data['apps'].get(app_str, raw_data['apps'].get(appid, {}))
        if 'data' in raw_data:
            return raw_data['data'].get(app_str, raw_data['data'].get(appid, {}))
        return {}

    def _extract_and_compress_with_type(self, appid: int, raw_data: dict) -> list:
        try:
            app_info = self._get_app_info_block(appid, raw_data)
            common = app_info.get('common', {})
            if not common:
                return None

            raw_type = common.get('type', '').lower().strip()
            type_code_map = {
                'game': 1,
                'music': 2,
                'application': 3
            }

            if raw_type not in type_code_map:
                return None

            type_code = type_code_map[raw_type]
            english_name = common.get('name', '').strip()
            localized_name = common.get('name_localized', {})
            schinese_name = localized_name.get('schinese', '').strip()
            tchinese_name = localized_name.get('tchinese', '').strip()

            has_name_sc = bool(schinese_name and schinese_name != english_name)
            has_name_tc = bool(tchinese_name and tchinese_name != english_name)

            name_code = 0
            names_to_add = [english_name]

            if has_name_sc and has_name_tc:
                if schinese_name == tchinese_name:
                    name_code = 1
                    names_to_add = [schinese_name]
                else:
                    name_code = 3
                    names_to_add = [schinese_name, tchinese_name]
            elif has_name_sc:
                name_code = 1
                names_to_add = [schinese_name]
            elif has_name_tc:
                name_code = 2
                names_to_add = [tchinese_name]

            header_img_data = common.get('header_image', "")
            has_image = False
            img_code = 0
            images_to_add = []

            if header_img_data:
                if isinstance(header_img_data, dict):
                    english_img = self._clean_hash(header_img_data.get('english', ''))
                    schinese_img = self._clean_hash(header_img_data.get('schinese', ''))
                    tchinese_img = self._clean_hash(header_img_data.get('tchinese', ''))

                    if english_img or schinese_img or tchinese_img:
                        has_image = True
                        if not english_img:
                            english_img = schinese_img or tchinese_img

                        has_img_sc = bool(schinese_img and schinese_img != english_img)
                        has_img_tc = bool(tchinese_img and tchinese_img != english_img)

                        if has_img_sc and has_img_tc:
                            if schinese_img == tchinese_img:
                                img_code = 1
                                images_to_add = [schinese_img]
                            else:
                                img_code = 3
                                images_to_add = [schinese_img, tchinese_img]
                        elif has_img_sc:
                            img_code = 1
                            images_to_add = [schinese_img]
                        elif has_img_tc:
                            img_code = 2
                            images_to_add = [tchinese_img]
                        else:
                            img_code = 0
                            images_to_add = [english_img]
                else:
                    single_img = self._clean_hash(str(header_img_data))
                    if single_img:
                        has_image = True
                        img_code = 0
                        images_to_add = [single_img]

            if has_image:
                return [name_code, img_code] + names_to_add + images_to_add + [type_code]
            else:
                return [name_code] + names_to_add + [type_code]

        except Exception as e:
            print(f"解析 AppID {appid} 數據時出錯: {e}")
            return None

    def _save_json_directly(self):
        """ 將當前進度以最純粹的固定 Key + AES-CBC 模式加密儲存 """
        try:
            # 1. 轉為緊湊的明文 JSON 位元組 (就是你原本上傳的那個數據結構)
            json_str = json.dumps(self.applist_data, ensure_ascii=False, separators=(',', ':'))
            json_bytes = json_str.encode('utf-8')

            # 2. 每次隨機生成 16 位元組 IV (符合 CBC 標準，防止產出固定檔案，但不影響金鑰)
            iv = os.urandom(16)

            # 3. 進行固定金鑰的 AES-CBC 加密
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(json_bytes, AES.block_size))

            # 4. 寫入檔案：[16位元組隨機IV] + [密文]
            with open(self.final_json, 'wb') as f:
                f.write(iv + ciphertext)

            # 5. 儲存跳過名單 (維持原本明文設計)
            with open(self.skipped_json, 'w', encoding='utf-8') as f:
                json.dump(sorted(list(self.skipped_data)), f, ensure_ascii=False, separators=(',', ':'))
        except Exception as e:
            print(f"儲存或加密檔案失敗: {e}")

    def _fetch_product_info(self, appid: int):
        access_token = self.access_tokens.get(str(appid), 0)
        params = [{'appid': appid, 'access_token': access_token}] if access_token else [appid]
        try:
            return self.client.get_product_info(apps=params, auto_access_tokens=False, timeout=15)
        except Exception as e:
            print(f"網路超時或錯誤，跳過 AppID {appid}: {e}")
            return None

    def process(self):
        base_appids = self.load_appids_from_depots()
        if not base_appids:
            print("沒有需要處理的 AppID，程式結束。")
            return

        todo_appids = []
        for aid in base_appids:
            aid_str = str(aid)
            in_success = (aid_str in self.applist_data or str(aid + 1) in self.applist_data)
            in_skipped = (aid in self.skipped_data or (aid + 1) in self.skipped_data)

            if not in_success and not in_skipped:
                todo_appids.append(aid)

        if not todo_appids:
            print("所有 AppID 都已處理完成！")
            return

        print(f"待處理總數: {len(base_appids)}，剩餘需全新掃描: {len(todo_appids)}")
        self._login()

        try:
            for idx, base_appid in enumerate(todo_appids, 1):
                target_appid = base_appid
                print(f"[{idx}/{len(todo_appids)}] 正在嘗試獲取 AppID {target_appid} (尾數0)...")

                raw = self._fetch_product_info(target_appid)
                has_type = False
                if raw:
                    app_info = self._get_app_info_block(target_appid, raw)
                    if 'common' in app_info and 'type' in app_info['common']:
                        has_type = True

                if not has_type:
                    retry_appid = base_appid + 1
                    print(f"   ⚠️ AppID {target_appid} 無類型。改為搜尋 AppID {retry_appid} (尾數1)...")
                    raw = self._fetch_product_info(retry_appid)
                    if raw:
                        target_appid = retry_appid

                if not raw:
                    print(f"   └ ❌ 兩次重試均無法獲取有效資料。將基礎 AppID {base_appid} 記入跳過名單。")
                    self.skipped_data.add(base_appid)
                    self._save_json_directly()
                    continue

                compressed = self._extract_and_compress_with_type(target_appid, raw)
                if compressed:
                    self.applist_data[str(target_appid)] = compressed
                    print(f"   └ ✅ 成功壓縮並記錄 AppID {target_appid} (Type代碼:{compressed[-1]}): {compressed}")
                else:
                    print(f"   └ ⚠️ 類型不符（非Game/Music/App）或無效。將 AppID {target_appid} 記入跳過名單。")
                    self.skipped_data.add(target_appid)

                self._save_json_directly()

        except KeyboardInterrupt:
            print("\n[偵測到 Ctrl+C 中斷] 已安全保存目前進度...")
        finally:
            self.client.disconnect()
            self._save_json_directly()
            print("Steam 連接已關閉，進度儲存完畢。")


if __name__ == "__main__":
    builder = DepotAppListBuilder()
    builder.process()