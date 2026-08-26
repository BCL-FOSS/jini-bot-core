import uuid
import re
import string
import random
import logging
import os
import logging
import os
import jwt
from datetime import datetime, timedelta, timezone
from tzlocal import get_localzone
import jwt
import re
from typing import Tuple
import os
import jwt
from datetime import datetime, timedelta, timezone
import httpx
from init_app import cl_data_db
import asyncio

class Util:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.company_global_namespace = 'cmp:'
        self.company_data_global_namespace = 'dta:'
        self.user_global_namespace = 'usr:'
        self.user_id_global_namespace = 'uid:'

    def gen_id(self) -> str:
        return str(uuid.uuid4())
    
    def gen_user(self, username=""):
        user_namespace = f'{self.user_global_namespace}{self.gen_id()}'
        user_id = f'{self.user_id_global_namespace}{username}{self.gen_id()}'
    
        return user_namespace, user_id

    def generate_ephemeral_token(self, id: str, rand: str,  secret_key: str, expire: int = 3, type: str = None) -> str:

        local_tz = get_localzone()  
        now = datetime.now(tz=timezone.utc)

        if type == 'prb':
            expire_value = timedelta(minutes=30)
        else:
            expire_value = timedelta(hours=expire)
        
        payload = {
            'iss': f"https://{os.environ.get('SERVER_NAME')}",
            'id': id,
            'rand': rand,
            'exp': now + expire_value,
        }

        encoded_jwt = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")

        return encoded_jwt
    
    def generate_api_key(self) -> str:
        return str(uuid.uuid4())
    
    def key_gen(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.SystemRandom().choice(chars) for _ in range(size))
    
    def extract_after_analysis(self, text: str) -> str:
        marker = "Analysis:"
        index = text.find(marker)

        if index == -1:
            return ""

        return text[index + len(marker):]

    def split_analysis(self, text: str) -> Tuple[str, str]:
        pattern = re.compile(r'analysis\s*:\s*', re.IGNORECASE)

        match = pattern.search(text)
        if not match:
            return text, ""

        cleaned_text = text[:match.start()].rstrip()
        analysis_text = text[match.end():].lstrip()

        return cleaned_text, analysis_text
    
    def split_text_by_keyword(self, text: str, keyword: str, cnfrm: bool = False) -> Tuple[str, str]:
        pattern = re.compile(rf'{re.escape(keyword)}\s*:\s*', re.IGNORECASE)
        
        match = pattern.search(text)

        if not match and cnfrm is True:
            return None

        if not match:
            return text, "".strip()
        
        text_before = text[:match.start()].rstrip()
        text_after = text[match.end():].lstrip()
        
        return text_before, text_after
    
    def round_down_to_5min(self, dt: datetime) -> datetime:
        """Round dt down (floor) to the nearest 5-minute boundary."""
        if dt is None:
            return dt
        minute = (dt.minute // 5) * 5
        return dt.replace(minute=minute, second=0, microsecond=0)

    def round_up_to_5min(self, dt: datetime) -> datetime:
        """Round dt up (ceiling) to the next 5-minute boundary (if already on boundary, keep)."""
        if dt is None:
            return dt
        # If already exact boundary, return as-is (but zero seconds/microseconds)
        if dt.second == 0 and dt.microsecond == 0 and (dt.minute % 5) == 0:
            return dt.replace(second=0, microsecond=0)
        # Compute minutes to add to reach next multiple of 5
        remainder = dt.minute % 5
        add_minutes = 5 - remainder
        # Normalize to next boundary with seconds/microseconds cleared
        # Use a base truncated to the minute first
        base = dt.replace(second=0, microsecond=0)
        res = base + timedelta(minutes=add_minutes)
        return res.replace(second=0, microsecond=0)
    
    def round_down_to_30sec(self, dt: datetime) -> datetime:
        """Round dt down (floor) to the nearest 30-second boundary."""
        if dt is None:
            return dt
        # Determine the 30-second bucket: 0-29 => 0, 30-59 => 30
        sec = (dt.second // 30) * 30
        return dt.replace(second=sec, microsecond=0)

    def round_up_to_30sec(self, dt: datetime) -> datetime:
        """Round dt up (ceiling) to the next 30-second boundary (if already on boundary, keep)."""
        if dt is None:
            return dt
        # If already exact boundary, return as-is (but zero microseconds)
        if (dt.second % 30) == 0 and dt.microsecond == 0:
            return dt.replace(microsecond=0)
        remainder = dt.second % 30
        add_seconds = 30 - remainder
        base = dt.replace(microsecond=0)
        res = base + timedelta(seconds=add_seconds)
        return res.replace(microsecond=0)

    async def make_http_request(self, conn_obj: httpx.AsyncClient, headers: dict, url: str, data: dict, timeout: int = 10):
        async with conn_obj as client:                  
            exec_resp = await client.post(url, json=data, headers=headers, timeout=timeout)
            if exec_resp.status_code != 200:
                self.logger.error(f"HTTP request failed with status code {exec_resp.status_code}: {exec_resp.text}")
                return exec_resp.status_code, None
            exec_resp_data = exec_resp.json()
            return exec_resp.status_code, exec_resp_data

    async def check_id(self, connecting_id: int) -> bool:
        allowed_telegram_ids = await cl_data_db.get_all_data(match=f"telegram_dta:*")
        for tg_id in allowed_telegram_ids:
            if tg_id.get('id') != str(connecting_id):
                return False
            else:
                return True

    async def run_shell_cmd(self, cmd: str):
        process = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()
    
        self.logger.error(stderr.decode())
        
        self.logger.info(stdout.decode())
        
        return_code = await process.wait()  
        
        self.logger.info(return_code)

        return return_code, stdout.decode(), stderr.decode()
    
