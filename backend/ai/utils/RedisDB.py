import redis.asyncio as redis
import logging
from typing import List
from init_app import logger

class RedisDB:
   
    def __init__(self, hostname='', port=''):
        self.host_name=hostname
        self.port=port
        self.logger = logging.getLogger(__name__)
        
    async def connect_db(self):
        self.redis_conn = redis.from_url( 
                f"redis://{self.host_name}:{self.port}", 
                encoding="utf-8", decode_responses=True)
        if self.redis_conn is None:
            self.logger.info(f'Redis connection to {self.host_name} failed')
            return None
        else:
            self.logger.info(f'Redis connection to {self.host_name} succeeded.')

    async def ping_db(self):
        try:
            pong = await self.redis_conn.ping()
            self.logger.info(pong)
        except Exception as e:
            logger.info(f"DB connection error: {str(e)}")
        finally:
            await self.redis_conn.close()
        return

    async def upload_db_data(self, id = '', data = {}):
        await self.connect_db()
        try: 
            str_hashmap = {str(k): str(v) for k, v in data.items()}
            result = await self.redis_conn.hset(id, mapping=str_hashmap)
        except Exception as e:
            logger.info(f"DB Upload Error: {str(e)}")
        finally:
            await self.redis_conn.close()
        return result

    async def get_all_data(self, match='*', cnfrm=False):
        await self.connect_db()
        try:
            all_data = {}
            cursor = b'0'  # Start the SCAN with cursor 0
            result=None

            if cnfrm is True:
                cursor, keys = await self.redis_conn.scan(cursor=cursor, match=match)
                
                if keys:
                    result = True
                else:
                    result = False
            else:
                cursor, keys = await self.redis_conn.scan(cursor=cursor, match=match)
                for key in keys:
                    hash_data = await self.redis_conn.hgetall(key)
                    all_data[key] = {k: v for k, v in hash_data.items()}
                if all_data.items():
                    result = all_data
                else:
                    result = None
        except Exception as e:
            self.logger.info(f"Error retrieving data: {e}")
        finally:
            await self.redis_conn.close()
        return result
           
    async def get_obj_data(self, key=''):
        await self.connect_db()
        try:
            probe = await self.redis_conn.hgetall(key)    
        except Exception as e:
            logger.info(str(e))
        finally:
            await self.redis_conn.close()
        if probe:
            return probe
        else:
            return None

    async def del_obj(self, key=''):
        await self.connect_db()
        try:
            probe = await self.redis_conn.delete(key)
        except Exception as e:
            logger.info(str(e))
        finally:
            await self.redis_conn.close()
        if probe:
            return probe
        else:
            return None

    async def json_obj_mgr(self, task: str, save_data: List[tuple]=None, keys: List[str]=None, path: str = '$', pattern: str | List[str] = None):
        await self.connect_db()
        result = None
        try:
            match task:
                case 's':
                    if save_data:
                        result = await self.redis_conn.json().mset(save_data)
                case 'g':
                    if pattern is not None:
                        if isinstance(pattern, str):
                            matching_keys = [key async for key in self.redis_conn.scan_iter(match=pattern)]
                        else:
                            matching_keys = list(pattern)

                        if matching_keys:
                            matching_keys = [
                                key.decode() if isinstance(key, bytes) else key
                                for key in matching_keys
                            ]
                            json_data = await self.redis_conn.json().mget(keys=matching_keys, path=path)
                            result = dict(zip(matching_keys, json_data))
                        else:
                            result = {}
                case 'd':
                    result = await self.redis_conn.json().delete(key=keys[0], path=path)
        except Exception as e:
            self.logger.error(f"json_obj_mgr({task}) failed: {e}")
            result = None
        finally:
            await self.redis_conn.close()
        return result
        
        

