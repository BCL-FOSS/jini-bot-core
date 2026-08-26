from quart import (Request, Websocket, websocket, render_template_string)
import asyncio
from utils.broker import Broker
from quart import json
import html
import shlex
from quart.utils import run_sync
import json
from init_app import app, logger, cron, schedule_cronjob, cl_sess_db, cl_data_db, cl_auth_db, ip_ban_db, ws_rate_limiter, check_for_utils, cwd, util_obj, api_name, max_auth_attempts, cli, utility_scripts_path, probe_url, init_core_api, main_url, current_client, client_auth, Client
import os
from quart import (websocket, jsonify)
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from quart import request, jsonify, request, Response
import bcrypt
from quart_auth import Unauthorized
from datetime import datetime, timedelta, timezone
import uuid
import secrets
from quart_auth import (
    Action
)
from functools import wraps

broker = Broker()
auth_ping_counter = {}
auth_attempts={}
connected_probes={}   
NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD = None 
email_script_path = os.path.join(utility_scripts_path, f'EmailMgr.py')

def as_bytes(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return str(value).encode()

async def retrieve_user_sess_data(sess_id):
    if not sess_id:
        return None
    cl_sess_data = await cl_sess_db.get_all_data(match=f"*{sess_id}*")
    if not cl_sess_data:
        logger.warning(f"No session record found for {sess_id}")
        return None
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)
    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml'),
            'sess_id': sess_id,
            'auth_token': cl_sess_data_dict.get('auth_token')}
    return data

async def ip_blocker(conn_obj: Request | Websocket, auto_ban: bool = False, check_if_allowed: bool = False):
    if check_if_allowed is True:
        if await ip_ban_db.get_all_data(match=f"*blocked_ip:{conn_obj.access_route[-1]}*", cnfrm=True) is True:
            logger.warning(f"IP {conn_obj.access_route[-1]} is not in allowed list, blocking access.")
            return False
    if auto_ban is True:
        logger.info(f"Auto banning IP: {conn_obj.access_route[-1]}")
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': conn_obj.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{conn_obj.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {conn_obj.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(conn_obj.access_route[-1], None) 

    if conn_obj.access_route[-1] not in auth_attempts:
        auth_attempts[conn_obj.access_route[-1]] = 1

    if auth_attempts[conn_obj.access_route[-1]] != max_auth_attempts:
        auth_attempts[conn_obj.access_route[-1]] += 1
    else:
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': conn_obj.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{conn_obj.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {conn_obj.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(conn_obj.access_route[-1], None)

def user_login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        auth_id = current_client.auth_id
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header.split(" ")[1]

        if auth_id is None or auth_id.strip() == "" or await cl_sess_db.get_all_data(match=f"*{auth_id}*", cnfrm=True) is False or token is None or token.strip() == "":
            await ip_blocker(conn_obj=request)
            raise Unauthorized()

        sess_data = await retrieve_user_sess_data(sess_id=auth_id)

        if not sess_data or sess_data.get('auth_token') is None:
            await ip_blocker(conn_obj=request)
            raise Unauthorized()

        if bcrypt.checkpw(password=token.encode(), hashed_password=as_bytes(sess_data.get('auth_token'))) is False:
            await ip_blocker(conn_obj=request)
            raise Unauthorized()
            
        return await app.ensure_async(func)(*args, **kwargs)
    return wrapper

async def jwt_verification(request: Request, api_key: str = None, auth_id: str = None):
    try:
        auth_check = False

        if api_key:
            api_data = await cl_auth_db.get_all_data(match=f"{api_name}:dta:*")
            if not api_data:
                await ip_blocker(conn_obj=request)
                raise Unauthorized()
            api_data_dict = next(iter(api_data.values()))
            if bcrypt.checkpw(api_key.encode(), as_bytes(api_data_dict.get(api_name))) is False:
                await ip_blocker(conn_obj=request)
                raise Unauthorized()

            auth_check = True
            return api_data_dict, auth_check

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            await ip_blocker(conn_obj=request)
            raise Unauthorized()
        token = auth_header.split(" ")[1]
        sess_data = await retrieve_user_sess_data(sess_id=auth_id)
        if not sess_data or sess_data.get('auth_token') is None:
            await ip_blocker(conn_obj=request)
            raise Unauthorized()
        if bcrypt.checkpw(password=token.encode(), hashed_password=as_bytes(sess_data.get('auth_token'))) is False:
            await ip_blocker(conn_obj=request)
            raise Unauthorized()

        auth_check = True
        return None, auth_check
    except Unauthorized:
        raise
    except (ExpiredSignatureError, InvalidTokenError):
        raise
    except Exception as e:
        logger.exception(f"jwt_verification failed: {e}")
        raise Unauthorized()

async def ws_jwt_verification(request: Websocket = None, api_token: str = None):
    try:
        if api_token:
            api_data = await cl_auth_db.get_all_data(match=f"{api_name}:dta:*")
            if not api_data:
                await ip_blocker(conn_obj=request or websocket)
                raise Unauthorized()
            api_data_dict = next(iter(api_data.values()))
            jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
            decoded_token = jwt.decode(jwt=api_token, key=jwt_key, algorithms=["HS256"])
            if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand'):
                await ip_blocker(conn_obj=request or websocket)
                raise Unauthorized()

        if request:
            auth_id = request.args.get('id')
            token = request.args.get('token')
            if not auth_id or not token:
                await ip_blocker(conn_obj=request)
                raise Unauthorized()
            sess_data = await retrieve_user_sess_data(sess_id=auth_id)
            if not sess_data or sess_data.get('auth_token') is None:
                await ip_blocker(conn_obj=request)
                raise Unauthorized()
            if bcrypt.checkpw(password=token.encode(), hashed_password=as_bytes(sess_data.get('auth_token'))) is False:
                await ip_blocker(conn_obj=request)
                raise Unauthorized()

        return True
    except Unauthorized:
        raise
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request or websocket)
        raise
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request or websocket)
        raise
    except Exception as e:
        logger.exception(f"ws_jwt_verification failed: {e}")
        raise Unauthorized()

async def _receive_probe() -> None:
    while True:
        message = await websocket.receive()
        logger.debug(message)
        message = json.loads(message)
        action=message.get('act')
        if action:
            match action:
                case 'hb':
                    logger.debug(f"Received probe {message.get('sess_id')} heartbeat: {message}")
                    now = datetime.now(tz=timezone.utc)
                    if message.get('sess_id') in connected_probes:
                        entry = connected_probes.get(message.get('sess_id'))
                        exp = entry.get('exp')
                        if exp and now <= exp:
                            new_exp = util_obj.round_up_to_30sec(now + timedelta(seconds=30))
                            entry['exp'] = new_exp
                            connected_probes[message.get('sess_id')] = entry
                            logger.debug(f"Refreshed ping expiry for session {message.get('sess_id')} to {new_exp}")
                    else:
                        pass
                case 'map':
                    doc_id = f"map_{message.get('timestamp')}_{message.get('sess_id')}_{str(uuid.uuid4())}"
                    data=[(message.get('sess_id'), f'$.devices.{doc_id}', json.loads(message.get('map')))]
                    if await cl_data_db.json_obj_mgr(task='ms', update_data=data):
                        logger.info(f"Network Map for Probe {message.get('sess_id')} received")
                case 'alert':
                    pass
                case _:
                    pass
        else:
            pass

async def session_watchdog(sess_id: str, check_interval: float = 5.0):
    logger.info(f"Starting session watchdog for {sess_id}")
    while True:
        try:
            entry = connected_probes.get(sess_id)
            now = datetime.now(tz=timezone.utc)
            if not entry:
               
                await asyncio.sleep(check_interval)
                continue

            exp = entry.get('exp')
            if exp is None:
                await asyncio.sleep(check_interval)
                continue

            now_quant = util_obj.round_down_to_30sec(now)
            exp_quant = util_obj.round_up_to_30sec(exp)

            if now_quant > exp_quant:
                logger.info(f"Session {sess_id} expired at {exp_quant} (now_quant={now_quant})")
                if connected_probes[sess_id]['status'] == 'offline':
                    await asyncio.sleep(check_interval)
                    continue

                if connected_probes[sess_id]['status'] == 'online':
                    connected_probes[sess_id]['status'] = 'offline'
                    connected_probes[sess_id]['badge'] = 'failure'

                    alert_id=f"alert:{sess_id}:{str(uuid.uuid4())}"
                    alert_data={'alert': 'outage',
                           'sess_id': sess_id,
                           'id': alert_id
                    }

                    await Broker(connected_probes[sess_id]['broker']).publish(message=json.dumps(alert_data))
                    await broker.publish(message=json.dumps(alert_data))

                    if await cl_data_db.json_obj_mgr(task='s', save_data=[(sess_id, f"$.alerts.{str(uuid.uuid4())}")]) is not None:
                        logger.info(f"{sess_id} {alert_data['alert']} processed")

                await asyncio.sleep(check_interval)

            else:
                seconds_to_expiry = (exp_quant - now_quant).total_seconds()
                sleep_for = min(check_interval, max(seconds_to_expiry, 0))
                await asyncio.sleep(sleep_for)
                    
        except asyncio.CancelledError:
            logger.info(f"Session watchdog for {sess_id} cancelled")
            break
                
        except Exception as e:
            logger.exception(f"Error in session_watchdog for {sess_id}: {e}")
            # Without this the loop retries the same failure without pause.
            await asyncio.sleep(check_interval)

@app.before_serving
async def startup(): 
    await check_for_utils()
    await init_core_api()
    

# ---------------------------------------------------------------- CORS
# Browser and Electron clients load from a different origin (or from
# file://, whose origin is "null"), so without these headers every
# cross-origin call fails at the preflight. Set CORS_ALLOWED_ORIGINS to a
# comma-separated list to restrict it; the default echoes the caller.
def _allowed_origin(origin: str) -> str | None:
    if not origin:
        return None
    configured = os.getenv('CORS_ALLOWED_ORIGINS', '').strip()
    if not configured or configured == '*':
        return origin
    allowed = [o.strip() for o in configured.split(',') if o.strip()]
    return origin if origin in allowed else None

@app.before_request
async def handle_preflight():
    if request.method != 'OPTIONS':
        return None
    origin = _allowed_origin(request.headers.get('Origin'))
    if not origin:
        return None
    response = Response(response='', status=204)
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = ', '.join([
        'Content-Type',
        'Authorization',
        os.getenv('API_KEY_HEADER_NAME', 'x-api-key')
    ])
    response.headers['Access-Control-Max-Age'] = '600'
    return response

@app.after_request
async def apply_cors(response: Response):
    origin = _allowed_origin(request.headers.get('Origin'))
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'
    return response


async def publish_probe_alerts(prb_id: str, alerts: list) -> int:
    published = 0
    probe_entry = connected_probes.get(prb_id)

    for alert in alerts or []:
        if not isinstance(alert, dict):
            logger.warning(f"Skipping non-object alert for {prb_id}: {alert!r}")
            continue

        alert.setdefault('prb_id', prb_id)
        alert.setdefault('id', f"alert:{prb_id}:{uuid.uuid4()}")
        message = json.dumps({'alert': alert, 'sess_id': prb_id, 'id': alert['id']})

        # The probe channel only exists while that probe is connected.
        if probe_entry and probe_entry.get('broker'):
            try:
                await Broker(probe_entry['broker']).publish(message=message)
            except Exception as e:
                logger.error(f"Could not publish to the {prb_id} probe channel: {e}")
        else:
            logger.info(f"No live probe channel for {prb_id}; user channel only")

        try:
            await broker.publish(message=message)
            published += 1
        except Exception as e:
            logger.error(f"Could not publish to the user channel: {e}")

        try:
            await cl_data_db.json_obj_mgr(
                task='ms',
                update_data=[(prb_id, f"$.alerts.{alert['id']}", alert)]
            )
        except Exception as e:
            logger.error(f"Could not persist alert {alert['id']}: {e}")

    return published

async def email_report(subject: str, body_html: str) -> bool:
    prim_contact = await cl_auth_db.get_all_data(match='*pct:*')
    if not prim_contact:
        logger.error("No primary contact on file; skipping the report email")
        return False
    contact = next(iter(prim_contact.values()))

    email_params = {
        'sender': {'name': os.getenv('JINIBOT_NAME'), 'email': os.environ.get('BREVO_SENDER_EMAIL')},
        'to': [{'name': f"{contact.get('fname')} {contact.get('lname')}", 'email': contact.get('eml')}],
        'subject': subject,
        'html_content': body_html
    }

    payload = shlex.quote(json.dumps(email_params))
    email_code, email_output, email_error = await util_obj.run_shell_cmd(
        cmd=f"python3 {email_script_path} -t 'send' -p {payload}"
    )
    if email_code != 0:
        logger.error(f"Report email failed ({email_code}): {email_error}")
        return False
    logger.info(f"Report email sent: {email_output}")
    return True

@app.before_request
async def check_ip():
    if await ip_blocker(conn_obj=request, check_if_allowed=True) is False:
        raise Unauthorized()

@app.before_websocket
async def check_ip_ws():
    if await ip_blocker(conn_obj=websocket, check_if_allowed=True) is False:
        try:
            await websocket.close()
        except RuntimeError:
            return None

@app.websocket(f"{probe_url}/channels/<string:probe_id>/<int:connect_type>")
async def heartbeat(probe_id, connect_type):
    monitor_task = None
    try:
        token = websocket.args.get('token')
        if not token:
            await ip_blocker(conn_obj=websocket)
            await websocket.close(1008)
            return

        try:
            await ws_jwt_verification(api_token=token)
        except (Unauthorized, ExpiredSignatureError, InvalidTokenError):
            await websocket.close(1008)
            return

        if probe_id is None or probe_id.strip() == "":
            await ip_blocker(conn_obj=websocket)
            await websocket.close(1008)
            return

        if await cl_data_db.get_all_data(match=f"*{probe_id}*", cnfrm=True) is False:
            await ip_blocker(conn_obj=websocket, auto_ban=True)
            await websocket.close(1008)
            return

        if await ws_rate_limiter.check_rate_limit(client_id=probe_id) is False:
            await ip_blocker(conn_obj=websocket)
            await websocket.close(1013)
            return

        if connect_type == 0:
            if probe_id and (probe_id not in connected_probes):
                now = datetime.now(tz=timezone.utc)
                connected_probes[probe_id] = {'conn_start': now,
                                        'id': probe_id,
                                        'exp': util_obj.round_up_to_30sec(now + timedelta(seconds=30)),
                                        'broker': Broker(),
                                        'status': 'online',
                                        'badge': 'success',
                                        'last_online': now.isoformat()
                                        }
                logger.debug(f"Initialized ping expiry for session {probe_id} -> {connected_probes[probe_id]['exp']}")
                asyncio.ensure_future(_receive_probe())
                monitor_task = asyncio.create_task(session_watchdog(sess_id=probe_id))

            elif probe_id and (probe_id in connected_probes):
                if connected_probes[probe_id]['status'] == 'offline':
                    now = datetime.now(tz=timezone.utc)
                    connected_probes[probe_id]['status'] = 'online'
                    connected_probes[probe_id]['badge'] = 'success'
                    connected_probes[probe_id]['last_online'] = now.isoformat()
                    connected_probes[probe_id]['exp'] = util_obj.round_up_to_30sec(now + timedelta(seconds=30))
                asyncio.ensure_future(_receive_probe())
                monitor_task = asyncio.create_task(session_watchdog(sess_id=probe_id))

        if probe_id and (probe_id in connected_probes) and connect_type == 1:
            asyncio.ensure_future(_receive_probe())

        if probe_id not in connected_probes:
            await websocket.close(1008)
            return

        await websocket.accept()
        try:
            async for message in Broker(connected_probes[probe_id]['broker']).subscribe():
                await websocket.send(message)
        except asyncio.CancelledError:
            logger.debug("Subscribe loop cancelled (client disconnected)")
        except Exception:
            logger.exception("Error while reading from broker or sending websocket message")

    except asyncio.CancelledError:
        logger.debug(f"Heartbeat socket for {probe_id} cancelled")
    except Exception as e:
        logger.exception(f"heartbeat error: {e}")
    finally:
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error cancelling monitor task: {e}")

@app.websocket(f"{main_url}/channels/users")
async def users():
    try:
        await ws_jwt_verification(request=websocket)
    except (Unauthorized, ExpiredSignatureError, InvalidTokenError):
        logger.warning("Rejected unauthenticated user channel connection")
        await websocket.close(1008)
        return
    except Exception as e:
        logger.exception(f"user channel auth error: {e}")
        await websocket.close(1011)
        return

    await websocket.accept()
    logger.info("User channel connected")
    try:
        async for message in broker.subscribe():
            await websocket.send(message)
    except asyncio.CancelledError:
        logger.debug("User channel cancelled (client disconnected)")
    except Exception as e:
        logger.exception(f"user channel error: {e}")

@app.route(f'{main_url}/register', methods=['POST'])
async def register():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()
    _, auth_check = await jwt_verification(request=request, api_key=api_key)
    if auth_check is not True:
        raise Unauthorized()

    user_data = await request.get_json()
    username = str(user_data.get('uname')).replace(" ", "").lower()
    password_hash = bcrypt.hashpw(str(user_data.get('pass')).encode(), bcrypt.gensalt())
    logger.info(f"Registering user: {username}")
    user_nmp, user_id = util_obj.gen_user(username=username)
    user_obj = {
            "id": user_id,
            "unm": username,
            "pwd": password_hash,
            "eml": user_data.get('eml'),
            "telegram_id": user_data.get('telegram'),
            "fname": user_data.get('fname'),
            "lname": user_data.get('lname')
        }
    user_key = f"{user_nmp}:{user_id}"
            
    if await cl_auth_db.get_all_data(match="*pct:*", cnfrm=True) is False:
            user_obj["db_id"] = f'pct:{user_key}'
    else:
            user_obj["db_id"] = user_key
        
    if await cl_auth_db.upload_db_data(id=user_obj.get('db_id'), data=user_obj) > 0:
            logger.info(f"Registration successful for '{username}'.")
                
        
            contact_data = {"LASTNAME": user_obj.get('lname'),
                                "FIRSTNAME": user_obj.get('fname'),
                                }
            add_contact_params = {'email': user_obj.get('eml'),
                            'ext_id': user_obj.get('db_id'),
                            'attributes': contact_data
                        }
                                        
            add_contact_command = f"python3 {email_script_path} -t 'add' -p {add_contact_params}"
            add_contact_code, add_contact_output, add_contact_error = await util_obj.run_shell_cmd(cmd=add_contact_command)
            logger.info(f"code: {add_contact_code}\noutput: {add_contact_output}\nerror: {add_contact_error}")
            return jsonify({'registered': username}), 200
    else:
        return jsonify({'error': 'Could not create the account'}), 400

@app.route(f'{main_url}/login', methods=['POST'])
async def login():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()
    _, auth_check = await jwt_verification(request=request, api_key=api_key)
    if auth_check is not True:
        raise Unauthorized()

    auth_data = await request.get_json()
    username = str(auth_data.get('uname'))
    password = str(auth_data.get('pass'))
    
    username = username.replace(" ", "").lower()
    
    if await cl_auth_db.get_all_data(match=f'*uid:{username}*', cnfrm=True) is False:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()
    
    account_data = await cl_auth_db.get_all_data(match=f'*uid:{username}*')    
    sub_dict = next(iter(account_data.values()))       
    password_hash = sub_dict.get('pwd')
                    
    if account_data and bcrypt.checkpw(password.encode(), as_bytes(password_hash)) is False:
        if request.access_route[-1] not in auth_ping_counter:
            now = datetime.now(tz=timezone.utc)
            auth_ping_counter[request.access_route[-1]] = {
                "ip": request.access_route[-1],
                "fail_count": 1,
                "timestamp": now
                }
            raise Unauthorized()
        
        if request.access_route[-1] in auth_ping_counter and auth_ping_counter[request.access_route[-1]]['fail_count'] >= int(os.getenv('MAX_AUTH_ATTEMPTS')):
            now = datetime.now(tz=timezone.utc)
            auth_ping_counter[request.access_route[-1]]['timestamp']=now
            await ip_blocker(conn_obj=request, auto_ban=True)
            raise Unauthorized()

        if request.access_route[-1] in auth_ping_counter and auth_ping_counter[request.access_route[-1]]['fail_count'] < int(os.getenv('MAX_AUTH_ATTEMPTS')):
            now = datetime.now(tz=timezone.utc)
            auth_ping_counter[request.access_route[-1]]['fail_count']+=1
            auth_ping_counter[request.access_route[-1]]['timestamp']=now
            raise Unauthorized()

        raise Unauthorized()

    auth_ping_counter.pop(request.access_route[-1], None)
                
    logger.info(f'Account credentials verified for {username}')
    session_id = util_obj.gen_id()    
    client_auth.login_user(Client(auth_id=session_id, action=Action.WRITE))
    sub_dict.pop('pwd')
    auth_token = client_auth.dump_token(auth_id=session_id, app=app)
    sub_dict['auth_token'] = bcrypt.hashpw(password=auth_token.encode(), salt=bcrypt.gensalt())
    if await cl_sess_db.upload_db_data(id=session_id, data=sub_dict) > 0:
        return jsonify({'token': auth_token, 'session_id': session_id}), 200

    logger.error(f"Could not persist session for {username}")
    return jsonify({'error': 'Could not create a session'}), 500

@app.route(f'{main_url}/logout/<string:auth_id>', methods=['GET'])
@user_login_required
async def logout(auth_id):

    if await cl_sess_db.get_all_data(match=f'*{auth_id}*', cnfrm=True) is False:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()

    if await cl_sess_db.del_obj(key=auth_id) is not None:
        client_auth.logout_user()
        return jsonify({'logged_out': auth_id}), 200

    logger.error(f"Could not delete session {auth_id}")
    return jsonify({'error': 'Could not end the session'}), 400

@app.route(f'{main_url}/reset', methods=['GET'])
@user_login_required
async def reset():
    prim_contact = await cl_auth_db.get_all_data(match='*pct:*')
    prim_contact_dict = next(iter(prim_contact.values()))
    old_api_data = await cl_data_db.get_all_data(match=f"{api_name}:dta:*")
    old_api_data_dict = next(iter(old_api_data.values())) if old_api_data else None
    if await cl_data_db.del_obj(key=f"{api_name}:dta:{old_api_data_dict.get(f'{api_name}_id')}") is not None:
        api_id = util_obj.key_gen(size=10) 
        new_api_key = str(uuid.uuid4())
        updated_api_data = {
            api_name: bcrypt.hashpw(new_api_key.encode(), bcrypt.gensalt()),
            f"{api_name}_id": api_id,
            f"{api_name}_rand": secrets.token_urlsafe(500),
            f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
        }
   
        if await cl_data_db.upload_db_data(id=f"{api_name}:dta:{api_id}", data=updated_api_data) > 0:
            link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))

            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Hello,</p>
                        <p><strong>umjiniti</strong> API key for 'JiniBot <strong>{os.getenv('JINIBOT_NAME')}</strong> has been reset.</p>
                        <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                        <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                        <p>Thank you,<br/>umjiniti Team</p>

                        </div>"""
            email_params = {'sender': {'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                            'to': [{"name": f"{prim_contact_dict.get('fname')} {prim_contact_dict.get('lname')}", "email": prim_contact_dict.get('eml')}],
                            'subject': f"New Jini API Key Generated for {prim_contact_dict.get('eml')}",
                            'hmtl_content': html_snippet }
            
            email_command = f"python3 {email_script_path} -t 'send' -p {email_params}"
            email_code, email_output, email_error = await util_obj.run_shell_cmd(cmd=email_command)
            return jsonify(), 200
        else:
            return jsonify(), 400
    else:
        return jsonify(), 400

@app.route(f'{main_url}/flows/new', methods=['POST'])
@user_login_required
async def flow():
    data = await request.get_json()
    if data is None:
        await ip_blocker(conn_obj=request)
        return jsonify(), 400
   
    if not data.get('id'):
        data['id'] = f"flow:{data.get('name')}:{str(uuid.uuid4())}"
    job1 = None
    now = datetime.now(tz=timezone.utc).isoformat()
    job_comment=f"auto_job_{data.get('name')}_{now}"
    task_command = ""
    script_path = os.path.join(cwd, 'utils', 'RemoteFlowRunner.py')
    task_command = f"python3 {script_path} -f {data.get('flow')} -n {data.get('name')}"
    job1 = await run_sync(lambda: cron.new(command=task_command, comment=job_comment))()
    scheduled_job = await run_sync(lambda: schedule_cronjob(job1, data.get('schedule')))()
    if await run_sync(scheduled_job.is_valid)():
        await run_sync(cron.write)()
        await asyncio.sleep(1)
        logger.info(f"Cron job added: {scheduled_job}")
        data['comment'] = job_comment
        saved = await cl_data_db.json_obj_mgr(
            task='ms',
            update_data=[(data['prb_id'], f"$.flows.{data.get('id')}", data)]
        )
        if not saved:
            logger.error(f"Cron job scheduled but flow {data.get('id')} could not be saved")
            return jsonify({'error': 'The flow could not be saved'}), 400
        return jsonify({'id': data.get('id'), 'comment': job_comment}), 200
    else:
        return jsonify({'error': 'The schedule produced an invalid cron job'}), 400
 

@app.route(f'{main_url}/alerts/update', methods=['POST'])
@user_login_required
async def alert_update():
    data = await request.get_json()
    if not data or not data.get('id') or not data.get('prb_id'):
        return jsonify({'error': 'prb_id and id are required'}), 400

    probes = await cl_data_db.json_obj_mgr(
        task='g', pattern=[data.get('prb_id')], path=f"$.alerts.{data.get('id')}"
    )
    existing = next(iter(probes.values()), None) if probes else None
    while isinstance(existing, list) and len(existing) == 1:
        existing = existing[0]

    if not isinstance(existing, dict):
        return jsonify({'error': 'No such alert'}), 404

    for field in ('ack', 'rslv', 'status'):
        if data.get(field):
            existing[field] = data[field]

    saved = await cl_data_db.json_obj_mgr(
        task='ms',
        update_data=[(data.get('prb_id'), f"$.alerts.{data.get('id')}", existing)]
    )
    if not saved:
        return jsonify({'error': 'The alert could not be updated'}), 400
    return jsonify(existing), 200

@app.route(f'{probe_url}/init', methods=['GET'])
async def prbinit():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()
    api_data_dict, _ = await jwt_verification(request=request, api_key=api_key)
    api_jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
    api_rand = api_data_dict.get(f'{api_name}_rand')
    api_id = api_data_dict.get(f'{api_name}_id')
    jwt_token = util_obj.generate_ephemeral_token(id=api_id, secret_key=api_jwt_key, rand=api_rand, type='prb')
    response = Response(response='Probe Token Success', status=200)  
    response.set_cookie(
            key='access_token',
            value=jwt_token,
            httponly=False,
            secure=False,
            max_age=None
        )
    return response
  
@app.route(f'{probe_url}/enroll', methods=['POST'])
async def prbenroll():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()
    await jwt_verification(request=request, api_key=api_key)
    site = request.args.get('site')
    if not site:
        site = 'default'
    adopted_probe_data = await request.get_json()
    adopted_probe_data['devices']={}
    adopted_probe_data['trace_results']={}
    adopted_probe_data['perf_results']={}
    adopted_probe_data['scan_results']={}
    adopted_probe_data['pcap_results']={}
    adopted_probe_data['alerts']={}
    adopted_probe_data['chats']={}
    adopted_probe_data['tasks']={}
    adopted_probe_data['flows']={}
    adopted_probe_data['tux_count']=0
    adopted_probe_data['win_count']=0
    adopted_probe_data['android_count']=0
    adopted_probe_data['iphone_count']=0
    if await cl_data_db.json_obj_mgr(task='s', save_data=[(adopted_probe_data.get('prb_id'), f"$", adopted_probe_data)]) is not None:
        return jsonify(), 200
    else:
        return jsonify(), 400

@app.route(f'{probe_url}/get', methods=['POST'])
@user_login_required
async def prbdata():
    data = await request.get_json()
    if not data:
        await ip_blocker(conn_obj=request)
        return jsonify({'error': 'A JSON body is required'}), 400
    pattern = data.get('pattern') or 'prb:*'
    path = data.get('path') or '$'

    if isinstance(pattern, str):
        candidate = pattern.strip()
        if candidate.startswith('['):
            try:
                pattern = json.loads(candidate)
            except json.JSONDecodeError:
                logger.warning(f"Could not decode key list {candidate!r}; treating it as a glob")

    probes = await cl_data_db.json_obj_mgr(task='g', pattern=pattern, path=path)
    return jsonify(probes if probes is not None else {}), 200
    
@app.route(f'{probe_url}/delete', methods=['POST'])
@user_login_required
async def prbdelete():
    data = await request.get_json() 
    id = data.get('id')
    result = await cl_data_db.del_obj(key=id)
    if result is None:
        return jsonify(), 400
    return jsonify(), 200

@app.route(f'{probe_url}/ingest', methods=['POST'])
async def prbingest():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()
    await jwt_verification(request=request, api_key=api_key)    
    data = await request.get_json()
    if data is None:
        return jsonify(), 400
    payload = {
        'documents': data.get('documents'),
    }
    ingest_resp, _ = await util_obj.make_http_request(
        headers={'content-type': 'application/json'},
        url=f"{os.getenv('OLLAMA_PROXY_URL')}/ingest/batch",
        data=payload,
        timeout=int(os.getenv('REQUEST_TIMEOUT'))
    )
    if ingest_resp != 200:
        logger.error(f"Document ingest failed with status {ingest_resp}")
        return jsonify({'error': 'Ingest failed'}), 502

    analysis_resp, analysis_body = await util_obj.make_http_request(
        headers={'content-type': 'application/json'},
        url=f"{os.getenv('OLLAMA_PROXY_URL')}/analyze/batch",
        data=data,
        timeout=int(os.getenv('REQUEST_TIMEOUT'))
    )
    if analysis_resp != 200:
        logger.error(f"Analysis failed with status {analysis_resp}")
        return jsonify({'error': 'Analysis failed'}), 502

    analysis_body = analysis_body or {}
    published = 0

    if analysis_body.get('detect_type') == 2:
        published = await publish_probe_alerts(
            prb_id=data.get('prb_id'),
            alerts=analysis_body.get('alerts') or []
        )

    report = analysis_body.get('report') or analysis_body.get('result')
    try:
        detect_type = int(data.get('detect_type', 0))
    except (TypeError, ValueError):
        detect_type = 0

    if detect_type in {1, 2} and report:
        flow_name = data.get('flow_name') or 'automation'
        html_snippet = (
            '<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">'
            '<p>Hello,</p>'
            f"<p>{os.getenv('JINIBOT_NAME')}'s {flow_name} Analysis:</p>"
            f"<pre style=\"white-space: pre-wrap; font-family: inherit;\">{html.escape(str(report))}</pre>"
            '</div>'
        )
        await email_report(
            subject=f"{os.getenv('JINIBOT_NAME')} {flow_name} Analysis Report",
            body_html=html_snippet
        )

    return jsonify({'published': published, 'detect_type': detect_type}), 200

@app.route(f'{probe_url}/flow/new', methods=['POST'])
async def prbflow():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        raise Unauthorized()
    await jwt_verification(request=request, api_key=api_key)
    data = await request.get_json()
    if not data:
        await ip_blocker(conn_obj=request)
        return jsonify({'error': 'A JSON body is required'}), 400
    if not data.get('id'):
        data['id'] = f"flow:{data.get('name')}:{str(uuid.uuid4())}"
    saved = await cl_data_db.json_obj_mgr(task='s', save_data=[(data.get('prb_id'), f"$.flows.{data.get('id')}", data)])
    if not saved:
        return jsonify({'error': 'The flow could not be saved'}), 400
    return jsonify({'id': data['id']}), 200

@app.errorhandler(Unauthorized)
async def unauthorized(e):
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401

@app.errorhandler(ExpiredSignatureError)
async def token_expired(e):
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Token expired"})), 1008

@app.errorhandler(InvalidTokenError)
async def invalid_token(e):
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Invalid token"})), 1000

@app.errorhandler(400)
async def bad_request(e):
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Bad Request"})), 400

@app.errorhandler(401)
async def need_to_login(e):
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401
    
@app.errorhandler(404)
async def page_not_found(e):
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Resource not found"})), 404

@app.errorhandler(500)
async def handle_internal_error(e):
    return await render_template_string(json.dumps({"error": "Internal server error"})), 500