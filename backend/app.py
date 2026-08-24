from quart import (Request, Websocket, websocket, render_template_string)
import asyncio
from utils.broker import Broker
from quart import jsonify
from quart.utils import run_sync
import json
from init_app import app, logger, cron, schedule_cronjob, cl_sess_db, cl_data_db, cl_auth_db, ip_ban_db, ws_rate_limiter, check_for_utils, cwd, load_network_diagnostic_prompt, util_obj, api_name, max_auth_attempts, cli, utility_scripts_path, probe_url, init_core_api, main_url, current_client, client_auth, Client
import os
from quart import (websocket, abort, jsonify)
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

async def retrieve_user_sess_data(sess_id):
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{sess_id}")
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
    global auth_attempts
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

        if auth_id is None or auth_id.strip() == "" or await cl_sess_db.get_all_data(match=f"{auth_id}", cnfrm=True) is False or token is None or token.strip() == "".strip():
            await ip_blocker()
            return Unauthorized()

        sess_data = await retrieve_user_sess_data(sess_id=auth_id)

        if bcrypt.checkpw(password=token, hashed_password=sess_data.get('auth_token')) is False:
            await ip_blocker()
            return Unauthorized()
            
        return await app.ensure_async(func)(*args, **kwargs)
    return wrapper

async def jwt_verification(request: Request | Websocket, api_key: str = None):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            await ip_blocker(conn_obj=request)
            abort(401)
        token = auth_header.split(" ")[1]
        auth_check = False
        api_data = await cl_data_db.get_all_data(match=f"{api_name}:dta:*")
        if api_data is None:
            await ip_blocker(conn_obj=request)
            abort(401)
        api_data_dict = next(iter(api_data.values()))
        if token:
            jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
            decoded_token = jwt.decode(jwt=token, key=jwt_key , algorithms=["HS256"])
            if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand') or bcrypt.checkpw(api_key,api_data_dict.get(api_name)) is False:
                await ip_blocker(conn_obj=request)
                abort(401)
            else:
                auth_check = True
        else:
            if bcrypt.checkpw(api_key, api_data_dict.get(api_name)) is False:
                await ip_blocker(conn_obj=request)
                abort(401)
            else:
                auth_check = True
        return api_data_dict, auth_check
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request)
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request)
        return InvalidTokenError()
    except Exception:
        return jsonify("Error, occurred"), 400

async def _receive_probe() -> None:
    while True:
        message = await websocket.receive()
        logger.debug(message)
        message = json.loads(message)
        action=message['act']
        if action:
            match action:
                case 'hb':
                    logger.debug(f"Received probe {message['sess_id']} heartbeat: {message}")
                    now = datetime.now(tz=timezone.utc)
                    if message["sess_id"] in connected_probes:
                        entry = connected_probes.get(message["sess_id"])
                        exp = entry.get('exp')
                        if exp and now <= exp:
                            new_exp = util_obj.round_up_to_30sec(now + timedelta(seconds=30))
                            entry['exp'] = new_exp
                            connected_probes[message["sess_id"]] = entry
                            logger.debug(f"Refreshed ping expiry for session {message['sess_id']} to {new_exp}")
                    else:
                        pass
                case 'map':
                    doc_id = f"map_{message['timestamp']}_{message['sess_id']}_{str(uuid.uuid4())}"
                    data=[(message['sess_id'], f'$.devices.{doc_id}', json.loads(message['map']))]
                    if await cl_data_db.json_obj_mgr(task='ms', update_data=data):
                        logger.info(f"Network Map for Probe {message['sess_id']} received")
                case _:
                    pass
        else:
            pass

async def session_watchdog(sess_id: str, check_interval: float = 5.0):
    logger.info(f"Starting session watchdog for {sess_id}")
    while True:
        try:
            if connected_probes.get(sess_id):
                entry = connected_probes.get(sess_id)

            now = datetime.now(tz=timezone.utc)

            if not entry:
                # No entry yet (client hasn't pinged). We still want to expire after specified time from connection start,
                # but the connection code initializes an entry at connect. So just sleep and continue.
                await asyncio.sleep(check_interval)
                continue

            exp = entry.get('exp')
            if exp is None:
                await asyncio.sleep(check_interval)
                continue

           
            now_quant = util_obj.round_down_to_30sec(now)
            exp_quant = util_obj.round_up_to_30sec(exp)

            #logger.debug(f"Session {sess_id} now_quant={now_quant} exp_quant={exp_quant} (raw now={now} raw exp={exp})")

            # Expiration occurred
            if now_quant > exp_quant:
                logger.info(f"Session {sess_id} expired at {exp_quant} (now_quant={now_quant})")
                if connected_probes[sess_id]['status'] == 'offline':
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

                    if await cl_data_db.upload_db_data(id=alert_id, data=alert_data) > 0:
                        logger.info(f"{sess_id} {alert_data['alert']} processed")
                    
            else:
                # Not yet expired: sleep until the sooner of check_interval or time to expiry (based on quantized values)
                seconds_to_expiry = (exp_quant - now_quant).total_seconds()
                sleep_for = min(check_interval, max(seconds_to_expiry, 0))
                #logger.debug(f"Session {sess_id} not yet expired (expires at {exp_quant}), sleeping for {sleep_for} seconds")
                await asyncio.sleep(sleep_for)
                    
        except asyncio.CancelledError:
            logger.info(f"Session watchdog for {sess_id} cancelled")
            break
                
        except Exception as e:
            logger.exception(f"Error in session_watchdog for {sess_id}: {e}")

@app.before_serving
async def startup():
    global NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD
    NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD = await run_sync(load_network_diagnostic_prompt())    
    await check_for_utils()
    await init_core_api()
    
@app.before_request
async def check_ip():
    if await ip_blocker(conn_obj=request, check_if_allowed=True) is False:
        abort(401)

@app.before_websocket
async def check_ip_ws():
    if await ip_blocker(conn_obj=request, check_if_allowed=True) is False:
        try:
            await websocket.close()
        except RuntimeError:
            return None

@app.websocket(f"{probe_url}/channels/<string:probe_id>/<int:connect_type>")
@user_login_required
async def heartbeat(probe_id, connect_type):
    global connected_probes
    
    try:
        if probe_id is None or isinstance(probe_id, str) is False or probe_id.strip() == "":
            await ip_blocker(conn_obj=websocket, auto_ban=True)
            await websocket.close()

        if await cl_data_db.get_all_data(match=f"*{probe_id}*", cnfrm=True) is False:
            await ip_blocker(conn_obj=websocket, auto_ban=True)
            await websocket.close()

        if await ws_rate_limiter.check_rate_limit(client_id=probe_id) is False:
            await ip_blocker(conn_obj=websocket)
            await websocket.close()

        monitor_task = None
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

            if probe_id and (probe_id in connected_probes):
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
        await websocket.accept()

        try:
            async for message in  Broker(connected_probes[probe_id]['broker']).subscribe():
                await websocket.send(message)
        except asyncio.CancelledError:
            logger.debug("Subscribe loop cancelled (client disconnected)")
            pass
        except Exception as e:
            logger.exception("Error while reading from broker or sending websocket message")
            pass

    except Exception as e:
        logger.error(e)
    except asyncio.CancelledError as e:
        logger.error(e)
    finally:
        if monitor_task:
            try:
                monitor_task.cancel()
                await monitor_task
            except Exception as e:
                logger.error(f"Error cancelling monitor task: {e}")
                pass

@app.route(f'{main_url}/register', methods=['POST'])
async def register():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        abort(401)
    _, auth_check = await jwt_verification(request=request, api_key=api_key)

    if auth_check is True:
        user_data = await request.get_json()
        username = str(user_data['uname']).replace(" ", "").lower()
        password_hash = bcrypt.hashpw(user_data['pass'], bcrypt.gensalt())
        logger.info(f"Registering user: {username}")
        user_nmp, user_id = util_obj.gen_user(username=username)
        user_obj = {
                "id": user_id,
                "unm": username,
                "pwd": password_hash,
                "eml": user_data['eml'],
                "telegram_id": user_data['telegram'],
                "fname": user_data['fname'],
                "lname": user_data['lname']
            }
        user_key = f"{user_nmp}:{user_id}"
            
        if await cl_auth_db.get_all_data(match="*pct:*", cnfrm=True) is False:
                user_obj["db_id"] = f'pct:{user_key}'
        else:
                user_obj["db_id"] = user_key
        
        if await cl_auth_db.upload_db_data(id=user_obj['db_id'], data=user_obj) > 0:
                logger.info(f"Registration successful for '{username}'.")
                
        
                contact_data = {"LASTNAME": user_data['lname'],
                                    "FIRSTNAME": user_data['fname'],
                                    }
                add_contact_params = {'email': user_data['eml'],
                                'ext_id': user_obj['db_id'],
                                'attributes': contact_data
                            }
                                        
                add_contact_command = f"python3 {email_script_path} -t 'add' -p {add_contact_params}"
                add_contact_code, add_contact_output, add_contact_error = await util_obj.run_shell_cmd(cmd=add_contact_command)
                logger.info(f"code: {add_contact_code}\noutput: {add_contact_output}\nerror: {add_contact_error}")
                return jsonify(), 200

@app.route(f'{main_url}/login', methods=['POST'])
async def login():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        abort(401)
    _, auth_check = await jwt_verification(request=request, api_key=api_key)
    
    if auth_check is True:
        auth_data = await request.get_json()
        username = str(auth_data['uname'])
        password = str(auth_data['pass'])
    
        username = username.replace(" ", "").lower()
    
        if await cl_auth_db.get_all_data(match=f'*uid:{username}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            abort(401)
    
        account_data = await cl_auth_db.get_all_data(match=f'*uid:{username}*')    
        sub_dict = next(iter(account_data.values()))       
        password_hash = sub_dict.get('pwd')
                    
        if account_data and bcrypt.checkpw(password, password_hash) is False:
            if request.access_route[-1] not in auth_ping_counter:
                now = datetime.now(tz=timezone.utc)
                auth_ping_counter[request.access_route[-1]] = {
                    "ip": request.access_route[-1],
                    "fail_count": 1,
                    "timestamp": now
                    }
                return Unauthorized()
        
            if request.access_route[-1] in auth_ping_counter and auth_ping_counter[request.access_route[-1]]['fail_count'] >= os.getenv('MAX_AUTH_ATTEMPTS'):
                now = datetime.now(tz=timezone.utc)
                auth_ping_counter[request.access_route[-1]]['timestamp']=now
                await ip_blocker(conn_obj=request, auto_ban=True)
                return Unauthorized()

            if request.access_route[-1] in auth_ping_counter and auth_ping_counter[request.access_route[-1]]['fail_count'] < os.getenv('MAX_AUTH_ATTEMPTS'):
                now = datetime.now(tz=timezone.utc)
                auth_ping_counter[request.access_route[-1]]['fail_count']+=1
                auth_ping_counter[request.access_route[-1]]['timestamp']=now
                return Unauthorized()
                
        logger.info(f'Account credentials verified for {username}')
        # Assign session ID for authenticated account
        session_id = util_obj.gen_id()    
        client_auth.login_user(Client(auth_id=session_id, action=Action.WRITE))
        sub_dict.pop('pwd')
        auth_token = client_auth.dump_token(auth_id=session_id, app=app)
        sub_dict['auth_token'] = bcrypt.hashpw(password=auth_token, salt=bcrypt.gensalt())
        if await cl_sess_db.upload_db_data(id=session_id, data=sub_dict) > 0:
            return jsonify({'token': auth_token})

@app.route(f'{main_url}/logout/<string:auth_id>', methods=['GET'])
@user_login_required
async def logout(auth_id):
    if await cl_sess_db.get_all_data(match=f'{auth_id}', cnfrm=True) is False:
            await ip_blocker()
            return Unauthorized()
        
    if await cl_sess_db.del_obj(key=auth_id) is not None:
        client_auth.logout_user()
        return jsonify(), 200
    
@app.route(f'{probe_url}/data', methods=['POST'])
@user_login_required
async def prbdata():
    data = await request.get_json()
    if not data:
        await ip_blocker(conn_obj=request)
        abort(401)
    probes=None
    if data['pattern']:
        probes = await cl_data_db.json_obj_mgr(task='g', pattern=data['pattern'])
    else:
        probes = await cl_data_db.json_obj_mgr(task='g')
    return jsonify(probes), 200
 
@app.route(f'{probe_url}/init', methods=['GET'])
async def prbinit():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        abort(401)
    api_data_dict = await jwt_verification(request=request, api_key=api_key)
    api_jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
    api_rand = api_data_dict.get(f'{api_name}_rand')
    api_id = api_data_dict.get(f'{api_name}_id')
    jwt_token = util_obj.generate_ephemeral_token(id=api_id, secret_key=api_jwt_key, rand=api_rand, type='prb')
    response = Response(response='Probe Token Success', status=200)  
    response.set_cookie(
            key='access_token',
            value=jwt_token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=3600  # 1 hour, adjust as needed
        )
    return response
  
@app.route(f'{probe_url}/enroll', methods=['POST'])
async def prbenroll():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    site = request.args.get('site')
    if not api_key:
        await ip_blocker(conn_obj=request)
        abort(401)
    if not site:
        site = 'default'
    await jwt_verification(request=request, api_key=api_key)
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
    if await cl_data_db.json_obj_mgr(task='s', new_data=adopted_probe_data, data_name=adopted_probe_data['prb_id']) is not None:
        return jsonify(), 200
    else:
        return jsonify(), 400
    
@app.route(f'{probe_url}/delete', methods=['POST'])
@user_login_required
async def prbdelete():
    data = await request.get_json() 
    id = data['id']
    result = await cl_data_db.del_obj(key=id)
    if result is None:
        return jsonify(), 400
    return jsonify(), 200

@app.route(f'{probe_url}/ingest', methods=['POST'])
async def prbingest():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    await jwt_verification(request=request, api_key=api_key)
    data = await request.get_json()
    if data is None:
        return jsonify(), 400
    payload = {
        'documents': data['documents'],       
    }
    ingest_resp, _ = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/ingest/batch", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

    if ingest_resp == 200:
        return jsonify(), 200
    else:
        return jsonify(), 400

@app.route(f'{probe_url}/analysis', methods=['POST'])
async def prbanalysis():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    if not api_key:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(request=request, api_key=api_key)
    data = await request.get_json()
    if data is None:
        return jsonify(), 400

    anlys_payload = {
        'content': data['content'],
        'metadata': data['metadata'],
        'available_tools': data['tool_instructions'],
        'detect_type': 1,
        'prompt': data['prompt']
    }
    anlys_status, anlys_resp = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/analyze/batch", data=anlys_payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))  
    
    if anlys_status == 200:
        prim_contact = await cl_auth_db.get_all_data(match='*pct:*')
        prim_contact_dict = next(iter(prim_contact.values()))
        html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                                                    <p>Hello,</p>
                                                    <p>{os.getenv('JINIBOT_NAME')}'s {data['flow_name']} Analysis:</p>
                                                    <p>{anlys_resp}</p>
                    
                            
                                                    </div>"""
        email_params = {'sender': {'name': f'{os.getenv('JINIBOT_NAME')}', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                        'to': [{"name": f'{prim_contact_dict.get('fname')} {prim_contact_dict.get('lname')}', "email": prim_contact_dict.get('eml')}],
                                                        'subject': f"{os.getenv('JINIBOT_NAME')} {data['flow_name']} Analysis Report",
                                                        'hmtl_content': html_snippet }
                    
        email_command = f"python3 {email_script_path} -t 'send' -p {email_params}"
        email_code, email_output, email_error = await util_obj.run_shell_cmd(cmd=email_command)
        if email_code == 0:
                                logger.info(f'Flow {data['flow_name']} complete')
                                return
        return jsonify(), 200

@app.route(f'{main_url}/flows', defaults={'task': None}, methods=['POST'])            
@app.route(f'{main_url}/flows/<string:task>', methods=['POST'])
@user_login_required
async def flow(task):
    data = await request.get_json()
    if task is None or data is None:
        await ip_blocker(conn_obj=request)
        return jsonify(), 400
    
    match task:
        case 'load':
            if await cl_data_db.get_all_data(match=f'*{data['id']}*', cnfrm=True) is True:
                flow_data = await cl_data_db.get_all_data(match=f'*{data['id']}*')
                flow_data_dict = next(iter(flow_data.values()))
                return jsonify(flow_data_dict), 200
            else:
                return jsonify(), 400
        case 'save': 
            if data['id'] == 'default':
                data['id'] = f"flow:{data['name']}:{str(uuid.uuid4())}" 
            job1 = None
            now = datetime.now(tz=timezone.utc).isoformat()
            job_comment=f"auto_job_{data['name']}_{now}"
            task_command = ""
            script_path = os.path.join(cwd, 'utils', 'RemoteFlowRunner.py')
            task_command = f"python3 {script_path} -f {data['flow']} -n {data['name']}"
            job1 = await run_sync(lambda: cron.new(command=task_command, comment=job_comment))()
            scheduled_job = await run_sync(lambda: schedule_cronjob(job1, data['schedule']))()
            if await run_sync(scheduled_job.is_valid())():
                await run_sync(cron.write())()
                await asyncio.sleep(1)
                logger.info(f"Cron job added: {scheduled_job}")
                if await cl_data_db.upload_db_data(id=data['id'], data=data) > 0:
                    return jsonify(), 200
            else:
                return jsonify(), 400
        case 'all':
            all_flows = await cl_data_db.get_all_data(match=f'flow:*')
            parsed_flows = next(iter(all_flows.values()))
            return jsonify(parsed_flows), 200
        case _:
            pass

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
            api_name: bcrypt.hashpw(new_api_key, bcrypt.gensalt()),
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
                            'to': [{"name": f'{prim_contact_dict.get('fname')} {prim_contact_dict.get('lname')}', "email": prim_contact_dict.get('eml')}],
                            'subject': f"New Jini API Key Generated for {prim_contact_dict.get('email')}",
                            'hmtl_content': html_snippet }
            
            email_command = f"python3 {email_script_path} -t 'send' -p {email_params}"
            email_code, email_output, email_error = await util_obj.run_shell_cmd(cmd=email_command)
            return jsonify(), 200
        else:
            return jsonify(), 400
    else:
        return jsonify(), 400
    
@app.errorhandler(Unauthorized)
async def unauthorized():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401

@app.errorhandler(ExpiredSignatureError)
async def token_expired():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Token expired"})), 1008

@app.errorhandler(InvalidTokenError)
async def invalid_token():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Invalid token"})), 1000

@app.errorhandler(400)
async def bad_request():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Bad Request"})), 400

@app.errorhandler(401)
async def need_to_login():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401
    
@app.errorhandler(404)
async def page_not_found():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Resource not found"})), 404

@app.errorhandler(500)
async def handle_internal_error(e):
    return await render_template_string(json.dumps({"error": "Internal server error"})), 500