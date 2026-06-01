from quart import (Request, Websocket, websocket, render_template_string)
import asyncio
from utils.broker import Broker
from quart import jsonify
from quart.utils import run_sync
import json
from init_app import app, logger
from quart_rate_limiter import rate_exempt
import os
from ai.utils.RedisDB import RedisDB
from quart import (websocket, abort, jsonify)
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from utils.WSRateLimiter import WSRateLimiter
from ai.utils.Util import Util
from quart import request, jsonify, request, Response
from passlib.hash import bcrypt
from quart_auth import Unauthorized
from datetime import datetime, timedelta, timezone
import uuid

cl_sess_db = RedisDB(hostname=os.getenv('CLIENT_SESS_DB'), 
                    port=os.getenv('CLIENT_SESS_DB_PORT'))
cl_auth_db = RedisDB(hostname=os.getenv('CLIENT_AUTH_DB'), 
                    port=os.getenv('CLIENT_AUTH_DB_PORT'))
cl_data_db = RedisDB(hostname=os.getenv('CLIENT_DATA_DB'),
                    port=os.getenv('CLIENT_DATA_DB_PORT'))
ip_ban_db = RedisDB(hostname=os.getenv('IP_BAN_DB'), 
                    port=os.getenv('IP_BAN_DB_PORT'))
ws_rate_limiter = WSRateLimiter(redis_host=os.getenv('RATE_LIMIT_DB'), 
                                redis_port=os.getenv('RATE_LIMIT_DB_PORT'))
broker = Broker()
bot_broker = Broker()
util_obj=Util()
api_name = os.getenv('API_NAME')
auth_ping_counter = {}
mntr_url=os.getenv('SERVER_NAME')
auth_attempts={}
max_auth_attempts=int(os.getenv('MAX_AUTH_ATTEMPTS'))
connected_probes={}

# LLM System prompts
REQUIRED_OUT_OF_SCOPE_MSG = "Please provide a question or request related to network administration or the available MCP tools."
NET_ADMIN_INSTRUCTIONS = (
                            "You are a Network Admin assistant with knowledge of "
                            "network engineering, network administration, firewall configurations, and securing networks according to "
                            "NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards. "
                            "You have access to MCP servers with tools that execute common network administration functions. "
                            "Always use the provided tools when applicable.\n"
                            "IMPORTANT: Only answer questions that are related to the tools below or your network administration expertise. "
                            "If a user asks something unrelated to the provided tools or prompt, DO NOT answer the question. "
                            f"Instead, only reply with: '{REQUIRED_OUT_OF_SCOPE_MSG}.'. Do not give any other type of reply.\n"
                            "If you are asked about your architecture, provider, or model identity, only respond with: "
                            f"'I am a locally hosted, open source {str(os.getenv('OLLAMA_MODEL'))} model running on ollama.'\n\n"
                        )                    
ANALYSIS_INSTRUCTIONS = (
    "Your primary task is to analyze the outputs of traceroutes, iperf speedtests, nmap network scans, SNMP statistics and network packet captures from tcpdump and tshark (cli version of wireshark) to identify, diagnose, troubleshoot and resolve network performance issues, outages and anomalies within current and historical network data. You will provide suggestions for network performance improvements only based on the specifications provided from the user prompt. If you are asked just to conduct an analysis always put 'SmartBot-Analysis:' before your response. If you are asked to remediate any issues found dring your analysis, use any of the applicable tools provided by the MCP servers. If the available tools are insufficient to perform remediation, reply with a detailed report of your findings, the steps you'd take to resolve any issues identified and what exact tools (command line network utilities, firewall/switch configurations etc.) and exact network command line tool commands you would use during the remediation process. Put 'SmartBot-Remediation: ' before your response. If you are asked to analyze if specific data within the network commandline utilities outputs meet certain criteria or KPI metrics specified by the user, put 'SmartBot-Alert:' before your response.\n"
                                )

def load_network_diagnostic_prompt() -> str:
    try:
        #base_dir = os.path.dirname(os.path.abspath(__file__))  # backend/
        base_dir = os.getcwd()
        prompt_path = os.path.join(base_dir, "ai", "smartbot", "skills", "network-diagnostic-system-prompt.md")
        logger.info(f"Loading network diagnostic system prompt from: {prompt_path}")
        with open(prompt_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.exception(f"Failed to load network diagnostic system prompt: {e}")
        return ""

NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD = load_network_diagnostic_prompt()

logger.info(f"Network diagnostic system prompt loaded successfully.\n {NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD[:500]}...")

async def ip_blocker(conn_obj: Request | Websocket, auto_ban: bool = False, check_if_allowed: bool = False):
    global auth_attempts
    if check_if_allowed is True:
        if await ip_ban_db.get_all_data(match=f"allowed_ip:{conn_obj.access_route[-1]}", cnfrm=True) is False:
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
    
async def jwt_verification(request: Request | Websocket, type: str = 'usr', api_key: str = None, sess_id: str = None, jwt_token: str = None):
    try:
        match type:
            case 'prb':
                api_data = await cl_data_db.get_all_data(match=f"{api_name}:dta:*")
                if api_data is None:
                    await ip_blocker(conn_obj=request)
                    abort(401)
                api_data_dict = next(iter(api_data.values()))
                if jwt_token:
                    jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
                    decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
                    if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand') or bcrypt.verify(api_key,api_data_dict.get(api_name)) is False:
                        await ip_blocker(conn_obj=request)
                        abort(401)
                else:
                    if bcrypt.verify(api_key, api_data_dict.get(api_name)) is False:
                        await ip_blocker(conn_obj=request)
                        abort(401)
                return api_data_dict
            case 'usr':
                if await cl_sess_db.get_all_data(match=f'*{sess_id}*', cnfrm=True) is False:
                    await ip_blocker(conn_obj=request)
                    abort(401)
                usr_sess_data = await cl_sess_db.get_all_data(match=f'*{sess_id}*')
                usr_data_dict = next(iter(usr_sess_data.values()))
                jwt_key = usr_data_dict.get(f'usr_jwt_secret')
                decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
                if decoded_token.get('rand') != usr_data_dict.get(f'usr_rand'):
                    await ip_blocker(conn_obj=request)
                    abort(401)
                return usr_data_dict
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
        
async def _receive_telegram_bot() -> None:
    while True:
        message = await websocket.receive()
        logger.debug(message)
        message = json.loads(message)
        is_authorized = await util_obj.check_id(message.get('telegram_id'))

        if is_authorized is False:
            logger.warning(f"Unauthorized Telegram ID {message.get('telegram_id')} attempted to connect to bot websocket.")
            return

        action=message['act']
        if action:
            match action:
                case 'query':
                    payload = {
                        "query": message['prompt'],
                        "n_results": 5,
                        "filter": {"tool_type": message['tool_filter'] if message['tool_filter'] else "all"},
                        "prb_id": message['prb_id'] if message['prb_id'] else None
                    }
                    status, response = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/query", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

                case 'exec':
                    final_output = ""
                    prompt, prb_id = await run_sync(lambda: util_obj.split_text_by_keyword(str(message["prompt"]).lower(), keyword="prb_id:", cnfrm=True))()

                    if prb_id is None:
                        await bot_broker.publish(message="Probe ID not specified. Please specify the probe ID by including 'prb_id:<ID>' at the end of your request.")

                    if await cl_data_db.get_all_data(match=f'*{prb_id}*', cnfrm=True) is True:
                        selected_probe = await cl_data_db.get_all_data(match=f'*{prb_id}*')
                        selected_probe_dict = next(iter(selected_probe.values()))

                        agent_msg_data = {}
                        
                        api = selected_probe_dict.get('prb_api_key')

                        tool_request, analysis_request = await run_sync(lambda: util_obj.split_text_by_keyword(prompt, keyword="analysis:"))()

                        logger.info(f'Tool request: {tool_request}, Analysis request: {analysis_request}')
                        saved_tools_instructions = ""

                        if connected_probes.get(prb_id)['tool_instructions'] is not None:
                            saved_tools_instructions = connected_probes.get(prb_id).get('tool_instructions')

                        payload = {
                                'model': os.getenv('OLLAMA_MODEL'),
                                'tools':[
                                        {
                                            "type": "mcp",
                                            "server_label": "netadmin_mcp_server",
                                            "server_url": str(selected_probe_dict.get('url')),
                                            "require_approval": "never",
                                        },
                                    ],
                                'usr_input':f"{tool_request}",
                                'instructions': NET_ADMIN_INSTRUCTIONS,
                                'api_key': api,
                                'chat_id': message['telegram_id'],
                            }
                        
                        status, tool_resp = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/chat", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

                        if status is True:
                            if saved_tools_instructions == "":
                                connected_probes.get(prb_id)['tool_instructions'] = tool_resp['tool_instructions']

                            if tool_resp['output_text'] == REQUIRED_OUT_OF_SCOPE_MSG:
                                err_msg_data = {
                                    "from": "agent",
                                    "msg": REQUIRED_OUT_OF_SCOPE_MSG,
                                    "url": selected_probe_dict.get('url'),
                                    "usr_id": message['usr_id']
                                }
                                await bot_broker.publish(message=json.dumps(err_msg_data))
                            else:
                                output_message = ""
                                logger.info(f"Request result: {tool_resp['output_text']}\n")
                                logger.info(type(tool_resp['output_text']))

                                data = json.loads(tool_resp['output_text'])

                                for item in data:
                                    net_cmd_output = item['output'][1]
                                    logger.info(f"Net command output: {net_cmd_output}")
                                    decoded_output = net_cmd_output.encode('utf-8').decode('unicode_escape')
                                    lines = decoded_output.split('\n')

                                    for i, line in enumerate(lines):
                                        net_cmd_data = f'{line}\n'
                                        output_message+=net_cmd_data

                                if analysis_request != "":
                                    analysis_msg = (
                                        f"{output_message}"
                                        + "\n\n"
                                        f"{analysis_request}"
                                        )
                                    
                                    analysis_instructions = (
                                        NET_ADMIN_INSTRUCTIONS
                                        + "\n\n"
                                        + ANALYSIS_INSTRUCTIONS
                                        + "\n\n"
                                        + NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD
                                    )

                                    payload['usr_input'] = analysis_msg
                                    payload['instructions'] = analysis_instructions
                                    analysis_payload = payload.copy()
                                    if connected_probes.get(prb_id).get('tool_instructions') != "":
                                        analysis_payload['tool_instructions'] = connected_probes.get(prb_id).get('tool_instructions')

                                    analysis_status, analysis_resp = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/chat", data=analysis_payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))   

                                    if analysis_status is True:
                                        final_output+=f'{output_message}\n\n'
                                        final_output+=analysis_resp['output_text']
                                        logger.info(final_output)
                                        agent_msg_data['query_type'] = 'tool_analysis'
                                else:
                                    final_output = output_message
                                    agent_msg_data['query_type'] = 'tool'      
                                    
                                time_stamp = datetime.now(timezone.utc).isoformat()
                                chat_data_id = f"chat:{prb_id}:{message['telegram_id']}:{time_stamp}"
                                chat_data = {'id': chat_data_id,
                                            'usr_msg': message["msg"],
                                            'agent_msg': final_output,
                                            'prb_id': prb_id,
                                            'timestamp': time_stamp,
                                            'type': agent_msg_data['query_type'],
                                            'tool_calls': tool_resp['tool_calls'],
                                            'tool_outputs': tool_resp['tool_outputs'],
                                            }
                                if await cl_data_db.upload_db_data(id=chat_data_id, data=chat_data) > 0:
                                    logger.info(f"Chat data uploaded successfully with id: {chat_data_id}")
                                
                                await bot_broker.publish(message=final_output)

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
                    global connected_probes
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
                case "tsk":  
                    logger.info(f"Received probe task confirmation message: {message}.")
                    match message.get('storage_opt'):
                        case 'new':
                            message['timestamp'] = datetime.now(tz=timezone.utc).isoformat()
                            task_id = f"task:obj:{message['job_type']}:{message['prb_id']}:{message['timestamp']}"
                            message['id'] = task_id
                            if await cl_data_db.upload_db_data(id=task_id, data=message) > 0:
                                logger.info(f"Task data uploaded successfully with id: {task_id}")
                        case 'updt':
                            if await cl_data_db.upload_db_data(id=message['id'], data=message) > 0:
                                logger.info(f"Task data updated successfully with id: {message['id']}")
                        case 'del':
                            result = await cl_data_db.del_obj(key=message['id'])
                            if result is not None:
                                logger.info(f"Task data deleted successfully with id: {message['id']}")
                    message.pop('act')
                    message.pop('storage_opt')
                    message['alert_type'] = 'task_config_confirmation'
                    message['msg'] = f"Task '{message['job_type']}' was configured at probe '{message['prb_id']}' with output: {message['task_output']}"

                    await broker.publish(message=json.dumps(message))
                case "smtbt":
                    if isinstance(message, list):
                        payload = {'documents': message}
                    else:
                        payload = message 
                    status, ingested_data = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/process", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

                    if status is True: 
                        if await cl_data_db.upload_db_data(id=ingested_data.get('db_id'), data=ingested_data.get('data')) > 0:
                            logger.info(f"SmartBot message data uploaded successfully with id: {ingested_data.get('db_id')}")

                        logger.info("SmartBot message ingested successfully.")

                        #await broker.publish(message=json.dumps(ingested_data.get('data')))
                        await connected_probes[message['prb_id']]['broker'].publish(message=json.dumps(ingested_data.get('data')))

                case _:
                    pass
        else:
            pass

async def _receive_user() -> None:
    while True:
        message = await websocket.receive()
        logger.debug(message)
        message = json.loads(message)
        await broker.publish(message=json.dumps(message))

async def session_watchdog(sess_id: str, check_interval: float = 5.0):
    logger.info(f"Starting session watchdog for {sess_id}")
    while True:
        try:
            PROBE = False
            if connected_probes.get(sess_id):
                entry = connected_probes.get(sess_id)
                PROBE = True

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

            if PROBE is True:
                now_quant = util_obj.round_down_to_30sec(now)
                exp_quant = util_obj.round_up_to_30sec(exp)

            #logger.debug(f"Session {sess_id} now_quant={now_quant} exp_quant={exp_quant} (raw now={now} raw exp={exp})")

            # Expiration occurred
            if now_quant > exp_quant:
                logger.info(f"Session {sess_id} expired at {exp_quant} (now_quant={now_quant}), logging out and closing ws")
                    
                if PROBE is True:
                    logger.info(f'Probe {sess_id} is either offline or a network outage has occurred.')
                    connected_probes.pop(sess_id)
                    probe_data = await cl_data_db.get_all_data(match=f"*{sess_id}*")
                    probe_data_dict = next(iter(probe_data.values()))

                    await cl_data_db.connect_db()

                    await cl_data_db.upload_db_data(id=probe_data_dict.get('db_id'), data={'status': 'offline',
                                                                                          'badge': 'danger',
                                                                                          'last_online': now.isoformat()})

                    probe_outage_data = {'alert_type': 'outage',
                                            'site': probe_data_dict.get('site'),
                                            'name': probe_data_dict.get('name'),
                                            'prb_id': sess_id,
                                            'status': 'offline',
                                            'timestamp': now.isoformat()}
                    
                    alert_id = f"alert:{sess_id}:{probe_outage_data['alert_type']}:{now.isoformat()}"

                    probe_outage_data['id'] = alert_id
                    
                    if await cl_data_db.upload_db_data(id=alert_id, data=probe_outage_data) > 0:
                        logger.info(f"Probe outage alert data uploaded successfully with id: {alert_id}")

                    await broker.publish(message=json.dumps(probe_outage_data))
                    return None

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
async def db_startup():
    await ip_ban_db.connect_db()
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

@app.before_request
async def check_ip():
    if await ip_ban_db.get_all_data(match=f"blocked_ip:{request.access_route[-1]}", cnfrm=True) is True:
        abort(401)

@app.before_websocket
async def check_ip_ws():
    if await ip_ban_db.get_all_data(match=f"blocked_ip:{websocket.access_route[-1]}", cnfrm=True) is True:
        try:
            await websocket.close()
        except RuntimeError:
            return None

@app.websocket("/v1/api/core/bot/ws")
@rate_exempt
async def bot_ws():
    try:
        await websocket.accept()
        asyncio.ensure_future(_receive_telegram_bot())
        async for message in bot_broker.subscribe():
            await websocket.send(message)
    except Exception as e:
        logger.error(f"Error in bot_ws: {e}")
    except asyncio.CancelledError:
        logger.info("bot_ws cancelled")

@app.websocket("/v1/api/core/channels/probe/heartbeat/<string:probe_id>")
@rate_exempt
async def heartbeat(probe_id):
    global connected_probes
    
    try:
        if probe_id is None or isinstance(probe_id, str) is False or probe_id.strip() == "":
            await ip_blocker(conn_obj=websocket, auto_ban=True)
            await websocket.close()

        usr_sess_id = websocket.args.get('sess_id') if websocket.args.get('sess_id') is not None else None

        if usr_sess_id is not None and usr_sess_id not in auth_ping_counter:
            await ip_blocker(conn_obj=websocket, auto_ban=True)
            await websocket.close()

        if await cl_data_db.get_all_data(match=f"*{probe_id}*", cnfrm=True) is False:
            await ip_blocker(conn_obj=websocket, auto_ban=True)
            await websocket.close()

        if await ws_rate_limiter.check_rate_limit(client_id=probe_id) is False:
            await ip_blocker(conn_obj=websocket)
            await websocket.close()

        monitor_task = None
        if probe_id and (probe_id not in connected_probes):
            if usr_sess_id is not None:
                await websocket.close()
            now = datetime.now(tz=timezone.utc)
            connected_probes[probe_id] = {'conn_start': now,
                                        'id': probe_id,
                                        "exp": util_obj.round_up_to_30sec(now + timedelta(seconds=30)),
                                        "broker" : Broker(),
                                        }
            logger.debug(f"Initialized ping expiry for session {probe_id} -> {connected_probes[probe_id]['exp']}")
            asyncio.ensure_future(_receive_probe())
            monitor_task = asyncio.create_task(session_watchdog(sess_id=probe_id))
            current_probe_data = await cl_data_db.get_all_data(match=f"*{probe_id}*")
            current_probe_data_dict = next(iter(current_probe_data.values()))
            online_status = {'status': 'online',
                             'badge': 'success',
                             'last_online': now.isoformat()}
            await cl_data_db.upload_db_data(id=current_probe_data_dict.get('db_id'), data=online_status)

        if probe_id and (probe_id in connected_probes):
            if usr_sess_id is not None:
                asyncio.ensure_future(_receive_probe())
            else:
                asyncio.ensure_future(_receive_probe())
                monitor_task = asyncio.create_task(session_watchdog(sess_id=probe_id))
        await websocket.accept()

        try:
            async for message in  connected_probes[probe_id]['broker'].subscribe():
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
    
@app.websocket("/v1/api/core/channels/users/ws")
@rate_exempt
async def ws():
    global auth_ping_counter    
    try:
        if websocket.cookies.get("access_token") is not None:
            id = None
            if websocket.args.get('id') is not None:
                id = websocket.args.get('id')
            jwt_token = websocket.cookies.get("access_token")
            if await ws_rate_limiter.check_rate_limit(client_id=jwt_token) is False:
                await ip_blocker(conn_obj=websocket)
                abort(401)
            if id is not None:
                await jwt_verification(sess_id=id, jwt_token=jwt_token, request=websocket, type='usr')           
            logger.info(f'websocket authentication successful for session {id}')
            await websocket.accept()
            if id and (id not in auth_ping_counter):
                now = datetime.now(tz=timezone.utc)
                auth_ping_counter[id] = {
                    "sess_id": id,
                    "sign_in_time": now
                }
                logger.debug(f"user session {id} -> signed in at {auth_ping_counter[id]['sign_in_time ']}") 
                asyncio.ensure_future(_receive_user())
            if id and (id in auth_ping_counter):
                asyncio.ensure_future(_receive_user())
            try:
                async for message in broker.subscribe():
                    await websocket.send(message)
            except asyncio.CancelledError:
                logger.debug("Subscribe loop cancelled (client disconnected)")
                pass
            except Exception as e:
                logger.exception("Error while reading from broker or sending websocket message")
                pass
        else:
           await ip_blocker(conn_obj=websocket)
           abort(401)
    except Exception as e:
        logger.error(e)
    except asyncio.CancelledError as e:
        logger.error(e)
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=websocket)
        logger.error(ExpiredSignatureError)
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=websocket)
        logger.error(InvalidTokenError)
    finally:
        if id and id in auth_ping_counter:
            auth_ping_counter.pop(id)
            logger.debug(f"Session {id} removed from auth ping counter on disconnect")

@app.route('/v1/api/core/probe/init', methods=['GET'])
async def prbinit():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    try:
        if not api_key:
            await ip_blocker(conn_obj=request)
            abort(401)
        api_data_dict = await jwt_verification(request=request, type='prb', api_key=api_key)
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
    except Exception():
        return jsonify({'error': 'Error occurred'}), 400
    
@app.route("/v1/api/core/probe/enroll", methods=['POST'])
async def prbenroll():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    site = request.args.get('site')
    jwt_token = request.cookies.get('access_token')
    if not api_key or not jwt_token:
        await ip_blocker(conn_obj=request)
        abort(401)
    if not site:
        site = 'default'
    await jwt_verification(jwt_token=jwt_token, request=request, api_key=api_key, type='prb')
    adopted_probe_data = await request.get_json()
    adopted_probe_data['db_id'] = f"prb:{adopted_probe_data['site']}:{str(uuid.uuid4())}:{adopted_probe_data['prb_id']}"
    if await cl_data_db.upload_db_data(id=adopted_probe_data['db_id'], data=adopted_probe_data) > 0:
        return jsonify(), 200
    else:
        return jsonify(), 400
    
@app.route('/v1/api/core/probes/exec/<string:prb_id>/<string:tool>/<string:command>', methods=['POST'])
@rate_exempt
async def prbexec(prb_id, tool, command):
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    jwt_token = request.cookies.get('access_token')
    if not jwt_token:
        await ip_blocker(conn_obj=request)
        abort(401)
    if await ws_rate_limiter.check_rate_limit(client_id=jwt_token) is False:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(jwt_token=jwt_token, request=request, api_key=api_key, type='prb')
    data = await request.get_json()
    if not data['prb_id'] or await cl_data_db.get_all_data(match=f"*{prb_id}*", cnfrm=True) is False:
        await ip_blocker(conn_obj=request)
        abort(401)
    prb_data = await cl_data_db.get_all_data(match=f"*{prb_id}*")
    prb_data_dict = next(iter(prb_data.values()))
    headers = {'content-type': 'application/json',
                   'x-api-key': prb_data_dict.get('prb_api_key')
                   }
    url = f"{prb_data_dict.get('url')}/v1/api/{tool}/{command}"
    return jsonify(), 500 if await util_obj.make_http_request(headers=headers, url=url, data=data, timeout=int(os.getenv('REQUEST_TIMEOUT'))) is False else 200
    
@app.route('/v1/api/core/probes/delete', methods=['POST'])
async def prbdelete():
    jwt_token = request.cookies.get("access_token")
    sess_id = request.args.get('sess_id')   
    if not jwt_token or not sess_id:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(sess_id=sess_id, jwt_token=jwt_token, request=request)
    data = await request.get_json() 
    id = data['id']
    result = await cl_data_db.del_obj(key=id)
    if result is None:
        return jsonify(), 400
    return jsonify(), 200

@app.route('/v1/api/core/probes/ingest', methods=['GET', 'POST'])
async def prbingest():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    jwt_token = request.cookies.get("access_token")
    if not jwt_token:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(jwt_token=jwt_token, request=request, api_key=api_key, type='prb')
    data = await request.get_json()
    if data is None:
        return jsonify(), 400
    if await cl_data_db.upload_db_data(id=data['db_id'], data=data) > 0:
        return jsonify(), 200
    else:
        return jsonify(), 400

@app.route('/v1/api/core/user/alerts', methods=['POST'])
async def alerts():
    jwt_token = request.cookies.get("access_token")
    sess_id = request.args.get('sess_id')   
    if not jwt_token or not sess_id:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(sess_id=sess_id, jwt_token=jwt_token, request=request)
    data = await request.get_json()
    match data['action']:
        case 'ack':
            if await cl_data_db.upload_db_data(id=data['id'], data={'ack': 'seen'}) > 0:
                return jsonify(), 200
            else:
                return jsonify(), 400
        case 'rslv':
            if await cl_data_db.upload_db_data(id=data['id'], data={'rslv': 'resolved'}) > 0:
                return jsonify(), 200
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