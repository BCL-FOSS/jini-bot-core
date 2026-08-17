from quart import (Request, Websocket, websocket, render_template_string)
import asyncio
from utils.broker import Broker
from quart import jsonify
from quart.utils import run_sync
import json
from init_app import app, logger, REQUIRED_OUT_OF_SCOPE_MSG, NET_ADMIN_INSTRUCTIONS, ANALYSIS_INSTRUCTIONS, cron, schedule_cronjob, cl_sess_db, cl_data_db, cl_auth_db, ip_ban_db, ws_rate_limiter, check_for_utils, cwd, load_network_diagnostic_prompt, util_obj, api_name, max_auth_attempts, cli, utility_scripts_path
from quart_rate_limiter import rate_exempt
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

broker = Broker()
bot_broker = Broker()
auth_ping_counter = {}
auth_attempts={}
connected_probes={}   
NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD = None 

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
                    if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand') or bcrypt.checkpw(api_key,api_data_dict.get(api_name)) is False:
                        await ip_blocker(conn_obj=request)
                        abort(401)
                else:
                    if bcrypt.checkpw(api_key, api_data_dict.get(api_name)) is False:
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
async def startup():
    await ip_ban_db.connect_db()
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()
    await check_for_utils()
    global NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD
    NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD = await run_sync(load_network_diagnostic_prompt())
    logger.info(f"Network diagnostic system prompt loaded successfully.\n {NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD[:500]}...")
    
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

@app.route('/v1/api/core/probes/ingest', methods=['POST'])
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

@app.route("/v1/api/core/probes/analysis", methods=['POST'])
async def prbanalysis():
    api_key = request.headers.get(os.getenv('API_KEY_HEADER_NAME'))
    jwt_token = request.cookies.get('access_token')
    if not api_key or not jwt_token:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(jwt_token=jwt_token, request=request, api_key=api_key, type='prb')
    data = await request.get_json()
    if data is None:
        return jsonify(), 400
    analysis_prompt = data['prompt']
    analysis_instructions = (
        NET_ADMIN_INSTRUCTIONS
        + "\n\n"
        + ANALYSIS_INSTRUCTIONS
        + "\n\n"
        + NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD
        )
                        
    payload = {
        'model': os.getenv('OLLAMA_MODEL'),
        'message': f"{analysis_prompt}",
        'name': f"{data['name']}",
        'instructions': analysis_instructions,
    }
    chat_resp, chat_resp_data = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/analysis", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

    if chat_resp == 200:
        alerts = str(data['notif_list']).split(',') if data.get('notif_list') else []
        for alert in alerts:
            match alert:
                case 'email':
                    email_contact = await cl_data_db.get_all_data(match='*pct:*')
                    email_contact_data = next(iter(email_contact.values()))
            
                    html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                                                        <p>Jini Monitor Analysis Complete</p>
                                                        <p>Probe ID: {data['prb_id']}</p>
                                                        <p>Prompt: {data['prompt']}</p>
                                                        <p>Response: {chat_resp_data}</p>
                                                        </div>"""
                    email_params = {'sender': {'name': 'jini bot', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                        'to': [{"name": f'{email_contact_data.get('fname')} {email_contact_data.get('lname')}', "email": email_contact_data.get('eml')}],
                                                        'subject': f'jini Bot Analysis Report - {data["prb_id"]} - {data['timestamp']}',
                                                        'html_content': html_snippet}
                    email_script_path = os.path.join(utility_scripts_path, f'EmailMgr.py')
                    email_command = f"python3 {email_script_path} -t 'send' -p {email_params}"
                    email_code, email_output, email_error = await util_obj.run_shell_cmd(cmd=email_command)
                    logger.info(f'code: {email_code}\noutput: {email_output}\nerror: {email_error}')
                case 'jira':
                    jira_script_path = os.path.join(utility_scripts_path, 'JiraMgr.py')
                    jira_params = {'message': chat_resp_data}
                    jira_command = f"python3 {jira_script_path} -t 'alert' -p {jira_params}"
                    jira_code, jira_output, jira_error = await util_obj.run_shell_cmd(cmd=jira_command)
                case 'slack':
                    slack_script_path = os.path.join(utility_scripts_path, 'SlackMgr.py')
                    slack_params = {}
                    slack_command = f"python3 {slack_script_path} -t 'alert' -p {slack_params}"
                    slack_code, slack_output, slack_error = await util_obj.run_shell_cmd(cmd=slack_command)
            
            anlys_id = f'anlys:{data["prb_id"]}:{data['timestamp']}:{str(uuid.uuid4())}'
            anlys_data = {'id': anlys_id,
                                          'data': html_snippet}
            
            if await cl_data_db.upload_db_data(id=anlys_id, data=anlys_data) > 0:
                logger.info(f'{data["prb_id"]} analysis complete')
                return jsonify(), 200
            else:
                logger.error(f'Error uploading analysis data for {data["prb_id"]}')
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

@app.route('/v1/api/core/flows', defaults={'task': None}, methods=['POST'])            
@app.route('/v1/api/core/flows/<string:task>', methods=['POST'])
@rate_exempt
async def flow(task):
    sess_id = request.args.get('sess_id')   
    jwt_token = request.cookies.get('access_token')
    if not jwt_token:
        await ip_blocker(conn_obj=request)
        abort(401)
    if await ws_rate_limiter.check_rate_limit(client_id=jwt_token) is False:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(sess_id=sess_id, jwt_token=jwt_token, request=request)
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
       
@app.route('/v1/api/core/reset', methods=['GET'])
@rate_exempt
async def reset():
    sess_id = request.args.get('sess_id')   
    jwt_token = request.cookies.get('access_token')
    if not jwt_token:
        await ip_blocker(conn_obj=request)
        abort(401)
    if await ws_rate_limiter.check_rate_limit(client_id=jwt_token) is False:
        await ip_blocker(conn_obj=request)
        abort(401)
    await jwt_verification(sess_id=sess_id, jwt_token=jwt_token, request=request)

    prim_contact = await cl_auth_db.get_all_data(match='*pct:*')
    prim_contact_dict = next(iter(prim_contact.values()))
    email_script_path = os.path.join(utility_scripts_path, f'EmailMgr.py')
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
            email_code, email_output, email_error = -await util_obj.run_shell_cmd(cmd=email_command)
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