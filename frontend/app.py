import uuid

from init_app import (app, client_auth, current_client, logger,
                      Client
                      )
from forms.LoginForm import LoginForm
from forms.TelegramForm import TelegramForm
from forms.APIForm import APIForm
from quart import (render_template_string, render_template, flash, redirect, url_for, session, request, abort)
from quart_wtf.csrf import CSRFError
from quart_auth import (
    Action
)
from quart_auth import Unauthorized
from functools import wraps
from utils.Util import Util
from utils.RedisDB import RedisDB
import json
import os
from passlib.hash import bcrypt
import secrets
import jwt
from datetime import datetime, timezone

util_obj = Util()
url_key = util_obj.key_gen(size=100)
url_cmp_id = util_obj.key_gen(size=100)
cl_auth_db = RedisDB(hostname=os.getenv('CLIENT_AUTH_DB'), 
                     port=os.getenv('CLIENT_AUTH_DB_PORT'))
cl_sess_db = RedisDB(hostname=os.getenv('CLIENT_SESS_DB'), 
                     port=os.getenv('CLIENT_SESS_DB_PORT'))
cl_data_db = RedisDB(hostname=os.getenv('CLIENT_DATA_DB'), 
                     port=os.getenv('CLIENT_DATA_DB_PORT'))
ip_ban_db = RedisDB(hostname=os.getenv('IP_BAN_DB'), 
                    port=os.getenv('IP_BAN_DB_PORT'))
mntr_url=os.getenv('SERVER_NAME')
api_name = os.getenv('API_NAME', 'umj-api-wflw')
max_auth_attempts=int(os.getenv('MAX_AUTH_ATTEMPTS'))
auth_attempts={}
reg_attempts={}

async def retrieve_user_sess_data(sess_id):
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{sess_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)
    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml'),
            'sess_id': sess_id}
    ws_url = f"wss://{mntr_url}/v1/api/core/channels/users/ws?id={sess_id}&unm={cl_sess_data_dict.get('unm')}"
    return data, ws_url

async def retrieve_task_results(prb_id, task):
    task_results = await cl_data_db.get_all_data(match=f"task:result:{prb_id}:{task}*")
    return task_results if task_results is not None else {"":""}

async def ip_blocker(auto_ban: bool = False):
    if auto_ban is True:
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': request.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {request.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(request.access_route[-1], None)
            abort(403) 

    if request.access_route[-1] not in auth_attempts:
        auth_attempts[request.access_route[-1]] = 1

    if auth_attempts[request.access_route[-1]] != max_auth_attempts:
        auth_attempts[request.access_route[-1]] += 1
    else:
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': request.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {request.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(request.access_route[-1], None)
            abort(403) 

def user_login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        auth_id = current_client.auth_id
        jwt_token = request.cookies.get("access_token")

        if auth_id is None or auth_id.strip() == "" or await cl_sess_db.get_all_data(match=f"{auth_id}", cnfrm=True) is False or jwt_token is None or jwt_token.strip() == "":
            await ip_blocker()
            return Unauthorized()
        
        logger.info(f"JWT Token from cookie: {jwt_token}")
        account_data = await cl_sess_db.get_all_data(match=f'*{auth_id}*')
        if account_data is not None:          
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)

            jwt_key = sub_dict.get('usr_jwt_secret')
            logger.info(jwt_key)
            try:
                decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
            except jwt.InvalidTokenError:
                await ip_blocker()
                return Unauthorized()
            except jwt.ExpiredSignatureError:
                await ip_blocker()
                return Unauthorized()
            except jwt.DecodeError:
                await ip_blocker()
                return Unauthorized()
            logger.info(decoded_token)

            if decoded_token.get('rand') != sub_dict.get('usr_rand'):
                await ip_blocker()
                return Unauthorized()
                    
            return await app.ensure_async(func)(*args, **kwargs)
    return wrapper

@app.before_serving
async def startup_tasks():
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()
    await ip_ban_db.connect_db()

@app.before_request
async def check_ip():
    await ip_ban_db.connect_db()
    logger.info(f"Checking if IP {request.access_route[-1]} is banned.")

    if await ip_ban_db.get_all_data(match=f"blocked_ip:{request.access_route[-1]}", cnfrm=True) is True:
        abort(403)

@app.route('/', methods=['GET', 'POST'])
async def index():
    try:
        logger.info(request.access_route)
        session["csrf_ready"] = True
        form = await LoginForm.create_form()

        if await form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            username = username.replace(" ", "").lower()
            
            await cl_auth_db.connect_db()
            await cl_sess_db.connect_db()
            await cl_data_db.connect_db()

            if await cl_auth_db.get_all_data(match=f'*uid:{username}*', cnfrm=True) is False:
                await flash(message='Create an account...', category='danger')
                return redirect(url_for('index'))

            account_data = await cl_auth_db.get_all_data(match=f'*uid:{username}*')
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)
            password_hash = sub_dict.get('pwd')
                
            if account_data and bcrypt.verify(password, password_hash) is False:
                await ip_blocker()
                return Unauthorized()
            
            logger.info(f'Account credentials verified for {username}')
            # Assign session ID for authenticated account
            session_id = util_obj.gen_id()

            # Client sign in and account sess. data -> sess-redis
            client_auth.login_user(Client(auth_id=session_id, action=Action.WRITE))

            await cl_sess_db.connect_db()

            # Pop password to mitigate potential leaks from redis session storage
            sub_dict.pop('pwd')

            # Generate user JWT data
            usr_rand=secrets.token_urlsafe(500)
            usr_jwt_secret=secrets.token_urlsafe(500)

            # Add JWT data to user session profile for upload to session redis db
            sub_dict["usr_rand"] = usr_rand
            sub_dict["usr_jwt_secret"] = usr_jwt_secret
            sub_dict['show_alerts'] = 'y'
            logger.info(sub_dict)

            # Generate user JWT to authenticate socket connection
            usr_jwt_token = util_obj.generate_ephemeral_token(user_id=session_id, secret_key=usr_jwt_secret, user_rand=usr_rand)
                        
            if await cl_sess_db.upload_db_data(id=session_id, data=sub_dict) > 0:
                rndm_cmp_id=util_obj.key_gen(size=100)
                session['url_key'] = util_obj.key_gen(size=100)

                resp = redirect(url_for('smartbot', cmp_id=rndm_cmp_id, obsc=session.get('url_key')))

                resp.set_cookie(
                            "access_token",
                            usr_jwt_token,
                            httponly=True,
                            secure=True,      # require HTTPS/WSS
                            samesite="Strict",
                            max_age=None      # 1 hour: 3600
                        )

                if await cl_data_db.get_all_data(match=f"api_dta:{sub_dict.get('db_id')}*", cnfrm=True) is False:
                    logger.info("User JWT token set in cookie.")
                    await flash(message=f'Authentication successful for {sub_dict.get('unm')}!', category='success')
                    return resp
                           
                else:
                    api_data = await cl_data_db.get_all_data(match=f"api_dta:{sub_dict.get('db_id')}*")
                    api_data_sub_dict = next(iter(api_data.values()))

                    api_jwt_key = api_data_sub_dict.get(f'{api_name}_jwt_secret')
                    api_rand = api_data_sub_dict.get(f'{api_name}_rand')
                    api_id = api_data_sub_dict.get(f'{api_name}_id')
                        
                    jwt_token = util_obj.generate_ephemeral_token(user_id=api_id, secret_key=api_jwt_key, user_rand=api_rand)

                    resp.set_cookie(
                                "api_access_token",
                                jwt_token,
                                httponly=True,
                                secure=True,      # require HTTPS/WSS
                                samesite="Strict",
                                max_age=None      # 1 hour: 3600
                            )

                    logger.info("API JWT token set in cookie.")

                    await flash(message=f'Authentication successful for {sub_dict.get('unm')}!', category='success')
                    return resp

        return await render_template('index/index.html', form=form)
    except Exception as e:
        logger.error( json.dumps({
            'status': 'error',
            'message': str(e)
        }), exc_info=True)

        return redirect(url_for('index'))

@app.route('/logout/<string:auth_id>', methods=['GET'])
@user_login_required
async def logout(auth_id):
    try:
        cur_usr_id = auth_id

        if await cl_sess_db.get_all_data(match=f'{cur_usr_id}', cnfrm=True) is False:
            await ip_blocker()
            return Unauthorized()
        
        result = await cl_sess_db.del_obj(key=cur_usr_id)

        logger.info(result)

        resp = redirect(url_for("index"))
        resp.delete_cookie("access_token")
        resp.delete_cookie("api_access_token")

        client_auth.logout_user()

        await flash(message="You have been logged out.", category="info")
        return resp

    except Exception as e:
        logger.error(json.dumps({
            "status": "error",
            "message": str(e)
        }), exc_info=True)
        resp = redirect(url_for("index"))
        resp.delete_cookie("access_token")
        resp.delete_cookie("api_access_token")
        return resp

@app.route('/floweditor', defaults={'cmp_id': 'bcl','obsc': url_key, 'flow_id': 'default', 'prb_id': 'default'}, methods=['GET', 'POST'])
@app.route("/floweditor/<string:cmp_id>/<string:obsc>/<string:flow_id>/<string:prb_id>", methods=['GET', 'POST'])
@user_login_required
async def floweditor(cmp_id, obsc, flow_id, prb_id):
    cur_usr_id = current_client.auth_id
    session["csrf_ready"] = True
    user_data, ws_url = await retrieve_user_sess_data(sess_id=cur_usr_id)

    probe_data = await cl_data_db.get_all_data(match=f"prb:*")
    if probe_data is None:
        probe_data = {'':''}

    return await render_template("app/floweditor.html", obsc_key=session.get('url_key') ,
                                cmp_id=cmp_id, all_probes=probe_data, mntr_url=mntr_url, 
                                user=user_data.get('unm'), cur_usr=user_data.get('unm'), ws_url=ws_url, cur_usr_id_id=cur_usr_id, data=user_data, flow_id=flow_id, prb_id=prb_id, cur_usr_id=cur_usr_id)

@app.route('/probe', defaults={'cmp_id': 'bcl','obsc': url_key, 'prb_id': 'default'}, methods=['GET', 'POST'])
@app.route("/probe/<string:cmp_id>/<string:obsc>/<string:prb_id>", methods=['GET', 'POST'])
@user_login_required
async def probe(cmp_id, obsc, prb_id):
    cur_usr_id = current_client.auth_id
    session["csrf_ready"] = True
    user_data, ws_url = await retrieve_user_sess_data(sess_id=cur_usr_id)
    probe_data = None
    probe_data_dict = None
    ifaces = None
    flows = None
    all_tasks = None
    probe_url = ""

    if prb_id != "default":
        probe_data = await cl_data_db.get_all_data(match=f"*{prb_id}*")
        probe_data_dict = next(iter(probe_data.values()))
        ifaces = probe_data_dict.get('iface_list')
        flows = await cl_data_db.get_all_data(match=f"flow:{prb_id}:*")
        all_tasks = await cl_data_db.get_all_data(match=f"task:obj:{prb_id}:*")
        api_key = probe_data_dict.get('prb_api_key')
        probe_url = f"https://{probe_data_dict.get('url')}"
    else:
        probe_data_dict = {'':''}
        flows = {'':''}
        ifaces = []
        api_key = None
        probe_url = ""

    return await render_template("app/probe.html", obsc_key=session.get('url_key') ,
                                flows=flows, cmp_id=cmp_id, mntr_url=mntr_url, cur_usr=user_data.get('unm'), cur_usr_id=cur_usr_id, ws_url=ws_url, data=user_data, probe_id=prb_id, all_tasks=all_tasks, probe_data=probe_data_dict, ifaces=ifaces, api_key=api_key, probe_api_url=probe_url)

@app.route('/alerts', defaults={'cmp_id': 'bcl','obsc': url_key, 'prb_id': 'default', 'alert_type': 'default'}, methods=['GET', 'POST'])
@app.route("/alerts/<string:cmp_id>/<string:obsc>/<string:prb_id>/<string:alert_type>", methods=['GET', 'POST'])
@user_login_required
async def alerts(cmp_id, obsc, prb_id, alert_type):
    cur_usr_id = current_client.auth_id
    session["csrf_ready"] = True
    user_data, ws_url = await retrieve_user_sess_data(sess_id=cur_usr_id)

    if await cl_sess_db.get_all_data(match=f"alert:", cnfrm=True) is False:
        alerts = {'':''}
    elif prb_id != "default" and alert_type != "default":
        alerts = await cl_data_db.get_all_data(match=f"alert:{prb_id}:{alert_type}:*")
    elif prb_id != "default" and alert_type == "default":
        alerts = await cl_data_db.get_all_data(match=f"alert:{prb_id}:*")
    elif prb_id == "default" and alert_type != "default":
        alerts = await cl_data_db.get_all_data(match=f"alert:*:{alert_type}:*")
    else:         
        alerts = await cl_data_db.get_all_data(match=f"alert:*")

    return await render_template("app/alerts.html", obsc_key=session.get('url_key') ,
                                  cmp_id=cmp_id, ws_url=ws_url, cur_usr=user_data.get('unm'), data=user_data, cur_usr_id=cur_usr_id, alerts=alerts)

@app.route('/chats', defaults={'cmp_id': 'bcl','obsc': url_key, 'usr': 'default', 'prb_id': 'default'}, methods=['GET', 'POST'])
@app.route("/chats/<string:cmp_id>/<string:obsc>/<string:usr>/<string:prb_id>", methods=['GET', 'POST'])
@user_login_required
async def chats(cmp_id, obsc, usr, prb_id):
    cur_usr_id = current_client.auth_id
    session["csrf_ready"] = True
    user_data, ws_url = await retrieve_user_sess_data(sess_id=cur_usr_id)

    if usr != "default":
        chats = await cl_data_db.get_all_data(match=f"chat:{prb_id}:{usr}:*")
    else:
        chats = {'':''}

    return await render_template("app/chats.html", obsc_key=session.get('url_key') ,
                                  cmp_id=cmp_id, cur_usr_id=cur_usr_id, ws_url=ws_url, cur_usr=user_data.get('unm'), data=user_data, usr=usr, chats=chats)

@app.route('/dashboard', defaults={'cmp_id': 'bcl','obsc': url_key, 'prb_id': 'default'}, methods=['GET', 'POST'])
@app.route("/dashboard/<string:cmp_id>/<string:obsc>/<string:prb_id>", methods=['GET', 'POST'])
@user_login_required
async def dashboard(cmp_id, obsc, prb_id):
    cur_usr_id = current_client.auth_id
    session["csrf_ready"] = True
    user_data, ws_url = await retrieve_user_sess_data(sess_id=cur_usr_id)

    trace_results = None
    perf_results = None
    scan_results = None
    pcap_results = None
    alerts = None
    devices = None
    tux_count = 0
    win_count = 0
    android_count = 0
    iphone_count = 0

    probe_data = await cl_data_db.get_all_data(match=f"prb:*")

    if probe_data is None:
        probe_data = {"":""}

    trace_results = await retrieve_task_results(prb_id, "trcrt")
    perf_results = await retrieve_task_results(prb_id, "test_clnt")
    scan_results = await retrieve_task_results(prb_id, "scan")
    pcap_results = await retrieve_task_results(prb_id, "pcap")
    alerts = await cl_data_db.get_all_data(match=f"alert:{prb_id}:*")
    devices = await cl_data_db.get_all_data(match=f"netmap:result:{prb_id}:devices")

    if trace_results is None:
        trace_results = {'':''}
    if perf_results is None:
        perf_results = {'':''}
    if scan_results is None:
        scan_results = {'':''}
    if pcap_results is None:
        pcap_results = {'':''}
    if alerts is None:
        alerts = {'':''}
    if devices is None:
        devices = {'':''}

    ws_prb_url = f"wss://{mntr_url}/v1/api/core/channels/probe/heartbeat/{prb_id}?sess_id={cur_usr_id}"

    return await render_template("app/dashboard.html", obsc_key=session.get('url_key') ,
                                  cmp_id=cmp_id, cur_usr_id=cur_usr_id, ws_url=ws_url, cur_usr=user_data.get('unm'), data=user_data, prb_id=prb_id, trace_results=trace_results, perf_results=perf_results, scan_results=scan_results, pcap_results=pcap_results, alerts=alerts, devices=devices, ws_prb_url=ws_prb_url, tux_count=tux_count, win_count=win_count, android_count=android_count, iphone_count=iphone_count, options=probe_data)

@app.errorhandler(CSRFError)
async def handle_csrf_error(e):
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "CSRF token error", "reason": str(e)})), 400

@app.errorhandler(Unauthorized)
async def unauthorized():
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401

@app.errorhandler(jwt.ExpiredSignatureError)
async def token_expired():
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "Token expired"})), 1008

@app.errorhandler(jwt.InvalidTokenError)
async def invalid_token():
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "Invalid token"})), 1000

@app.errorhandler(400)
async def bad_request():
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "Bad Request"})), 400

@app.errorhandler(401)
async def need_to_login():
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401
    
@app.errorhandler(404)
async def page_not_found():
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "Resource not found"})), 404

@app.errorhandler(500)
async def handle_internal_error(e):
    await ip_blocker()
    return await render_template_string(json.dumps({"error": "Internal server error", "reason": str(e)})), 500