import json
import os
from telegram import Update, Message, Chat, User
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from backend.init_app import util_obj, NET_ADMIN_INSTRUCTIONS, logger, REQUIRED_OUT_OF_SCOPE_MSG, utility_scripts_path
from backend.app import cl_data_db, connected_probes
from datetime import datetime, timezone
import uuid
from websocket import create_connection
import asyncio
from telegram.ext import Application, CommandHandler, ContextTypes

connected_chats=[{}]

async def check_id(self, connecting_id: int) -> bool:
        allowed_telegram_ids = await cl_data_db.get_all_data(match=f"telegram_dta:*")
        for tg_id in allowed_telegram_ids:
            if tg_id.get('id') != str(connecting_id):
                return False
            else:
                return True

async def alerts_telegram_users(ws_url: str, application: Application):
    ws = create_connection(url=ws_url)
    to_check = True
    while to_check:
        async def receive_resp():
            raw = await asyncio.to_thread(ws.recv)
            data = json.loads(raw)
            match data.get('alert_type'):
                case 'outage':
                    for chat in connected_chats:
                        bot = application.bot
                        chat = Chat(id=chat['chat_id'], type=Chat.PRIVATE)
                        user = User(id=chat['chat_id'], first_name="System", is_bot=False)    
                        mock_message = Message(message_id=0, date=None, chat=chat, from_user=user, text="")
                        mock_update = Update(update_id=0, message=mock_message)
                        context = ContextTypes.DEFAULT_TYPE.from_update(mock_update, application)
                        await send_alert(mock_update, context)
                    await asyncio.to_thread(ws.close)
                    continue
        await receive_resp()

async def chat_update(update: Update):
    if update.effective_chat.id and (update.effective_chat.id not in connected_chats):
        connected_chats.append({
            'chat_id': update.effective_chat.id,
            'user_id': update.effective_user.id
                            })
    await asyncio.sleep(0.2)

async def check_probes_status(app: Application):
    for probe in connected_probes.values():
        ws_url = f"wss://{os.getenv('SERVER_NAME')}/v1/api/core/channels/probe/heartbeat/{probe['id']}/{1}?token={connected_probes[probe['id']]['token']}"
        connected_probes[probe['prb_id']]['alerts'] = asyncio.create_task(alerts_telegram_users(ws_url=ws_url, application=app))
        await asyncio.sleep(0.1)

async def execute_tool_call(prompt: str):
    prompt, prb_id = await util_obj.split_text_by_keyword(prompt.lower(), keyword="prb_id:", cnfrm=True)
    if await cl_data_db.get_all_data(match=f'*{prb_id}*', cnfrm=True) is True:
        selected_probe = await cl_data_db.get_all_data(match=f'*{prb_id}*')
        selected_probe_dict = next(iter(selected_probe.values()))
        api = selected_probe_dict.get('prb_api_key')
        tool_request, analysis_request = await util_obj.split_text_by_keyword(prompt, keyword="analysis:")
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
                    }
        now = datetime.now(tz=timezone.utc).isoformat()
               
        status, tool_resp = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/chat", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

        if status == 200:
            parser_script_path=os.path.join(utility_scripts_path, f'Parsers.py')
            if saved_tools_instructions == "":
                connected_probes.get(prb_id)['tool_instructions'] = tool_resp['tool_instructions']

            if tool_resp['output_text'] == REQUIRED_OUT_OF_SCOPE_MSG:
                return REQUIRED_OUT_OF_SCOPE_MSG
            else:
                documents=[]
                all_content=""
                logger.info(f"Request result: {tool_resp['output_text']}\n")
                logger.info(type(tool_resp['output_text']))
                data = json.loads(tool_resp['output_text'])

                for item in data:
                    output_message = ""
                    net_cmd_output = item['output'][1]
                    logger.info(f"Net command output: {net_cmd_output}")
                    decoded_output = net_cmd_output.encode('utf-8').decode('unicode_escape')
                    lines = decoded_output.split('\n')

                    for i, line in enumerate(lines):
                        net_cmd_data = f'{line}\n'
                        output_message+=net_cmd_data  

                    content=f"Tool: {item['tool']}\n"
                    content+=f"Probe: {prb_id}"
                    content += f"Timestamp: {now}\n"
                    content += f"Raw Output:\n{output_message}\n"
                    doc_id = f"chat_{now}_{prb_id}_{str(uuid.uuid4())}"

                    documents.append({
                        "tool_type": f"{item['tool']}",
                        "output": f"{output_message}",
                        "content": content,
                        "metadata": {
                            "prb_id": f"{prb_id}",
                            "timestamp": f"{now}",
                            "tool_type": f"{item['tool']}",
                            "type": f"chat_{prb_id}"
                                    },
                        "auto_execute": False,
                        "id": doc_id
                        }) 
                    all_content+=f"{content}\n\n"

                status, tool_resp = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/ingest/batch", data={'docuements': json.dumps(documents)}, timeout=int(os.getenv('REQUEST_TIMEOUT')))      

                if status == 200:
                    anlys_payload = {
                        'content': all_content,
                        'metadata': json.dumps({"type": f"chat_{prb_id}",
                                                "prb_id": f"{prb_id}"}),
                        'available_tools': data['tool_instructions'],
                        'detect_type': 1
                    }
                    anlys_status, anlys_resp = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/analyze/batch", data=anlys_payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))  

                    if anlys_status == 200:
                        return anlys_resp


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await check_id(connecting_id)
    if not is_authorized:
        return

    await chat_update(update=update)
    
    probe_data = await cl_data_db.get_all_data(match=f"prb:*")
    probe_data_dict = next(iter(probe_data.values()))
    probe_info = ""
    for prb in probe_data_dict:
        probe_info += f"Probe ID: {prb.get('id')}, Name: {prb.get('name')}, Site: {prb.get('site')}\n"

    await context.bot.send_message(chat_id=update.effective_chat.id, text="👋 Hello! I'm your Jini Network Assistant.\n" \
    "I have access to the following probes:\n" + probe_info + "\n\nAvailable Commands:\n/query - send a query to the umjini\n/exec - execute net admin tasks at specified sites (probes) with umjini. Specify the probe by ID by putting 'prb_id:<ID>' at the end of your request\n"
    "/start - show this message again")

async def exec(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await check_id(connecting_id)
    if not is_authorized:
        return

    await chat_update(update=update)
    
    if not context.args:
        await update.message.reply_text("Usage: /exec <your command> prb_id:<probe_id>")
        return
    
    prompt = " ".join(context.args)
    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )
    response = await execute_tool_call(prompt=prompt)
    await update.message.reply_text(response)

async def query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await check_id(connecting_id)
    if not is_authorized:
        return
    if not context.args:
        await update.message.reply_text("Usage: /query <your question>")
        return
    await chat_update(update=update)
    prompt = " ".join(context.args)
    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )
    payload = {}
    llm_prompt, query_prompt = await util_obj.split_text_by_keyword(prompt, keyword="query:")
    payload['prompt'] = llm_prompt

    if query_prompt != "".strip():
        parsed_query, filter = await util_obj.split_text_by_keyword(query_prompt, keyword="filter:")
        if filter == "".strip():
            payload['query'] = query_prompt
        else:
            payload['query'] = parsed_query
            parsed_filter, doc_filter = await util_obj.split_text_by_keyword(query_prompt, keyword="doc_filter:")
            if doc_filter == "".strip():
                payload['filter'] = parsed_filter
            else:
                payload['doc_filter'] = doc_filter

    status, resp = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/query", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))  
  
    await update.message.reply_text(resp['result'])

async def send_alert(update: Update, context: ContextTypes.DEFAULT_TYPE):
    alert_msg = " ".join(context.args)
    await context.bot.send_message(chat_id=update.effective_chat.id, text=alert_msg)

async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await check_id(connecting_id)
    if not is_authorized:
        return
    await context.bot.send_message(chat_id=update.effective_chat.id, text="Sorry, I didn't understand that command.")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    connecting_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    is_authorized = await check_id(connecting_id)
    if not is_authorized:
        return
    await chat_update(update=update)
    user_id = update.effective_user.id if update.effective_user else update.effective_chat.id
    prompt = update.message.text

    await context.bot.send_chat_action(
        chat_id=update.effective_chat.id, action="typing"
    )

def main() -> None:
    app = ApplicationBuilder().token(os.getenv("TELEGRAM_BOT_TOKEN")).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("query", query))
    app.add_handler(CommandHandler("exec", exec))
    app.add_handler(CommandHandler("send", send_alert))
    #app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.COMMAND, unknown))  
    app.run_polling()
    monitor_task = asyncio.create_task(check_probes_status(app=app))

if __name__ == "__main__":
    main()