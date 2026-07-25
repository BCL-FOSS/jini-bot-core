import ast
import argparse
import asyncio
from email import message
from backend.init_app import logger, ANALYSIS_INSTRUCTIONS, NET_ADMIN_INSTRUCTIONS, REQUIRED_OUT_OF_SCOPE_MSG, cl_auth_db, cl_data_db, cwd
from backend.app import NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD
from backend.ai.utils.Util import Util
import os
from uuid import uuid4
from backend.utils.EmailSenderHandler import EmailSenderHandler
from datetime import datetime, timedelta, timezone
import uuid

class FlowRunner:
    def __init__(self):
        self.logger = logger
        self.util_obj = Util()
        self.email_handler = EmailSenderHandler()
        self.cwd = cwd

    async def run(self, flow_str: str, flow_name: str):
        flow_dict = ast.literal_eval(flow_str)

        # Parsed flow data
        workflow = flow_dict
        self.logger.info(workflow)
        workflow_data = workflow['drawflow']['Home']['data']
        self.logger.info(workflow_data)
        alerts = [{}]
        agents = {}
        remote_tools_to_execute = [{}]
        remote_tool_params = {}
                
        for node_id, node in workflow_data.items():
            node_data = node.get('data')
            match node_data['name']:
                case str() as s if s.startswith('prb:'):
                    if node_data['prb-trcrttype']:
                        remote_tool_params['tool_prms']['target'] = node_data['prb-trcrttarget']

                        if node_data['prb-trcrtoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-trcrtoptions']
                        if node_data['prb-trcrtpktlen']:
                            remote_tool_params['tool_prms']['packetlen'] = node_data['prb-trcrtpktlen']
                        if node_data['prb-trcrtdnsserver'] and node_data['prb-trcrttype'] == 'trcrt_dns':
                            remote_tool_params['tool_prms']['server'] = node_data['prb-trcrtdnsserver']

                        remote_tools_to_execute[node_id]['name'] = node_data['prb-trcrttype']
                        remote_tools_to_execute[node_id]['arguments'] = remote_tool_params
                        remote_tools_to_execute[node_id]['prb_id'] = node_data['id']
                        remote_tools_to_execute[node_id]['url'] = node_data['url']
                        remote_tools_to_execute[node_id]['api_key'] = node_data['api_key']

                    if node_data['prb-perftype']:
                        if node_data['prb-perfoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-perfoptions']
                        if node_data['prb-perfserver'] and node_data['prb-perftype'] == 'spdtst_clnt':
                            remote-_tool_params['tool_prms']['server'] = node_data['prb-perfserver']

                        remote_tools_to_execute[node_id]['name'] = node_data['prb-perftype']
                        remote_tools_to_execute[node_id]['arguments'] = remote_tool_params
                        remote_tools_to_execute[node_id]['prb_id'] = node_data['id']
                        remote_tools_to_execute[node_id]['url'] = node_data['url']
                        remote_tools_to_execute[node_id]['api_key'] = node_data['api_key']

                    if node_data['prb-scanstype']:
                        if node_data['prb-scantarget']:
                            remote_tool_params['tool_prms']['target'] = node_data['prb-scantarget']

                        if node_data['prb-scanstype'] == 'scan_snmp':
                            if node_data['prb-snmpscanscripts']:
                                remote_tool_params['tool_prms']['scripts'] = node_data['prb-snmpscanscripts']

                            if node_data['prb-snmpcommunity']:
                                remote_tool_params['community'] = node_data['prb-snmpcommunity']

                        if node_data['prb-scanoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-scanoptions']

                        if node_data['prb-scantgtifacedef'] == 'y' and node_data['scantgtiface']:
                            remote_tool_params['tool_prms']['interface'] = node_data['prb-scantgtiface']

                        if node_data['prb-scanvulnscore'] and node_data['prb-scanstype'] == 'vuln_scan':
                            remote_tool_params['tool_prms']['min_score'] = node_data['prb-scanvulnscore']

                        if node_data['prb-scantype'] == 'scan-map':
                            if node_data['prb-scantcpsyn']:
                                remote_tool_params['tool_prms']['syn_ports'] = node_data['prb-scantcpsyn']
                            if node_data['prb-scantcpack']:
                                remote_tool_params['tool_prms']['ack_ports'] = node_data['prb-scantcpack']

                        remote_tools_to_execute[node_id]['name'] = node_data['prb-scanstype']
                        remote_tools_to_execute[node_id]['arguments'] = remote_tool_params
                        remote_tools_to_execute[node_id]['prb_id'] = node_data['id']
                        remote_tools_to_execute[node_id]['url'] = node_data['url']
                        remote_tools_to_execute[node_id]['api_key'] = node_data['api_key']

                    if node_data['prb-pcapmode']:
                        if node_data['prb-pcapmode'] != 'pcap_lcl' and node_data['prb-pcaptrmuser'] and node_data['prb-pcaptrmpass'] and node_data['prb-pcaptrmhost']:
                            remote_tool_params['tool_prms']['usr'] = node_data['prb-pcaptrmuser']
                            remote_tool_params['tool_prms']['pwd'] = node_data['prb-pcaptrmpass']
                            remote_tool_params['tool_prms']['host'] = node_data['prb-pcaptrmhost']

                        if node_data['prb-pcapmode'] == 'pcap_lcl' and node_data['prb-pcapcount']:
                            remote_tool_params['tool_prms']['cap_count'] = node_data['prb-pcapcount']

                            if node_data['prb-pcaplcliface']:
                                remote_tool_params['tool_prms']['interface'] = node_data['prb-pcaplcliface']

                        if node_data['prb-pcapduration'] and node_data['prb-pcapmode'] == 'pcap_win':
                            remote_tool_params['tool_prms']['duration'] = node_data['prb-pcapduration']

                        if node_data['prb-pcaprmiface'] and node_data['prb-pcapmode'] == 'pcap_win' | 'pcap_tux':
                            remote_tool_params['tool_prms']['remote_iface'] = node_data['prb-pcaprmiface']

                        remote_tools_to_execute[node_id]['name'] = node_data['prb-pcapmode']
                        remote_tools_to_execute[node_id]['arguments'] = remote_tool_params
                        remote_tools_to_execute[node_id]['prb_id'] = node_data['id']
                        remote_tools_to_execute[node_id]['url'] = node_data['url']
                        remote_tools_to_execute[node_id]['api_key'] = node_data['api_key']

                case 'slack':
                    alerts['tool'] = node_data['name']

                case 'jira':
                    alerts['tool'] = node_data['name']
                 
                case 'email':
                    alerts['tool'] = node_data['name']

                case 'smartbot':
                    if node_data['bot-prompt']:
                        agents[0]['prompt'] = node_data['bot-prompt']
                        agents[0]['agent'] = node_data['name']


        task_output=""
        if remote_tools_to_execute != [{}]:
            for node_id in remote_tools_to_execute:
                headers = {'content-type': 'application/json',
                           'x-api-key': [remote_tools_to_execute[node_id]['api_key']]}
                task_data = {'url': f"https://{remote_tools_to_execute[node_id]['url']}/v1/api/tasks/exec",
                            'headers': headers,
                            'data': {
                                    'action': remote_tools_to_execute[node_id]['name'],
                                    'params': remote_tools_to_execute[node_id]['arguments'],
                                    'prb_id': remote_tools_to_execute[node_id]['prb_id'],
                                }
                            }
                
                task_resp, task_resp_json = await self.util_obj.make_http_request(**task_data)
                if task_resp == 200:
                     
                    parser_script_path = os.path.join(self.cwd, 'utils', 'jini-utils', f'Parsers.py')
                    task_command = f"python3 {parser_script_path} --action {remote_tools_to_execute[node_id]['name']} -o {task_resp_json['output']}"

                    if str(remote_tools_to_execute[node_id]['name']).startswith('scan_'):
                        task_command+=f'--file {task_resp_json['output']}'

                    if str(remote_tools_to_execute[node_id]['name']).startswith('trcrt'):
                        task_command+=f'-tar {remote_tools_to_execute[node_id]['arguments']['tool_prms']['target']} -pid {remote_tools_to_execute[node_id]['prb_id']}'

                    if str(remote_tools_to_execute[node_id]['name']).startswith('pcap_'):
                        task_command+=f'-i {remote_tools_to_execute[node_id]['arguments']['tool_prms']['interface']}'

                    task_return_code, task_stdout, task_stderr = await self.util_obj.run_shell_cmd(task_command)
                    if task_return_code == 0:
                        task_output+=f"Task: {remote_tools_to_execute[node_id]['name']}\nProbe: {remote_tools_to_execute[node_id]['prb_id']}\nOutput: {task_stdout}\n"
                    else:
                        task_output+=f"Task: {remote_tools_to_execute[node_id]['name']}\nProbe: {remote_tools_to_execute[node_id]['prb_id']}\nStatus: Failed\n"

            analysis_prompt = (
                                        f"{task_output}"
                                        + "\n\n"
                                        f"{agents[0]['prompt']}"
                                        )
                                    
            analysis_instructions = (
                                        NET_ADMIN_INSTRUCTIONS
                                        + "\n\n"
                                        + ANALYSIS_INSTRUCTIONS
                                        + "\n\n"
                                        + NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD
                                    )
                    
            payload = {
                                'model': os.getenv('OLLAMA_MODEL'),
                                'message':f"{analysis_prompt}",
                                'name':f'{agents[0]['name']}',
                                'instructions': analysis_instructions,
                            }

            chat_resp, chat_resp_json = await self.util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/analysis", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

            if chat_resp.status == 200:
                email_contact = None
                now = str(datetime.now(tz=timezone.utc))
                if await cl_auth_db.get_all_data(match='*primary-contact-email*', cnfrm=True) is False:
                    await cl_data_db.upload_db_data(id=f'anlys:{agents[0]['name']}:{now}:{str(uuid.uuid4())}')
                else:
                    email_contact = await cl_data_db.get_all_data(match='*primary-contact-email*')

                html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                                <p>Jini Monitor Analysis Complete</p>
                                <p>Workflow: {flow_name}</p>
                                <p>Prompt: {agents[0]['prompt']}</p>
                                <p>Response: {chat_resp_json}</p>
                                <p>Tool(s) Output: {task_output}</p>
                                </div>"""
                email_params = {'sender': {'name': 'jini bot', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                'to': [{"name": email_contact, "email": email_contact}],
                                'subject': f'jini Bot Analysis Report - {flow_name} - {now}',
                                'html_content': html_snippet}
                email_script_path = os.path.join(self.cwd, 'utils', 'jini-utils', f'EmailMgr.py')
                email_command = f"python3 {email_script_path} -t 'send' -p {email_params}"

                email_code, email_output, email_error = -await self.util_obj.run_shell_cmd(cmd=email_command)
                

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run network automation workflows.")
    parser.add_argument(
        '-f', '--flow', 
        type=str, 
        help="Network flow to execute"
    )
   
    parser.add_argument(
        '-w', '--ws_url', 
        type=str, 
        help="WebSocket URL for reporting results"
    )
    parser.add_argument(
        '-pid', '--probe_id', 
        type=str, 
        help="Probe ID for reporting results"
    )
    parser.add_argument(
        '-ak', '--api_key', 
        type=str, 
        help="API key for authentication"
    )
    parser.add_argument(
        '-url', '--probe_url',
        type=str,
        help="Probe API url"
    )
    parser.add_argument(
        '-uid', '--user_id',
        type=str,
        help="User ID assigned to the current flow"
    )
    args = parser.parse_args()

    workflow_runner = FlowRunner()

    asyncio.run(workflow_runner.run(flow_str=str(args.flow), ws_url=args.ws_url, probe_id=args.probe_id, api_key=args.api_key, url=args.probe_url, user_id=args.user_id))