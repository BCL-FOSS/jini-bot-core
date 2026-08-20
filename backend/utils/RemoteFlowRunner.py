import ast
import argparse
import asyncio
from backend.init_app import logger, ANALYSIS_INSTRUCTIONS, NET_ADMIN_INSTRUCTIONS, util_obj, comm_mgr
from backend.app import NETWORK_DIAGNOSTIC_SYSTEM_PROMPT_MD
import os
import json

class RemoteFlowRunner:
    def __init__(self):
        pass
   
    async def run(self, flow_str: str, flow_name: str):
        flow_dict = ast.literal_eval(flow_str)
        workflow = flow_dict
        logger.info(workflow)
        workflow_data = workflow['drawflow']['Home']['data']
        logger.info(workflow_data)
        alerts = [str]
        agent = {}
        remote_tools_to_execute = {}
                
        for node_id, node in workflow_data.items():
            node_data = node.get('data')
            match node_data['name']:
                case str() as s if s.startswith('prb:'):
                    remote_tools_to_execute[node_data['name']] = {
                        'task_data': [],
                        'url': node_data['url'],
                        'api_key': node_data['api_key'],
                        'name': node_data['name']
                        }
                    if node_data['prb-trcrttype']:
                        remote_tool_params = {}
                        remote_tool_params['tool_prms']['target'] = node_data['prb-trcrttarget']

                        if node_data['prb-trcrtoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-trcrtoptions']
                        if node_data['prb-trcrtpktlen']:
                            remote_tool_params['tool_prms']['packetlen'] = node_data['prb-trcrtpktlen']
                        if node_data['prb-trcrtdnsserver'] and node_data['prb-trcrttype'] == 'trcrt_dns':
                            remote_tool_params['tool_prms']['server'] = node_data['prb-trcrtdnsserver']

                        remote_tools_to_execute[node_data['name']]['task_data'].append({
                            'action': node_data['prb-trcrttype'],
                            'params': remote_tool_params
                        })

                    if node_data['prb-perftype']:
                        remote_tool_params = {}
                        if node_data['prb-perfoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-perfoptions']
                        if node_data['prb-perfserver'] and node_data['prb-perftype'] == 'spdtst_clnt':
                            remote_tool_params['tool_prms']['server'] = node_data['prb-perfserver']

                        remote_tools_to_execute[node_data['name']]['task_data'].append({
                            'action': node_data['prb-perftype'],
                            'params': remote_tool_params
                        })

                    if node_data['prb-scanstype']:
                        remote_tool_params = {}
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

                        remote_tools_to_execute[node_data['name']]['task_data'].append({
                            'action': node_data['prb-scanstype'],
                            'params': remote_tool_params
                        })

                    if node_data['prb-pcapmode']:
                        remote_tool_params = {}
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

                        remote_tools_to_execute[node_data['name']]['task_data'].append({
                            'action': node_data['prb-pcapmode'],
                            'params': remote_tool_params
                        })

                case 'slack' | 'jira' | 'email':
                    alerts.append(node_data['name'])

                case 'smartbot':
                    if node_data['bot-prompt']:
                        agent['prompt'] = node_data['bot-prompt']
                        agent['agent'] = node_data['name']

        if remote_tools_to_execute != {}:
            probe_response=""
            for probe in remote_tools_to_execute:
                headers = {'content-type': 'application/json',
                           'x-api-key': probe['api']}
                task_data = {'url': f"{probe['url']}/v1/api/tasks/exec",
                            'headers': headers,
                            'data': {
                                    'tools_list': json.dumps(probe['task_data'])
                                }
                            }
                task_resp, task_resp_json = await util_obj.make_http_request(**task_data)
                if task_resp == 200:
                    probe_response += f"Probe: {probe['name']}\nOutput: {task_resp_json.get('output')}\n\n"

            analysis_prompt = (
                    f"{probe_response}"
                    + "\n\n"
                    + f"{agent['prompt']}"
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
                    'message': f"{analysis_prompt}",
                    'name': f"{agent['name']}",
                    'instructions': analysis_instructions,
                }

            chat_resp, chat_resp_json = await util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/analysis", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

            if chat_resp == 200:
                await comm_mgr.send_llm_response(alerts=alerts, flow_name=flow_name, prompt=agent['prompt'], llm_resp=chat_resp_json, task_output=probe_response)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run network automation workflows.")
    parser.add_argument(
        '-f', '--flow', 
        type=str, 
        help="Network flow to execute"
    )
    parser.add_argument(
        '-n', '--name', 
        type=str, 
        help="Network flow name"
    )
    args = parser.parse_args()
    workflow_runner = RemoteFlowRunner()
    asyncio.run(workflow_runner.run(flow_str=str(args.flow), flow_name=args.name))