import ast
import argparse
import asyncio
from email import message
from backend.init_app import logger
from backend.ai.utils.Util import Util
import os

class FlowRunner:
    def __init__(self):
        self.logger = logger
        self.util_obj = Util()

    async def ollama_chat(self, prompt: str, system_prompt):
        payload = {
            'model': os.getenv('OLLAMA_MODEL'),                    
            'bot_prompt':f"{prompt}",
            'instructions': system_prompt,   
        }
        status, response = await self.util_obj.make_http_request(headers={'content-type': 'application/json'}, url=f"{os.getenv('OLLAMA_PROXY_URL')}/analysis", data=payload, timeout=int(os.getenv('REQUEST_TIMEOUT')))

        return status, response

    async def run(self, flow_str: str, api_key: str, url: str, user_id: str):
        flow_dict = ast.literal_eval(flow_str)

        # Parsed flow data
        workflow = flow_dict
        self.logger.info(workflow)
        workflow_data = workflow['drawflow']['Home']['data']
        self.logger.info(workflow_data)

        node_output_mapping = {}
        alerts = {}
        agents = {}
        remote_tools_to_execute = {}
        remote_tool_params = {}
                
        for node_id, node in workflow_data.items():
            node_data = node.get('data')
            match node_data['name']:
                case str() as s if s.startswith('prb:'):
                    if node_data['prb-trcrttype']:
                        remote_tool_params['target'] = node_data['prb-trcrttarget']

                        if node_data['prb-trcrtoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-trcrtoptions']
                        if node_data['prb-trcrtpktlen']:
                            remote_tool_params['tool_prms']['packetlen'] = node_data['prb-trcrtpktlen']
                        if node_data['prb-trcrtdnsserver'] and node_data['prb-trcrttype'] == 'trcrt_dns':
                            remote_tool_params['tool_prms']['server'] = node_data['prb-trcrtdnsserver']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-trcrttype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-perftype']:
                        if node_data['prb-perfoptions']:
                            remote_tool_params['tool_prms']['options'] = node_data['prb-perfoptions']
                        if node_data['prb-perfserver'] and node_data['prb-perftype'] == 'spdtst_clnt':
                            remote_tool_params['tool_prms']['server'] = node_data['prb-perfserver']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-perftype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

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
                            remote_tool_params['interface'] = node_data['prb-scantgtiface']

                        if node_data['prb-scanvulnscore'] and node_data['prb-scanstype'] == 'vuln_scan':
                            remote_tool_params['tool_prms']['min_score'] = node_data['prb-scanvulnscore']

                        if node_data['prb-scantype'] == 'scan-map':
                            if node_data['prb-scantcpsyn']:
                                remote_tool_params['tool_prms']['syn_ports'] = node_data['prb-scantcpsyn']
                            if node_data['prb-scantcpack']:
                                remote_tool_params['tool_prms']['ack_ports'] = node_data['prb-scantcpack']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-scanstype'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                    if node_data['prb-pcapmode']:
                        if node_data['prb-pcapmode'] != 'pcap_lcl' and node_data['prb-pcaptrmuser'] and node_data['prb-pcaptrmpass'] and node_data['prb-pcaptrmhost']:
                            remote_tool_params['tool_prms']['usr'] = node_data['prb-pcaptrmuser']
                            remote_tool_params['tool_prms']['pwd'] = node_data['prb-pcaptrmpass']
                            remote_tool_params['tool_prms']['host'] = node_data['prb-pcaptrmhost']

                        if node_data['prb-pcapmode'] == 'pcap_lcl' and node_data['prb-pcapcount']:
                            remote_tool_params['tool_prms']['cap_count'] = node_data['prb-pcapcount']

                        if node_data['prb-pcapduration'] and node_data['prb-pcapmode'] == 'pcap_win':
                            remote_tool_params['tool_prms']['duration'] = node_data['prb-pcapduration']

                        remote_tools_to_execute[node_id] = {'name': node_data['prb-pcapmode'], 'arguments': remote_tool_params, 'prb': node_data['name']}

                case 'slack':
                    alerts['tool'] = node_data['name']

                case 'jira':
                    alerts['tool'] = node_data['name']
                 
                case 'email':
                    alerts['tool'] = node_data['name']

                case 'smartbot':
                    if node_data['bot-prompt']:
                        agents['prompt'] = node_data['bot-prompt']
                        agents['agent'] = node_data['name']

        if remote_tools_to_execute != {}:
            for node_id, tool_info in remote_tools_to_execute.items():
                headers = {'content-type': 'application/json',
                           'x-api-key': api_key}
                bot_data = {'url': url, 
                            'headers': headers,
                            'data': {
                                    'tool': tool_info['name'],
                                    'tool_prms': tool_info['arguments'],
                                    'prb_id': tool_info['prb'],
                                }
                            }
                
                mcp_run = await self.util_obj.make_http_request(**bot_data)
                if mcp_run.status_code == 200:
                    mcp_tool_data = mcp_run.json()
                    if node_id in node_output_mapping and node_output_mapping[node_id]:
                        node_output_mapping[node_id]['result'] = mcp_tool_data['output']
                        node_output_mapping[node_id]['prb'] = remote_tools_to_execute[node_id]['prb']
                        node_output_mapping[node_id]['tool'] = bot_data['payload']['tool']

        return node_output_mapping, alerts, agents
    
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