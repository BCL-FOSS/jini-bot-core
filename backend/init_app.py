from quart import Quart
from quart.utils import run_sync
import nest_asyncio
import logging
import secrets
import nest_asyncio
import logging
from quart_rate_limiter import (RateLimiter, RateLimit, timedelta)
import logging
from ai.utils.Util import Util
import os
from crontab import CronTab
from ai.utils.RedisDB import RedisDB
from utils.WSRateLimiter import WSRateLimiter
import asyncio

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

app = Quart(__name__)
app.config.from_object("config")
app.config['SECRET_KEY'] = secrets.token_urlsafe()
app.config['SECURITY_PASSWORD_SALT'] = str(secrets.SystemRandom().getrandbits(128))
nest_asyncio.apply()
RateLimiter(
    app,
    default_limits=[
        RateLimit(1, timedelta(seconds=1)),
        RateLimit(20, timedelta(minutes=1)),
    ],
)
util_obj = Util()
cron = CronTab(user='root')
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
    "Your primary task is to analyze the outputs of traceroutes, iperf speedtests, nmap network scans, SNMP statistics and network packet captures from tcpdump and tshark (cli version of wireshark) to identify, diagnose, troubleshoot and resolve network performance issues, outages and anomalies within current and historical network data. You will provide suggestions for network performance improvements only based on the specifications provided from the user prompt. If you are asked just to conduct an analysis always put 'SmartBot-Analysis:' before your response. If you are asked to remediate any issues found dring your analysis, use any of the applicable tools provided by the MCP servers. If the available tools are insufficient to perform remediation, reply with a detailed report of your findings, the steps you'd take to resolve any issues identified and what exact tools (command line network utilities, firewall/switch configurations etc.) and exact network command line tool commands you would use during the remediation process. Put 'SmartBot-Remediation: ' before your response. If you are asked to analyze if specific data within the network commandline utilities outputs meet certain criteria or KPI metrics specified by the user, put 'SmartBot-Alert:' before your response.\n")
cwd = os.getcwd()
utility_scripts_path = os.path.join(cwd, 'ai', 'utils', 'jini-utils')

async def check_for_utils():
    # Check if jini utility scripts have been downloaded. If not, clones from github.
    if os.path.isdir(utility_scripts_path) is False:
        code, output, error = await util_obj.run_shell_cmd(cmd=f'cd {os.path.join(cwd, 'ai', 'utils')} && git clone https://github.com/BCL-FOSS/jini-utils.git')
        if code != 0:
            logger.info(f'Error: {error}\nOutput: {output}')  
        logger.info(output)
        exit(code=code)
    else:
        pass

def load_network_diagnostic_prompt() -> str:
    try:
        #base_dir = os.path.dirname(os.path.abspath(__file__))  # backend/
        prompt_path = os.path.join(cwd, "ai", "skills", "network-diagnostic-system-prompt.md")
        logger.info(f"Loading network diagnostic system prompt from: {prompt_path}")
        with open(prompt_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.exception(f"Failed to load network diagnostic system prompt: {e}")
        return ""

def schedule_cronjob(job1: CronTab, core_act_data: dict):
    if 'minutes' in core_act_data and core_act_data['minutes']:
        minutes_range = str(core_act_data['minutes']).split(",")
        if isinstance(minutes_range, list):
            match len(minutes_range):
                case 3:
                    job1.minute.during(minutes_range[0], minutes_range[1]).every(minutes_range[2])
                case 2:
                    job1.minute.during(minutes_range[0], minutes_range[1])
                case 1:
                    job1.minute.every(minutes_range[0])

    if 'hours' in core_act_data and core_act_data['hours']:
        hours_range = str(core_act_data['hours']).split(",")
        if isinstance(hours_range, list):
            match len(hours_range):
                case 3:
                    job1.hour.during(hours_range[0], hours_range[1]).every(hours_range[2])
                case 2:
                    job1.hour.during(hours_range[0], hours_range[1])
                case 1:
                    job1.hour.every(hours_range[0])

    if 'dom' in core_act_data and core_act_data['dom']:
        dom_range = str(core_act_data['dom']).split(",")
        if isinstance(dom_range, list):
            match len(dom_range):
                case 3:
                    job1.dom.during(dom_range[0], dom_range[1]).every(dom_range[2])
                case 2:
                    job1.dom.during(dom_range[0], dom_range[1])
                case 1:
                    job1.dom.every(dom_range[0])

    if 'days' in core_act_data and core_act_data['days']:
        days_range = str(core_act_data['days']).split(",")
        if isinstance(days_range, list):
            job1.dow.on(days_range)

    if 'months' in core_act_data and core_act_data['months']:
        months_range = str(core_act_data['months']).split(",")
        if isinstance(months_range, list):
            match len(months_range):
                case 3:
                    job1.month.during(months_range[0], months_range[1]).every(months_range[2])
                case 2:
                    job1.month.during(months_range[0], months_range[1])
                case 1:
                    job1.month.every(months_range[0])
                                    
    return job1
