import httpx
from quart import Quart
import logging
import os
from utils.RAGEngine import RAGEngine
import json
import re
from utils.RedisDB import RedisDB
from utils.Util import Util

logging.basicConfig(level=logging.DEBUG)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

util_obj = Util()

app = Quart(__name__)
OLLAMA_URL = "http://ollama:11434/api/chat"

cl_data_db = RedisDB(hostname=os.environ.get('CLIENT_DATA_DB'),
                                                    port=os.environ.get('CLIENT_DATA_DB_PORT'))
REQUIRED_OUT_OF_SCOPE_MSG = "Please provide a question or request related to network administration or the available MCP tools."

# Headers and payloads to initialize FastMCP connections
headers = {
    'accept': 'application/json, text/event-stream',
    'content-type': 'application/json'
}
init_payload = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-08-24",
        "capabilities": {},
        "clientInfo": {
            "name": "python-client",
            "version": "1.0.0"
        }
    },
    "id": 1
}
init_complete_payload = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized"
}

# === Utility: Clean Ollama output ===
def clean_ollama_output(raw: str) -> str:
    """Strip <think> blocks and whitespace from model output."""
    return re.sub(r"<think>.*?</think>", "", raw, flags=re.S).strip()


# === Defensive parser for MCP arguments ===
def normalize_arguments(args):
    """
    Ensure arguments are always a dict of values (per OpenAI tool spec).
    If model echoes a schema, convert required keys to placeholders.
    """
    if isinstance(args, dict):
        logger.debug(f"Using arguments as-is: {args}")
        return args
    elif isinstance(args, list) and len(args) > 0 and isinstance(args[0], dict):
        schema_obj = args[0]
        clean_args = {}
        for req in schema_obj.get("required", []):
            clean_args[req] = f"<missing:{req}>"
        logger.warning(f"Model returned schema instead of values. Converted to placeholders: {clean_args}")
        return clean_args
    else:
        logger.warning(f"Unexpected arguments format: {args}")
        return {}

async def call_mcp(server_url: str, tool_call: dict):
    """
    Call the FastMCP server tool with sanitized arguments.
    """
    tool_name = tool_call.get("name")
    args = normalize_arguments(tool_call.get("arguments", {}))
    logger.info(f"Calling MCP tool `{tool_name}` with arguments: {args}")

    async with httpx.AsyncClient() as client:
        # Initialize MCP session
        resp = await client.post(server_url, json=init_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
        
        session_id = resp.headers.get('mcp-session-id')
        headers['Mcp-Session-Id'] = session_id
        logger.info(f"Using MCP session: {session_id}")

        # Complete initialization
        init_complete_resp = await client.post(server_url, json=init_complete_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        # Perform tool call
        tool_call_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            },
            "id": 2
        }

        tool_call_resp = await client.post(server_url, json=tool_call_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        # Extract SSE "data:" line
        lines = tool_call_resp.text.split('\n')
        data_line = next((line for line in lines if line.startswith('data: ')), None)
        if data_line:
            result = json.loads(data_line[6:])
            answer = result['result']['content'][0]
            #answer_data = json.loads(answer['text'])
            text = answer.get("text")
            answer_data = json.loads(text)
            return answer_data

async def fetch_mcp_tools(server_url: str) -> list:
    """
    Fetch available tool schemas (inputs + returns) from MCP server manifest.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(server_url, json=init_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
      
        session_id = resp.headers.get('mcp-session-id')
        headers['Mcp-Session-Id'] = session_id
        logger.info(f"Fetched MCP session: {session_id}")

        init_complete_resp = await client.post(server_url, json=init_complete_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        tool_list_payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2
        }

        tool_list_resp = await client.post(server_url, json=tool_list_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        lines = tool_list_resp.text.split('\n')
        data_line = next((line for line in lines if line.startswith('data: ')), None)
        if data_line:
            result = json.loads(data_line[6:])
            tool_data = result['result']
            logger.info(f"Available tools: {tool_data['tools']}")
            return tool_data['tools']
        
async def chat_with_ollama(conversation: list, model: str) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            OLLAMA_URL,
            json={"model": model, "messages": conversation, "stream": False},
            timeout=int(os.environ.get('REQUEST_TIMEOUT')),
        )
        
        if resp.status_code != 200:
            logger.error(f"Ollama API error: {resp.status_code} - {resp.text}")
            return None
      
        ollama_json = resp.json()
        ollama_out = ollama_json.get("message", {}).get("content", "")
        logger.info(f"Ollama output (raw): {ollama_out}")

    ollama_out_clean = clean_ollama_output(ollama_out)

    return ollama_out_clean

# Initialize RAG Engine
rag_engine = RAGEngine(
            collection_name=os.environ.get('COLLECTION_NAME', 'network_analysis'),
            embedding_model=os.environ.get('EMBEDDING_MODEL', 'all-MiniLM-L6-v2'),
            ollama_model=os.environ.get('OLLAMA_MODEL', 'qwen2.5:7b'),
            mcp_server_url=os.environ.get('MCP_SERVER_URL')
        )

