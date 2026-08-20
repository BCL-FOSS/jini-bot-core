import re
import json
import uuid
from quart import request, jsonify
from init_app import app, logger, headers, rag_engine, call_mcp, fetch_mcp_tools, chat_with_ollama, REQUIRED_OUT_OF_SCOPE_MSG
import uuid
from backend.init_app import cl_data_db
from datetime import datetime, timezone
from quart.utils import run_sync

@app.before_serving
async def db_startup():
    await rag_engine.init_chroma_db()

@app.route("/v1/chat", methods=["POST"])
async def chat():
    data = await request.get_json()
    logger.info(f"Incoming request: {data}")

    model = data.get("model")
    instructions = data.get("instructions")
    user_input = data.get("usr_input")
    tools = data.get("tools")
    user = data.get("user")
    api_key = data.get("api_key")
    headers['x-api-key'] = api_key
    logger.info(headers)
    tool_instructions = ""
    response_payload = {}

    if 'tool_instructions' in data and data['tool_instructions']:
        tool_instructions = data['tool_instructions']

    else:
        # --- Step A: Collect tool schemas from MCP servers ---
        tool_schemas = []
        for t in tools:
            if t.get("type") == "mcp":
                mcp_tools = await fetch_mcp_tools(server_url=t["server_url"])
                if mcp_tools is None:
                    return {'Error': f"Failed to fetch tools from {t['server_url']}"}
                for tool in mcp_tools:
                    tool_schemas.append({
                        "server_label": t["server_label"],
                        "server_url": t["server_url"],
                        "schema": tool
                    })

        logger.info(tool_schemas)
        # --- Step B: Build tool instructions for the LLM ---
        if tool_schemas:
            tool_instructions += (
                "You have access to the following tools. "
                "When using them, respond ONLY with a JSON object in this format:\n"
                '{"name": "<tool_name>", "arguments": {"param1": "value1", "param2": "value2"}}\n\n'
                "Arguments must always be concrete values, not schemas or descriptions.\n\n"
                "✅ Valid example:\n"
                '{"name": "controller_system_data", "arguments": {"user": "hollow", "ip": "ubnt.baughcl.tech"}}\n\n'
                "❌ Invalid example:\n"
                '{"name": "controller_system_data", "arguments": [{"properties": {"user": {...}, "ip": {...}}}]}\n\n'
                "If you want to call multiple tools in a single response, return a JSON array of objects, e.g.:\n"
                "✅ Valid example:\n"
                '[{"name": "tool_a", "arguments": {...}}, {"name": "tool_b", "arguments": {...}}]\n\n'   
                "Available tools:\n"
            )
            for ts in tool_schemas:
                sch = ts["schema"]
                tool_instructions += f"- {sch['name']}: {sch['description']}\n"
                tool_instructions += f"  Parameters: {json.dumps(sch['inputSchema'])}\n"

    # --- Step C: Send conversation to Ollama ---
    conversation = [
        {"role": "system", "content": instructions + "\n" + tool_instructions},
        {"role": "user", "content": user_input},
    ]

    ollama_out_clean = await chat_with_ollama(conversation, model)

    if f"I am a locally hosted, open source {model} model running on ollama.".lower() in ollama_out_clean.lower():
        logger.info(tools[0].get('server_url'))

        response_payload={
            "id": f"resp:{user}:{tools[0].get('server_url')}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
            "user_msg": user_input,
            "output_text": ollama_out_clean
        }

        logger.info(response_payload)

        return jsonify(response_payload)
    
    if f"SmartBot-Remediation: ".lower() in ollama_out_clean.lower():
        logger.info(tools[0].get('server_url'))

        response_payload={
            "id": f"resp:{user}:{tools[0].get('server_url')}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
            "user_msg": user_input,
            "output_text": ollama_out_clean
        }

        logger.info(response_payload)

        return jsonify(response_payload)
    
    parsed = None
    try:
        parsed = json.loads(ollama_out_clean)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", ollama_out_clean, re.S)
        if match:
            try:
                parsed = json.loads(match.group())
            except Exception as e:
                logger.warning(f"Could not parse JSON block: {e}")

    # --- Step E: Handle tool calls with retry on bad format ---
    tool_outputs = []
    final_output = ""

    def is_valid_arguments(obj):
        return isinstance(obj.get("arguments", {}), dict)

    # Helper: re-prompt Ollama when output is invalid
    async def retry_with_clarification(conversation, reason, bad_output):
        logger.warning(f"Bad tool call output detected. Reason: {reason}")
        logger.warning(f"--- BAD OUTPUT ---\n{bad_output}\n-----------------")

        conversation.append({
            "role": "system",
            "content": (
                f"Your previous output could not be parsed because: {reason}. "
                "Please retry by returning ONLY a JSON object with concrete argument values, like:\n"
                '{"name": "tool_name", "arguments": {"param": "value"}}\n'
                "Do NOT return schemas, descriptions, or wrap arguments in arrays."
            )
        })

        return await chat_with_ollama(conversation, model)

    # If parsed is bad or arguments are schema instead of values
    if not (isinstance(parsed, dict) and "name" in parsed and is_valid_arguments(parsed)) and not (isinstance(parsed, list)):
        reason = "Arguments were not a dict of values or a list of tool calls"
        retry_output = await retry_with_clarification(conversation, reason, ollama_out_clean)
        logger.info(retry_output)

        if retry_output.lower() == REQUIRED_OUT_OF_SCOPE_MSG.lower():
            error_payload={
                "output_text": retry_output
            }

            logger.info(error_payload)

            return jsonify(error_payload)

        try:
            parsed = json.loads(retry_output)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", retry_output, re.S)
            if match:
                try:
                    parsed = json.loads(match.group())
                except Exception as e:
                    logger.warning(f"Retry also failed to parse JSON: {e}")

    # After retry, try tool call(s) handling
    # Support multiple tool calls by accepting a JSON array of {"name":..., "arguments": {...}} objects
    tool_calls = []

    if isinstance(parsed, dict) and "name" in parsed and is_valid_arguments(parsed):
        tool_calls = [parsed]
    elif isinstance(parsed, list):
        # Filter only valid tool call dicts
        for item in parsed:
            if isinstance(item, dict) and "name" in item and is_valid_arguments(item):
                tool_calls.append(item)
            else:
                logger.warning(f"Skipping invalid tool call item: {item}")
    else:
        logger.warning("Model did not return a valid tool call after retry.")
        final_output = REQUIRED_OUT_OF_SCOPE_MSG

    # Execute each tool call (if any)
    if tool_calls:
        # For each tool call, find which MCP server provides it and call it
        for tc in tool_calls:
            tool_name = tc.get("name") 
            server_url = None
            server_label = None
            for ts in tool_schemas:
                if ts["schema"]["name"] == tool_name:
                    server_url = ts["server_url"]
                    server_label = ts["server_label"]
                    break

            if server_url:
                try:
                    result = await call_mcp(server_url=server_url, tool_call=tc)
                    tool_outputs.append({"tool": tool_name, "server": server_label, "server_url": server_url, "output": result})
                except Exception as e:
                    logger.exception(f"Error calling MCP tool {tool_name} on {server_url}: {e}")
                    tool_outputs.append({"tool": tool_name, "server": server_label, "server_url": server_url, "error": str(e)})
            else:
                logger.warning(f"No server found exposing tool `{tool_name}`; marking as out-of-scope")
                tool_outputs.append({"tool": tool_name, "error": "Tool not available on known MCP servers"})

        final_output = json.dumps(tool_outputs)

    response_payload['id'] = f"resp:{user}:{server_url}:{(tool_calls[0].get('name') if tool_calls else 'none')}:"
    response_payload['user_msg'] = user_input
    response_payload['output_text'] = final_output
    response_payload['tool_outputs'] = tool_outputs
    response_payload['tool_calls'] = tool_calls
    response_payload['tool_instructions'] = tool_instructions
    response_payload['ollama_out_clean'] = ollama_out_clean

    logger.info(response_payload)

    return jsonify(response_payload)

@app.route('/v1/analysis', methods=['POST'])
async def analysis():
    data = await request.get_json()
    model = data.get("model")
    instructions = data.get("instructions")
    message = data.get("message")
    name = data.get('name')

    # --- Step C: Send conversation to Ollama ---
    conversation = [
        {"role": "system", "content": instructions},
        {"role": "user", "content": message},
    ]

    ollama_out_clean = await chat_with_ollama(conversation, model)
    
    response_payload={
            "id": f"bot:analysis:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
            "user_msg": message,
            "output_text": ollama_out_clean
        }

    logger.info(response_payload)
    
    parsed = None
    try:
        parsed = json.loads(ollama_out_clean)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", ollama_out_clean, re.S)
        if match:
            try:
                parsed = json.loads(match.group())
            except Exception as e:
                logger.warning(f"Could not parse JSON block: {e}")

    return parsed

@app.route('/v1/stats', methods=['GET'])
async def get_stats():
    """Get RAG engine statistics"""
    stats = await rag_engine.get_collection_stats()
    return jsonify({
            "stats": stats
        }), 200
   
@app.route('/v1/ingest', methods=['POST'])
async def ingest_tool_output():
    """
    Ingest network tool output
    
    Body:
    {
        "tool_type": "nmap|tcpdump|traceroute|iperf|tshark|pcap",
        "output": "raw tool output",
        "metadata": {
            "prb_id": "probe-01",
            "target": "192.168.1.1",
            "timestamp": "2026-02-05T12:00:00Z"
        }
    }
    """
    data = await request.get_json()
    if not data:
        return jsonify(), 400
        
    tool_type = data.get('tool_type')
    parsed_output = data.get('parsed_output')
    raw_output = data.get('output')
    metadata = data.get('metadata', {})
    prb_id = metadata.get('prb_id')
        
    if not tool_type or not parsed_output:
        return jsonify(), 400
        
    if 'timestamp' not in metadata:
        metadata['timestamp'] = datetime.now(timezone.utc).isoformat()
        
    metadata['tool_type'] = tool_type
        
    doc_id = f"prbtool:{prb_id}:{tool_type}:{metadata.get('timestamp')}:{str(uuid.uuid4())}"
        
    content = f"Tool: {tool_type}\n"
    content += f"Timestamp: {metadata.get('timestamp')}\n"
    content += f"Probe: {metadata.get('prb_id', 'N/A')}\n"
    content += f"Target: {metadata.get('target', 'N/A')}\n\n"
    content += f"Raw Output:\n{raw_output}\n\n"
        
    if parsed_output.get('anomalies'):
        content += f"Detected Anomalies:\n{json.dumps(parsed_output['anomalies'], indent=2)}\n"

    if await rag_engine.ingest_document(doc_id, content, metadata) is True:

        if await cl_data_db.upload_db_data(
                id=doc_id,
                data={
                    "tool_type": tool_type,
                    "timestamp": metadata.get('timestamp'),
                    "parsed": json.dumps(parsed_output),
                    "has_anomalies": len(parsed_output.get('anomalies', [])) > 0
                }
            ) is not None:
                return jsonify(), 200
        else:
            logger.error("Failed to upload data to Redis after successful RAG ingestion")
            return jsonify(), 500
    else:
        logger.error("Failed to ingest document into RAG engine")
        return jsonify(), 500
    
@app.route('/v1/ingest/batch', methods=['POST'])
async def ingest_batch():
    """
    Batch ingest multiple tool outputs
    
    Body:
    {
        "documents": [
            {
                "tool_type": "nmap",
                "output": "...",
                "metadata": {
                    "prb_id": "probe-01",
                    "timestamp": "2026-02-05T12:00:00Z"
                    }
            },
            ...
        ]
    }
    """
    data = await request.get_json()
    documents = data.get('documents')
        
    if not documents:
        return jsonify(), 400
        
    processed_docs = []
    parsed_docs = json.loads(documents)
    for doc in parsed_docs:
        tool_type = doc.get('tool_type')
        output = doc.get('output')
        metadata = doc.get('metadata')
        prb_id = metadata.get('prb_id')
        content = doc.get('content')
            
        if not tool_type or not output:
            continue
            
        if 'timestamp' not in metadata:
            metadata['timestamp'] = datetime.now(timezone.utc).isoformat()
            
        doc_id = f"prbtool:{prb_id}:{tool_type}:{metadata.get('timestamp')}:{str(uuid.uuid4())}"
            
        processed_docs.append({
                'id': doc_id,
                'content': content,
                'metadata': metadata
            })
        
    count = await rag_engine.ingest_batch(processed_docs)

    if count is None or count == 0:
        return jsonify(), 400
        
    return jsonify({
            "ingested_count": count,
            "total_submitted": len(documents)
        }), 200
    
@app.route('/v1/query', methods=['POST'])
async def query_rag():
    """
    Query the RAG system
    
    Body:
    {
        "query": "Show me recent port scans",
        "n_results": 5,
        "filter": {"tool_type": "nmap"}
    }
    """
    data = await request.get_json()
        
    query = data.get('query')
    n_results = data.get('n_results', 5)
    where_filter = data.get('filter')
        
    if not query:
        return jsonify(), 400
        
    result = await rag_engine.rag_query(query, n_results, where_filter)
        
    return jsonify({
            "result": result
        }), 200
    
@app.route('/v1/analyze', methods=['POST'])
async def analyze_output():
    """
    Analyze tool output for anomalies without ingesting
    
    Body:
    {
        "tool_type": "tcpdump",
        "output": "raw output",
        "metadata": {...}
    }
    """
    data = await request.get_json()
        
    tool_type = data.get('tool_type')
    output = data.get('output')
    metadata = data.get('metadata', {})
        
    if not tool_type or not output:
        return jsonify(), 400
        
    metadata['tool_type'] = tool_type
    metadata['timestamp'] = metadata.get('timestamp', datetime.now(timezone.utc).isoformat())
        
    content = f"Tool: {tool_type}\n{output}"
        
    anomaly_result = await rag_engine.detect_anomalies(content, metadata)
        
    return jsonify({
            "rag_analysis": anomaly_result
        }), 200
    
@app.route('/v1/process', methods=['POST'])
async def process_and_act():
    """
    Complete pipeline: ingest, analyze, decide action, optionally execute
    
    Body:
    {
        "tool_type": "nmap",
        "output": "...",
        "metadata": {...},
        "available_tools": ["send_email_alert", "create_jira_ticket"],
        "auto_execute": false
    }
    
    or

    Body:
    {
        "documents": [
            {
                "tool_type": "nmap",
                "output": "...",
                "metadata": {...},
                "available_tools": ["send_email_alert", "create_jira_ticket"],
                "auto_execute": false
            },
            ...
        ]
    }
    """
    data = await request.get_json()

    documents = data.get('documents')
    if documents:
        results = await rag_engine.batched_process_and_act(documents)
        if not results:
            return jsonify(), 500
        return jsonify({
                "data": results
            }), 200

    tool_type = data.get('tool_type')
    output = data.get('output')
    metadata = data.get('metadata')
    available_tools = data.get('available_tools')
    auto_execute = data.get('auto_execute', False)
            
    if not tool_type or not output:
        return jsonify(), 400
            
    metadata['tool_type'] = tool_type
    metadata['timestamp'] = metadata.get('timestamp', datetime.now(timezone.utc).isoformat())
            
    content = f"Tool: {tool_type}\nTimestamp: {metadata['timestamp']}\n\n{output}"
            
    result = await rag_engine.process_and_act(
        content,
        metadata,
        available_tools,
        auto_execute
    )
        
    if not result:
        return jsonify(), 500
        
    return jsonify({
                "data": result,
                "db_id": f"processed-{tool_type}-{metadata['timestamp']}-{str(uuid.uuid4())}" 
            }), 200
    
@app.route('/v1/history', methods=['GET'])
async def get_history():
    """
    Get ingestion history from Redis
    
    Query params:
    - tool_type: Filter by tool type
    - has_anomalies: Filter by anomaly presence (true/false)
    """
    tool_type = request.args.get('tool_type')
    has_anomalies = request.args.get('has_anomalies')
        
    if tool_type:
        pattern = f"{tool_type}_*"
    else:
        pattern = "*"
        
    all_data = await cl_data_db.get_all_data(match=pattern)
        
    if not all_data:
        return jsonify(), 200
        
    history = []
    for doc_id, data in all_data.items():
        if has_anomalies is not None:
            has_anom = data.get('has_anomalies', 'False') == 'True'
            filter_anom = has_anomalies.lower() == 'true'
            if has_anom != filter_anom:
                continue
            
        history.append({
                "document_id": doc_id,
                "tool_type": data.get('tool_type'),
                "timestamp": data.get('timestamp'),
                "has_anomalies": data.get('has_anomalies') == 'True'
            })
        
    return jsonify({
            "count": len(history),
            "history": history
        }), 200