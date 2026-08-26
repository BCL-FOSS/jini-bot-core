import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import json
import re
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from init_app import call_mcp, logger, chat_with_ollama, web_client

class RAGEngine:
    def __init__(
        self,
        collection_name: str = "network_analysis",
        embedding_model: str = "all-MiniLM-L6-v2",
        ollama_model: str = "qwen3:1.7b",
        mcp_server_url: str = None
    ):
        """
        RAG Engine for network analysis with ChromaDB and Ollama
        
        Args:
            collection_name: ChromaDB collection name
            embedding_model: HuggingFace model for embeddings
            ollama_model: Ollama model for LLM inference
            mcp_server_url: URL of the MCP server for tool execution
        """
        self.collection_name = collection_name
        self.ollama_model = ollama_model
        self.mcp_server_url = mcp_server_url
        
        # Initialize embedding model
        logger.info(f"Loading embedding model: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)

    async def init_chroma_db(self):
        self.chroma_client = await chromadb.AsyncHttpClient(host="localhost", port=6000)
       
        try:
            self.collection = await self.chroma_client.get_collection(name=self.collection_name)
            logger.info(f"Loaded existing collection: {self.collection_name}")
        except Exception:
            self.collection = await self.chroma_client.create_collection(
                name=self.collection_name,
                metadata={"description": "Network tool analysis and anomaly detection"}
            )
            logger.info(f"Created new collection: {self.collection_name}")
    
    def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding vector for text"""
        embedding = self.embedding_model.encode(text, convert_to_tensor=False)
        return embedding.tolist()
    
    async def ingest_document(
        self,
        doc_id: str,
        content: str,
        metadata: Dict[str, Any]
    ) -> bool:
        """
        Ingest a network tool output document into ChromaDB
        
        Args:
            doc_id: Unique document identifier
            content: The network tool output text
            metadata: Additional metadata (tool_type, timestamp, probe, etc.)
        
        Returns:
            bool: Success status
        """
        embedding = self.generate_embedding(content)
            
        await self.collection.add(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[content],
                metadatas=[metadata]
            )
            
        logger.info(f"Ingested document: {doc_id} (tool: {metadata.get('tool_type')})")
        return True
    
    async def ingest_batch(
        self,
        documents: List[Dict[str, Any]]
    ) -> int:
        """
        Batch ingest multiple documents
        
        Args:
            documents: List of dicts with 'id', 'content', and 'metadata'
        
        Returns:
            int: Number of successfully ingested documents
        """
        ids = []
        embeddings = []
        contents = []
        metadatas = []
        
        for doc in documents:
            try:
                embedding = self.generate_embedding(doc['content'])
                ids.append(doc['id'])
                embeddings.append(embedding)
                contents.append(doc['content'])
                metadatas.append(doc['metadata'])
            except Exception as e:
                logger.error(f"Error processing document {doc.get('id')}: {e}")
                continue
        
        if ids:
            try:
                await self.collection.add(
                    ids=ids,
                    embeddings=embeddings,
                    documents=contents,
                    metadatas=metadatas
                )
                logger.info(f"Batch ingested {len(ids)} documents")
                return len(ids)
            except Exception as e:
                logger.error(f"Error in batch ingestion: {e}", exc_info=True)
                return 0
        
        return 0
    
    async def query_similar(
        self,
        query_text: Optional[str],
        n_results: Optional[int] = 5,
        where_filter: Optional[Dict] = None,
        where_doc_filter: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Query for similar network patterns
        
        Args:
            query_text: Text to search for
            n_results: Number of results to return
            where_filter: Metadata filter (e.g., {"tool_type": "nmap"})
        
        Returns:
            Dict with results
        """
        query_embedding = self.generate_embedding(query_text)
            
        results = await self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where_filter,
            where_document=where_doc_filter
        )

        if not results:
            logger.info("No similar documents found")
            return {"query": query_text, "results": None, "count": 0}
            
        return {
            "query": query_text,
            "results": results,
            "count": len(results['ids'][0]) if results['ids'] else 0
        }
       
    async def analyze_with_llm(
        self,
        context: str,
        query: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Use Ollama LLM to analyze network data with RAG context
        
        Args:
            context: Retrieved context from vector DB
            query: User query or analysis request
            system_prompt: Optional system prompt
        
        Returns:
            str: LLM analysis result
        """
        if system_prompt is None:
            system_prompt = """You are an expert network security analyst. Analyze network tool outputs, 
            identify anomalies, security issues, and performance problems. Provide actionable insights 
            and recommend appropriate responses."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Context:\n{context}\n\nQuery: {query}"}
        ]
        response = await chat_with_ollama(conversation=messages, model=self.ollama_model, conn_obj=web_client)
        if not response:
            logger.error("LLM analysis failed: No response received")
            return None
        return response
    
    async def rag_query(
        self,
        prompt: str,
        query: Optional[str],
        n_results: Optional[int] = 3,
        where_filter: Optional[Dict] = None,
        where_doc_filter: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Full RAG query: retrieve similar docs and analyze with LLM
        
        Args:
            query: Analysis query
            n_results: Number of similar docs to retrieve
            where_filter: Metadata filter
        
        Returns:
            Dict with retrieved docs and LLM analysis
        """
        # Retrieve similar documents
        similar_results = await self.query_similar(query, n_results, where_filter, where_doc_filter=where_doc_filter)
        
        if not similar_results.get('results') or not similar_results['results']['documents']:
            return {
                "query": query,
                "retrieved_docs": [],
                "analysis": "No relevant documents found in the database."
            }
        
        # Build context from retrieved documents
        docs = similar_results['results']['documents'][0]
        metadatas = similar_results['results']['metadatas'][0]
        
        context_parts = []
        for doc, meta in zip(docs, metadatas):
            tool_type = meta.get('tool_type', 'unknown')
            timestamp = meta.get('timestamp', 'unknown')
            context_parts.append(f"[{tool_type} - {timestamp}]\n{doc}\n")
        
        context = "\n---\n".join(context_parts)
        
        # Analyze with LLM
        analysis = await self.analyze_with_llm(context, prompt)
        
        return {
            "query": query,
            "retrieved_docs": [
                {"content": doc, "metadata": meta} 
                for doc, meta in zip(docs, metadatas)
            ],
            "analysis": analysis
        }
    
    async def detect_anomalies(
        self,
        content: str,
        metadata: Dict[str, Any],
        detect_type: int,
        available_tools: str = None,
        user_prompt: str = None,
        site: str = None,
        prb_id: str = None,
        prb_name: str = None
    ) -> Dict[str, Any] | Tuple[List[Dict[str, Any]], str]:
        
        similar = await self.query_similar(
            content,
            n_results=5,
            where_filter=metadata
        )
        
        if similar['results'] and similar['results']['documents']:
            historical_docs = similar['results']['documents'][0][:3]
            historical_context = "\n---\n".join(historical_docs)
        else:
            historical_context = "No historical data available."

        
        # LLM analysis for anomaly detection
        anomaly_prompt = f"""Analyze the following {metadata.get('flow')} automation workflow network tools output for anomalies, security issues, or unusual patterns. Compare it with historical data if available.

        Current Output:
        {content}

        Historical Similar Patterns:
        {historical_context}
        \n
        """
        if user_prompt is not None:
            anomaly_prompt+=f"Scope your analysis according to the specifications and inquiries in the following user prompt: {user_prompt}.\n\n"
        else:
            anomaly_prompt+="""
            Identify:
            1. Any security threats (port scans, suspicious traffic, etc.)
            2. Performance issues (packet loss, high latency, etc.)
            3. Configuration problems
            4. Anomalies compared to historical patterns
            5. Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO) 
            \n\n
            """

        match detect_type:
            case 0:
                anomaly_prompt+= "Provide your analysis in JSON format with keys: severity, anomalies (list), recommendations (list)"

            case 1:
                anomaly_prompt+= f"""Provide your analysis in text format identifying all anomalies identified and recommendations using the following available tools. Format this response in the form of a report (with proper headers, labels etc.): \n{available_tools}
                """
            case 2:
                anomaly_prompt+=(
                    """Provide your analysis as a tuple of two objects:\n 
                    First objects: list of JSON objects for each identified anomaly, security issue, and unusual pattern, with each JSON object in the following format:\n"""
                    "{'alert_type': '', 'name': '', 'site': '', status: 'unresolved', timestamp: '', id: '', prb_id: '', ack: 'unseen', rslv: 'unresolved', msg: '', severity: ''}\n"
                    f"{site} will be used to fill out the 'site' keys for all created JSON objects\n"
                    f"{prb_id} will be used to fill out the 'prb_id' keys for all created JSON objects\n"
                    f"{prb_name} will be used to fill out the 'name' keys for all created JSON objects\n"
                    "You will generate the data for the following keys in each JSON object 'alert_type' (provide a title), 'timestamp' (provide a timestamp in ISO format), 'msg' (provide a brief summary of the identified anomaly, security issue or unusual pattern), 'severity' (provide the severity level)\n\n"
                    "Second object: A text summary of the anomalies, security issues, or unusual patterns identified during analysis. It shoudlexpand deeper on the summary provided in the list of JSON objects for each alert, and provide any suggestions for remediation, improvement and/or potential configuration changes. Format this response in the form of a text only analysis report (with proper headers, labels etc.)"
                    )
        
        analysis = await self.analyze_with_llm(context=historical_context, query=anomaly_prompt)

        if analysis is None:
            logger.error("Anomaly detection failed: the LLM returned no response")
            if detect_type == 2:
                return [], "Analysis unavailable: the language model returned no response."
            return {
                "anomaly_data": {
                    "severity": "UNKNOWN",
                    "anomalies": ["The language model returned no response"],
                    "recommendations": []
                },
                "similar_patterns_found": similar['count']
            }

        # detect_type 2 asks the model for a (list of alert objects, report text)
        # pair, so it needs its own parser rather than the plain JSON path.
        if detect_type == 2:
            return self._parse_alert_report(
                analysis,
                defaults={
                    'site': site,
                    'prb_id': prb_id,
                    'name': prb_name,
                    'flow': metadata.get('flow') if metadata else None
                }
            )

        # detect_type 1 asks for a formatted text report; there is no JSON to
        # find, so skip the parse instead of failing into the fallback branch.
        if detect_type == 1:
            return {
                "anomaly_data": {"report": analysis},
                "similar_patterns_found": similar['count']
            }

        try:
            anomaly_data = json.loads(self._strip_code_fences(analysis))
        except (json.JSONDecodeError, TypeError):
            # Fallback to text analysis
            anomaly_data = {
                "severity": "UNKNOWN",
                "anomalies": ["Unable to parse structured response"],
                "recommendations": [],
                "raw_analysis": analysis
            }

        return {
            "anomaly_data": anomaly_data,
            "similar_patterns_found": similar['count']
        }

    @staticmethod
    def _strip_code_fences(text: str) -> str:
        """Return the contents of the first fenced block, or the text as-is."""
        if not isinstance(text, str):
            return text
        if "```json" in text:
            return text.split("```json", 1)[1].split("```", 1)[0].strip()
        if "```" in text:
            parts = text.split("```")
            if len(parts) >= 3:
                return parts[1].strip()
        return text.strip()

    def _parse_alert_report(self, analysis: str, defaults: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str]:
        """Split a detect_type 2 response into (alert objects, report text).

        Models are inconsistent about how they return "a tuple of two objects",
        so several shapes are accepted:

          * a JSON array followed by prose
          * a JSON object with alerts/report style keys
          * a Python-looking tuple: ([{...}, {...}], "report")
          * prose only, with no alerts at all

        Anything unparseable degrades to (no alerts, raw text) rather than
        raising — an unusable LLM response must not break the ingest pipeline.
        """
        text = self._strip_code_fences(analysis)
        alerts: List[Dict[str, Any]] = []
        report = ""

        # When the model fences the alert array and writes the report outside
        # the fence, the stripped block holds only the array — keep the prose
        # around it so the report is not silently discarded.
        outside_fence = ""
        if isinstance(analysis, str) and "```" in analysis:
            segments = analysis.split("```")
            # even-indexed segments sit outside the fences
            outside_fence = " ".join(
                seg.strip() for i, seg in enumerate(segments) if i % 2 == 0 and seg.strip()
            ).strip()

        # 1. A single JSON document containing both halves.
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            parsed = None

        if isinstance(parsed, list):
            alerts, report = parsed, outside_fence
        elif isinstance(parsed, dict):
            for key in ('alerts', 'anomalies', 'first', 'first_object', 'objects'):
                if isinstance(parsed.get(key), list):
                    alerts = parsed[key]
                    break
            for key in ('report', 'summary', 'analysis', 'second', 'second_object', 'text'):
                if isinstance(parsed.get(key), str):
                    report = parsed[key]
                    break
            if not alerts and not report:
                alerts = [parsed]

        # 2. Otherwise locate the JSON array and treat the remainder as prose.
        if not alerts and not report:
            start = text.find('[')
            if start != -1:
                depth, end, in_str, esc = 0, -1, False, False
                for i in range(start, len(text)):
                    ch = text[i]
                    if in_str:
                        if esc:
                            esc = False
                        elif ch == '\\':
                            esc = True
                        elif ch == '"':
                            in_str = False
                        continue
                    if ch == '"':
                        in_str = True
                    elif ch == '[':
                        depth += 1
                    elif ch == ']':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                if end != -1:
                    candidate = text[start:end]
                    try:
                        alerts = json.loads(candidate)
                    except json.JSONDecodeError:
                        # Models often emit single quotes, as the prompt example does.
                        try:
                            alerts = json.loads(re.sub(r"(?<![A-Za-z0-9])'([^']*)'", r'"\1"', candidate))
                        except json.JSONDecodeError:
                            logger.warning("Could not decode the alert array from the LLM response")
                            alerts = []
                    report = (text[:start] + text[end:]).strip() or outside_fence
                else:
                    report = text
            else:
                report = text

        if not isinstance(alerts, list):
            alerts = [alerts] if isinstance(alerts, dict) else []

        # Strip tuple punctuation left over from a "( [...], "..." )" answer.
        report = report.strip().lstrip('(').rstrip(')').strip().strip(',').strip()
        if report.startswith('"') and report.endswith('"') and len(report) > 1:
            report = report[1:-1]

        normalised = [self._normalise_alert(a, defaults) for a in alerts if isinstance(a, dict)]
        return normalised, report

    @staticmethod
    def _normalise_alert(alert: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
        """Fill in the fields the GUI and the alerts store rely on.

        The model is asked to echo site/prb_id/name back, but it frequently
        omits them or invents placeholders, so trusted values always win.
        """
        out = dict(alert)

        out['site'] = defaults.get('site') or out.get('site') or 'unknown'
        out['prb_id'] = defaults.get('prb_id') or out.get('prb_id') or ''
        out['name'] = defaults.get('name') or out.get('name') or out['prb_id']

        out['alert_type'] = str(out.get('alert_type') or defaults.get('flow') or 'Anomaly')
        out['msg'] = str(out.get('msg') or out.get('message') or '')
        out['severity'] = str(out.get('severity') or 'INFO').upper()

        # These three drive the GUI's status icons; the model must not set them.
        out['status'] = 'unresolved'
        out['ack'] = 'unseen'
        out['rslv'] = 'unresolved'

        timestamp = out.get('timestamp')
        if not isinstance(timestamp, str) or not timestamp.strip():
            timestamp = datetime.now(tz=timezone.utc).isoformat()
        out['timestamp'] = timestamp

        # A model-invented id risks collisions and key injection, so the id is
        # always generated here.
        out['id'] = f"alert:{out['prb_id'] or 'unknown'}:{uuid.uuid4()}"
        return out

    async def decide_action(
        self,
        anomaly_result: Dict[str, Any],
        available_tools: str = None
    ) -> Dict[str, Any]:
        """
        Decide what action to take based on anomaly detection
        
        Args:
            anomaly_result: Result from detect_anomalies
            available_tools: List of available MCP tool names
        
        Returns:
            Dict with recommended actions
        """
        severity = anomaly_result.get('anomaly_data', {}).get('severity', 'UNKNOWN')
        anomalies = anomaly_result.get('anomaly_data', {}).get('anomalies', [])
        
        decision_prompt = f"""Based on the following anomaly detection results, decide what actions to take.

        Severity: {severity}
        Anomalies Found: {json.dumps(anomalies, indent=2)}\n\n
              
        Decide:
        1. Should an alert be sent? (yes/no)
        2. Which alert channels? (email, slack, jira, etc.)
        3. Should any automated remediation be attempted?
        4. What MCP tools should be called and with what parameters?
        
        Respond in JSON format with keys: send_alert (bool), alert_channels (list), 
        remediation_needed (bool), mcp_actions (list of dicts with tool and params)\n\n"""

        if available_tools is not None:
            decision_prompt+=f"Available MCP Tools: \n{available_tools}\n\n"
        
        decision = await self.analyze_with_llm("", decision_prompt)
        
        # Parse decision
        try:
            if "```json" in decision:
                decision = decision.split("```json")[1].split("```")[0].strip()
            elif "```" in decision:
                decision = decision.split("```")[1].split("```")[0].strip()
            
            decision_data = json.loads(decision)
        except json.JSONDecodeError:
            # Default safe action for critical/high severity
            if severity in ['CRITICAL', 'HIGH']:
                decision_data = {
                    "send_alert": True,
                    "alert_channels": ["email", "slack"],
                    "remediation_needed": False,
                    "mcp_actions": [],
                    "raw_decision": decision
                }
            else:
                decision_data = {
                    "send_alert": False,
                    "alert_channels": [],
                    "remediation_needed": False,
                    "mcp_actions": [],
                    "raw_decision": decision
                }
        
        return decision_data
    
    async def batch_content_processing(self, payload: Dict[str, Any] = None, **kwargs):
        """Run anomaly detection for a batch.

        Accepts the request body as a single dict (which is how the endpoint
        calls it) or as keyword arguments. The previous signature was
        **kwargs-only, so `batch_content_processing(data)` raised
        TypeError: takes 1 positional argument but 2 were given.
        """
        params = dict(payload or {})
        params.update(kwargs)

        try:
            detect_type = int(params.get('detect_type', 0))
        except (TypeError, ValueError):
            logger.warning(f"Invalid detect_type {params.get('detect_type')!r}; defaulting to 0")
            detect_type = 0

        anomaly_result = await self.detect_anomalies(
            content=params.get('content'),
            metadata=params.get('metadata') or {},
            available_tools=params.get('available_tools'),
            detect_type=detect_type,
            user_prompt=params.get('prompt'),
            site=params.get('site'),
            prb_name=params.get('prb_name'),
            prb_id=params.get('prb_id')
        )

        if detect_type == 0:
            return await self.decide_action(anomaly_result, params.get('available_tools'))

        return anomaly_result

    async def execute(self, action_decision: Dict[str, Any], auto_execute: bool = False):
        execution_results = []
        if auto_execute is True and action_decision.get('mcp_actions'):
            for action in action_decision['mcp_actions']:
                tool_name = action.get('tool')
                params = action.get('params', {})
                if tool_name:
                    result = await call_mcp(server_url=self.mcp_server_url, tool_call={"name": tool_name, "arguments": params}, conn_obj=web_client)
                    if result is None:
                        logger.error(f"Failed to execute MCP tool: {tool_name} with params: {params}")
                        return None
                    execution_results.append({
                        "tool": tool_name,
                        "params": params,
                        "result": result
                    }) 
            return {      
                    "action_decision": action_decision,
                    "execution_results": execution_results if execution_results else None
                }
    
    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the ChromaDB collection"""
        count = await self.collection.count()
        if not count:
            return None
        return {
            "collection_name": self.collection_name,
            "total_documents": count,
            "embedding_model": self.embedding_model.get_embedding_dimension()
        }