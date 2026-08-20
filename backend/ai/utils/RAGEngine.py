import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import json
from typing import List, Dict, Any, Optional
from init_app import call_mcp, logger, chat_with_ollama

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
        query_text: str,
        n_results: int = 5,
        where_filter: Optional[Dict] = None
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
            where=where_filter
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
        response = await chat_with_ollama(conversation=messages, model=self.ollama_model)
        if not response:
            logger.error("LLM analysis failed: No response received")
            return None
        return response
    
    async def rag_query(
        self,
        query: str,
        n_results: int = 3,
        where_filter: Optional[Dict] = None
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
        similar_results = await self.query_similar(query, n_results, where_filter)
        
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
        analysis = await self.analyze_with_llm(context, query)
        
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
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        
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
        anomaly_prompt = f"""Analyze the following {metadata.get('flow')} automation workflow network tools output for anomalies, security issues, 
        or unusual patterns. Compare it with historical data if available.

        Current Output:
        {content}

        Historical Similar Patterns:
        {historical_context}

        Identify:
        1. Any security threats (port scans, suspicious traffic, etc.)
        2. Performance issues (packet loss, high latency, etc.)
        3. Configuration problems
        4. Anomalies compared to historical patterns
        5. Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)

        Provide your analysis in JSON format with keys: severity, anomalies (list), recommendations (list)"""
        
        analysis = await self.analyze_with_llm(historical_context, anomaly_prompt)
        
        # Try to parse JSON response
        try:
            # Extract JSON from markdown code blocks if present
            if "```json" in analysis:
                analysis = analysis.split("```json")[1].split("```")[0].strip()
            elif "```" in analysis:
                analysis = analysis.split("```")[1].split("```")[0].strip()
            
            anomaly_data = json.loads(analysis)
        except json.JSONDecodeError:
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
    
    async def decide_action(
        self,
        anomaly_result: Dict[str, Any],
        available_tools: str
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
        Anomalies Found: {json.dumps(anomalies, indent=2)}
        
        Available MCP Tools: \n{available_tools}\n\n
        
        Decide:
        1. Should an alert be sent? (yes/no)
        2. Which alert channels? (email, slack, jira, etc.)
        3. Should any automated remediation be attempted?
        4. What MCP tools should be called and with what parameters?
        
        Respond in JSON format with keys: send_alert (bool), alert_channels (list), 
        remediation_needed (bool), mcp_actions (list of dicts with tool and params)"""
        
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
    
    async def batch_content_processing(self, content: str,  metadata: Dict[str, Any], available_tools: str = None):
        anomaly_result = await self.detect_anomalies(content, metadata)                
        action_decision = await self.decide_action(anomaly_result, available_tools)
        return action_decision

    async def execute(self, action_decision: Dict[str, Any], auto_execute: bool = False):
        execution_results = []
        if auto_execute is True and action_decision.get('mcp_actions'):
            for action in action_decision['mcp_actions']:
                tool_name = action.get('tool')
                params = action.get('params', {})
                if tool_name:
                    result = await call_mcp(server_url=self.mcp_server_url, tool_call={"name": tool_name, "arguments": params})
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