import asyncio
import os
import json
import re
from typing import Any, Dict, List, Optional, Union
from mitmproxy import io

from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Directory where mitmproxy dump files are stored
DUMP_DIR = "/Users/lucas/Coding/mitmproxy-mcp/dumps"

server = Server("mitmproxy-mcp")

# Cache for storing flows per session
FLOW_CACHE = {}

# Maximum content size in bytes before switching to structure preview
MAX_CONTENT_SIZE = 10000

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available tools.
    Each tool specifies its arguments using JSON Schema validation.
    """
    return [
        types.Tool(
            name="list_flows",
            description="List HTTP flows in a session",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The ID of the session to list flows from"
                    }
                },
                "required": ["session_id"]
            }
        ),
        types.Tool(
            name="get_flow_details",
            description="Get details of specific flows in a session",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The ID of the session"
                    },
                    "flow_indexes": {
                        "type": "array",
                        "items": {
                            "type": "integer"
                        },
                        "description": "The indexes of the flows"
                    },
                    "include_content": {
                        "type": "boolean",
                        "description": "Whether to include full content in the response (default: true)",
                        "default": true
                    }
                },
                "required": ["session_id", "flow_indexes"]
            }
        ),
        types.Tool(
            name="extract_json_fields",
            description="Extract specific fields from JSON content in a flow using JSONPath expressions",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The ID of the session"
                    },
                    "flow_index": {
                        "type": "integer",
                        "description": "The index of the flow"
                    },
                    "content_type": {
                        "type": "string",
                        "enum": ["request", "response"],
                        "description": "Whether to extract from request or response content"
                    },
                    "json_paths": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "JSONPath expressions to extract (e.g. ['$.data.users', '$.metadata.timestamp'])"
                    }
                },
                "required": ["session_id", "flow_index", "content_type", "json_paths"]
            }
        )
    ]

async def get_flows_from_dump(session_id: str) -> list:
    """
    Retrieves flows from the dump file, using the cache if available.
    """
    dump_file = os.path.join(DUMP_DIR, f"{session_id}.dump")
    if not os.path.exists(dump_file):
        raise FileNotFoundError("Session not found")

    if session_id in FLOW_CACHE:
        return FLOW_CACHE[session_id]
    else:
        with open(dump_file, "rb") as f:
            reader = io.FlowReader(f)
            flows = list(reader.stream())
        FLOW_CACHE[session_id] = flows
        return flows

async def list_flows(arguments: dict) -> list[types.TextContent]:
    """
    Lists HTTP flows from a mitmproxy dump file.
    """
    session_id = arguments.get("session_id")
    if not session_id:
        return [types.TextContent(type="text", text="Error: Missing session_id")]

    try:
        flows = await get_flows_from_dump(session_id)

        flow_list = []
        for i, flow in enumerate(flows):
            if flow.type == "http":
                request = flow.request
                response = flow.response
                flow_info = {
                    "index": i,
                    "method": request.method,
                    "url": request.url,
                    "status": response.status_code if response else None
                }
                flow_list.append(flow_info)

        return [types.TextContent(type="text", text=json.dumps(flow_list, indent=2))]
    except FileNotFoundError:
        return [types.TextContent(type="text", text="Error: Session not found")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error reading flows: {str(e)}")]

def generate_json_structure(json_data: Any, max_depth: int = 2, current_depth: int = 0) -> Any:
    """
    Generate a simplified structure of JSON content, showing keys and types
    but replacing actual values with type indicators after a certain depth.
    """
    if current_depth >= max_depth:
        if isinstance(json_data, dict):
            return {"...": f"{len(json_data)} keys"}
        elif isinstance(json_data, list):
            return f"[{len(json_data)} items]"
        else:
            return f"({type(json_data).__name__})"
    
    if isinstance(json_data, dict):
        result = {}
        for key, value in json_data.items():
            result[key] = generate_json_structure(value, max_depth, current_depth + 1)
        return result
    elif isinstance(json_data, list):
        if not json_data:
            return []
        # For lists, show structure of first item and count
        sample = generate_json_structure(json_data[0], max_depth, current_depth + 1)
        return [sample, f"... ({len(json_data)-1} more items)"] if len(json_data) > 1 else [sample]
    else:
        return f"({type(json_data).__name__})"

def parse_json_content(content: bytes, headers: dict) -> Union[Dict, str, bytes]:
    """
    Attempts to parse content as JSON if the content type indicates JSON.
    Returns the parsed JSON or the raw content if parsing fails.
    """
    content_type = headers.get("Content-Type", "").lower() if headers else ""
    
    if "application/json" in content_type or "text/json" in content_type:
        try:
            return json.loads(content.decode(errors="ignore"))
        except json.JSONDecodeError:
            return content.decode(errors="ignore")
    return content.decode(errors="ignore")

def extract_with_jsonpath(json_data: Any, path: str) -> Any:
    """
    Basic implementation of JSONPath extraction.
    Supports simple dot notation and array indexing.
    For more complex cases, consider using a full JSONPath library.
    """
    # Handle root object reference
    if path == "$":
        return json_data
    
    # Strip leading $ if present
    if path.startswith("$"):
        path = path[1:]
    if path.startswith("."):
        path = path[1:]
        
    parts = []
    # Parse the path - handle both dot notation and brackets
    current = ""
    in_brackets = False
    for char in path:
        if char == "[":
            if current:
                parts.append(current)
                current = ""
            in_brackets = True
        elif char == "]":
            if in_brackets:
                try:
                    # Handle array index
                    parts.append(int(current.strip()))
                except ValueError:
                    # Handle quoted key
                    quoted = current.strip()
                    if (quoted.startswith("'") and quoted.endswith("'")) or \
                       (quoted.startswith('"') and quoted.endswith('"')):
                        parts.append(quoted[1:-1])
                    else:
                        parts.append(quoted)
                current = ""
                in_brackets = False
        elif char == "." and not in_brackets:
            if current:
                parts.append(current)
                current = ""
        else:
            current += char
    
    if current:
        parts.append(current)
    
    # Navigate through the data
    result = json_data
    for part in parts:
        try:
            if isinstance(result, dict):
                result = result.get(part)
            elif isinstance(result, list) and isinstance(part, int):
                if 0 <= part < len(result):
                    result = result[part]
                else:
                    return None
            else:
                return None
            
            if result is None:
                break
        except Exception:
            return None
    
    return result

async def get_flow_details(arguments: dict) -> list[types.TextContent]:
    """
    Gets details of specific flows from a mitmproxy dump file.
    For large JSON content, returns structure preview instead of full content.
    """
    session_id = arguments.get("session_id")
    flow_indexes = arguments.get("flow_indexes")
    include_content = arguments.get("include_content", True)

    if not session_id:
        return [types.TextContent(type="text", text="Error: Missing session_id")]
    if not flow_indexes:
        return [types.TextContent(type="text", text="Error: Missing flow_indexes")]

    try:
        flows = await get_flows_from_dump(session_id)
        flow_details_list = []

        for flow_index in flow_indexes:
            try:
                flow = flows[flow_index]

                if flow.type == "http":
                    request = flow.request
                    response = flow.response

                    # Parse content
                    request_content = parse_json_content(request.content, dict(request.headers))
                    response_content = None
                    if response:
                        response_content = parse_json_content(response.content, dict(response.headers))
                    
                    # Handle large content
                    request_content_preview = None
                    response_content_preview = None
                    
                    # Check if request content is large and is JSON
                    if include_content and len(request.content) > MAX_CONTENT_SIZE and isinstance(request_content, dict):
                        request_content_preview = generate_json_structure(request_content)
                        request_content = None  # Don't include full content
                    
                    # Check if response content is large and is JSON
                    if response and include_content and len(response.content) > MAX_CONTENT_SIZE and isinstance(response_content, dict):
                        response_content_preview = generate_json_structure(response_content)
                        response_content = None  # Don't include full content

                    # Build flow details
                    flow_details = {
                        "index": flow_index,
                        "method": request.method,
                        "url": request.url,
                        "request_headers": dict(request.headers),
                        "status": response.status_code if response else None,
                        "response_headers": dict(response.headers) if response else None,
                    }
                    
                    # Add content or previews based on size
                    if include_content:
                        if request_content is not None:
                            flow_details["request_content"] = request_content
                        if request_content_preview is not None:
                            flow_details["request_content_preview"] = request_content_preview
                            flow_details["request_content_size"] = len(request.content)
                            flow_details["request_content_note"] = "Content too large to display. Use extract_json_fields tool to get specific values."
                            
                        if response_content is not None:
                            flow_details["response_content"] = response_content
                        if response_content_preview is not None:
                            flow_details["response_content_preview"] = response_content_preview
                            flow_details["response_content_size"] = len(response.content) if response else 0
                            flow_details["response_content_note"] = "Content too large to display. Use extract_json_fields tool to get specific values."
                    
                    flow_details_list.append(flow_details)
                else:
                    flow_details_list.append({"error": f"Flow {flow_index} is not an HTTP flow"})

            except IndexError:
                flow_details_list.append({"error": f"Flow index {flow_index} out of range"})

        return [types.TextContent(type="text", text=json.dumps(flow_details_list, indent=2))]

    except FileNotFoundError:
        return [types.TextContent(type="text", text="Error: Session not found")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error reading flow details: {str(e)}")]

async def extract_json_fields(arguments: dict) -> list[types.TextContent]:
    """
    Extract specific fields from JSON content in a flow using JSONPath expressions.
    """
    session_id = arguments.get("session_id")
    flow_index = arguments.get("flow_index")
    content_type = arguments.get("content_type")
    json_paths = arguments.get("json_paths")

    if not session_id:
        return [types.TextContent(type="text", text="Error: Missing session_id")]
    if flow_index is None:
        return [types.TextContent(type="text", text="Error: Missing flow_index")]
    if not content_type:
        return [types.TextContent(type="text", text="Error: Missing content_type")]
    if not json_paths:
        return [types.TextContent(type="text", text="Error: Missing json_paths")]

    try:
        flows = await get_flows_from_dump(session_id)
        
        try:
            flow = flows[flow_index]
            
            if flow.type != "http":
                return [types.TextContent(type="text", text=f"Error: Flow {flow_index} is not an HTTP flow")]
            
            request = flow.request
            response = flow.response
            
            # Determine which content to extract from
            content = None
            headers = None
            if content_type == "request":
                content = request.content
                headers = dict(request.headers)
            elif content_type == "response":
                if not response:
                    return [types.TextContent(type="text", text=f"Error: Flow {flow_index} has no response")]
                content = response.content
                headers = dict(response.headers)
            else:
                return [types.TextContent(type="text", text=f"Error: Invalid content_type. Must be 'request' or 'response'")]
            
            # Parse the content
            json_content = parse_json_content(content, headers)
            
            # Only extract from JSON content
            if not isinstance(json_content, (dict, list)):
                return [types.TextContent(type="text", text=f"Error: The {content_type} content is not valid JSON")]
            
            # Extract fields
            result = {}
            for path in json_paths:
                try:
                    extracted = extract_with_jsonpath(json_content, path)
                    result[path] = extracted
                except Exception as e:
                    result[path] = f"Error extracting path: {str(e)}"
            
            return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
            
        except IndexError:
            return [types.TextContent(type="text", text=f"Error: Flow index {flow_index} out of range")]
            
    except FileNotFoundError:
        return [types.TextContent(type="text", text="Error: Session not found")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error extracting JSON fields: {str(e)}")]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Handle tool execution requests.
    Delegates to specific functions based on the tool name.
    """
    if not arguments:
        raise ValueError("Missing arguments")

    if name == "list_flows":
        return await list_flows(arguments)
    elif name == "get_flow_details":
        return await get_flow_details(arguments)
    elif name == "extract_json_fields":
        return await extract_json_fields(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mitmproxy-mcp",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )