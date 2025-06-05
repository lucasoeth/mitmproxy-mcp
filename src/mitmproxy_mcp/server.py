import asyncio
import os
import json
import re
import base64
from typing import Any, Dict, List, Optional, Union, Tuple
from mitmproxy import io

from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

from mitmproxy_mcp.flow_utils import get_flows_from_dump, parse_json_content
from mitmproxy_mcp.json_utils import generate_json_structure, extract_with_jsonpath
from mitmproxy_mcp.protection_analysis import (
    analyze_response_for_challenge,
    analyze_script,
    analyze_cookies,
    extract_javascript,
    generate_suggestions,
    identify_protection_system,
    BOT_PROTECTION_SIGNATURES,
)

# Maximum content size in bytes before switching to structure preview
MAX_CONTENT_SIZE = 2000

server = Server("mitmproxy-mcp")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available tools.
    Each tool specifies its arguments using JSON Schema validation.
    """
    return [
        types.Tool(
            name="list_flows",
            description="Retrieves detailed HTTP request/response data including headers, content (or structure preview for large JSON), and metadata from specified flows",
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
            description="Lists HTTP requests/responses from a mitmproxy capture session, showing method, URL, and status codes",
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
                        "default": True
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
        ),
        types.Tool(
            name="analyze_protection",
            description="Analyze flow for bot protection mechanisms and extract challenge details",
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "The ID of the session"
                    },
                    "flow_index": {
                        "type": "integer",
                        "description": "The index of the flow to analyze"
                    },
                    "extract_scripts": {
                        "type": "boolean",
                        "description": "Whether to extract and analyze JavaScript from the response (default: true)",
                        "default": True
                    }
                },
                "required": ["session_id", "flow_index"]
            }
        )
    ]

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

                    flow_details = {}
                    
                    # Check if request content is large and is JSON
                    if include_content and len(request.content) > MAX_CONTENT_SIZE and isinstance(request_content, dict):
                        request_content_preview = generate_json_structure(request_content)
                        request_content = None  # Don't include full content
                    elif include_content and len(request.content) > MAX_CONTENT_SIZE:
                        if isinstance(request_content, str):
                            request_content = request_content[:MAX_CONTENT_SIZE] + " ...[truncated]"
                        else:
                            request_content = request_content[:MAX_CONTENT_SIZE].decode(errors="ignore") + " ...[truncated]"
                        flow_details["request_content_note"] = f"Request content truncated to {MAX_CONTENT_SIZE} bytes."
                    
                    # Check if response content is large and is JSON
                    if response and include_content and len(response.content) > MAX_CONTENT_SIZE and isinstance(response_content, dict):
                        response_content_preview = generate_json_structure(response_content)
                        response_content = None  # Don't include full content
                    elif response and include_content and len(response.content) > MAX_CONTENT_SIZE:
                        if isinstance(response_content, str):
                            response_content = response_content[:MAX_CONTENT_SIZE] + " ...[truncated]"
                        else:
                            response_content = response_content[:MAX_CONTENT_SIZE].decode(errors="ignore") + " ...[truncated]"
                        flow_details["response_content_note"] = f"Response content truncated to {MAX_CONTENT_SIZE} bytes."

                    # Build flow details
                    flow_details.update( {
                        "index": flow_index,
                        "method": request.method,
                        "url": request.url,
                        "request_headers": dict(request.headers),
                        "status": response.status_code if response else None,
                        "response_headers": dict(response.headers) if response else None,
                    })
                    
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

async def analyze_protection(arguments: dict) -> list[types.TextContent]:
    """
    Analyze a flow for bot protection mechanisms and extract challenge details.
    """
    session_id = arguments.get("session_id")
    flow_index = arguments.get("flow_index")
    extract_scripts = arguments.get("extract_scripts", True)
    
    if not session_id:
        return [types.TextContent(type="text", text="Error: Missing session_id")]
    if flow_index is None:
        return [types.TextContent(type="text", text="Error: Missing flow_index")]
    
    try:
        flows = await get_flows_from_dump(session_id)
        
        try:
            flow = flows[flow_index]
            
            if flow.type != "http":
                return [types.TextContent(type="text", text=f"Error: Flow {flow_index} is not an HTTP flow")]
            
            # Analyze the flow for protection mechanisms
            analysis = {
                "flow_index": flow_index,
                "method": flow.request.method,
                "url": flow.request.url,
                "protection_systems": identify_protection_system(flow),
                "request_cookies": analyze_cookies(dict(flow.request.headers)),
                "has_response": flow.response is not None,
            }
            
            if flow.response:
                # Add response analysis
                content_type = flow.response.headers.get("Content-Type", "")
                is_html = "text/html" in content_type
                
                analysis.update({
                    "status_code": flow.response.status_code,
                    "response_cookies": analyze_cookies(dict(flow.response.headers)),
                    "challenge_analysis": analyze_response_for_challenge(flow),
                    "content_type": content_type,
                    "is_html": is_html,
                })
                
                # If HTML and script extraction is requested, extract and analyze JavaScript
                if is_html and extract_scripts:
                    try:
                        html_content = flow.response.content.decode('utf-8', errors='ignore')
                        analysis["scripts"] = extract_javascript(html_content)
                    except Exception as e:
                        analysis["script_extraction_error"] = str(e)
            
            # Add remediation suggestions based on findings
            analysis["suggestions"] = generate_suggestions(analysis)
            
            return [types.TextContent(type="text", text=json.dumps(analysis, indent=2))]
            
        except IndexError:
            return [types.TextContent(type="text", text=f"Error: Flow index {flow_index} out of range")]
            
    except FileNotFoundError:
        return [types.TextContent(type="text", text="Error: Session not found")]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error analyzing protection: {str(e)}")]

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
    elif name == "analyze_protection":
        return await analyze_protection(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )