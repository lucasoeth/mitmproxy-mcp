import asyncio
import os
import json
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