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

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Handle tool execution requests.
    Currently supports listing HTTP flows from mitmproxy dump files.
    """
    if name != "list_flows":
        raise ValueError(f"Unknown tool: {name}")

    if not arguments:
        raise ValueError("Missing arguments")

    session_id = arguments.get("session_id")
    if not session_id:
        return [types.TextContent(type="text", text="Error: Missing session_id")]

    dump_file = os.path.join(DUMP_DIR, f"{session_id}.dump")
    if not os.path.exists(dump_file):
        return [types.TextContent(type="text", text="Error: Session not found")]

    try:
        with open(dump_file, "rb") as f:
            reader = io.FlowReader(f)
            flows = list(reader.stream())

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

        return [types.TextContent(type="text", text=json.dumps(flow_list))]
    except Exception as e:
        return [types.TextContent(type="text", text=f"Error reading flows: {str(e)}")]

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