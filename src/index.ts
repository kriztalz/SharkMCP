import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CaptureSession } from "./types.js";
import { startCaptureSessionSchema, startCaptureSessionHandler } from "./tools/start-capture-session.js";
import { stopCaptureSessionSchema, stopCaptureSessionHandler } from "./tools/stop-capture-session.js";
import { analyzePcapFileSchema, analyzePcapFileHandler } from "./tools/analyze-pcap-file.js";
import { manageConfigSchema, manageConfigHandler } from "./tools/manage-config.js";

// Active capture sessions storage
const activeSessions = new Map<string, CaptureSession>();

// Initialize MCP server
const server = new McpServer({
  name: 'SharkMCP',
  version: '0.1.0',
});

/**
 * Register all tools with the MCP server
 * Each tool is defined in its own module for better organization
 */

// Tool 1: Start background packet capture session
server.tool(
  'start_capture_session',
  'Start a background packet capture session. LLMs control all capture parameters including filters, interfaces, and packet limits. Can use saved configurations.',
  startCaptureSessionSchema,
  async (args) => startCaptureSessionHandler(args, activeSessions)
);

// Tool 2: Stop capture session and retrieve results
server.tool(
  'stop_capture_session',
  'Stop a running capture session and analyze packets. LLMs control all analysis parameters including display filters and output formats. Can use saved configurations.',
  stopCaptureSessionSchema,
  async (args) => stopCaptureSessionHandler(args, activeSessions)
);

// Tool 3: Analyze an existing PCAP file
server.tool(
  'analyze_pcap_file',
  'Analyze a local pcap/pcapng file. LLMs control all analysis parameters including filters, output formats, and custom fields. Can use saved configurations.',
  analyzePcapFileSchema,
  async (args) => analyzePcapFileHandler(args)
);

// Tool 4: Manage filter configurations
server.tool(
  'manage_config',
  'Save, load, list, or delete reusable filter configurations. Allows LLMs to store commonly used capture and analysis parameters for easy reuse.',
  manageConfigSchema,
  async (args) => manageConfigHandler(args)
);

// Start receiving messages on stdin and sending messages on stdout
const transport = new StdioServerTransport();
await server.connect(transport);

console.error("SharkMCP server is running and connected to transport. Ready for requests.");