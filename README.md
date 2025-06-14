# SharkMCP - Network Packet Analysis MCP Server

A Model Context Protocol (MCP) server that provides network packet capture and analysis capabilities through Wireshark/tshark integration. Designed for AI assistants to perform network security analysis, troubleshooting, and packet inspection.

This server was thought for situations where you want your agent to debug a program that sends requests and verify the packet traffic, allowing the following workflow:

- Start recording packets
- Run tool or perform request
- Stop recording and analyze results

## Architecture

SharkMCP provides a simple, local development-focused architecture:

```
┌─────────────────────────────────────────────────────────┐
│                    SharkMCP Server                      │
├─────────────────────────────────────────────────────────┤
│  MCP Protocol Layer                                     │
│  ├─ start_capture_session                               │
│  ├─ stop_capture_session                                │
│  ├─ analyze_pcap_file                                   │
│  └─ manage_config                                       │
├─────────────────────────────────────────────────────────┤
│  tshark Integration Layer                               │
│  ├─ Cross-platform executable detection                 │
│  ├─ Process management                                  │
│  └─ Output parsing (JSON/fields/text)                   │
├─────────────────────────────────────────────────────────┤
│  Host System Integration                                │
│  ├─ Local tshark installation                           │
│  ├─ Direct network interface access                     │
│  └─ Native file system operations                       │
└─────────────────────────────────────────────────────────┘
```

## Features

- **Async Packet Capture**: Start background capture sessions with configurable filters and timeouts.
- **PCAP File Analysis**: Analyze existing packet capture files
- **Flexible Output Formats**: JSON, custom fields, or traditional text output
- **SSL/TLS Decryption**: Support for SSL keylog files to decrypt HTTPS traffic
- **Reusable Configurations**: Save and reuse capture/analysis configurations

/!\ Packet information can be very extensive. Make sure to use a scoped display filter not to overload the context of your conversation.

## Prerequisites

### System Requirements
- **Wireshark/tshark**: Must be installed and accessible
- **Node.js**: Version 18+ 
- **pnpm**: Package manager (recommended)

### Installing Wireshark/tshark

**macOS** (using Homebrew):
```bash
brew install wireshark
```

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install tshark wireshark-common
```

**Windows**:
Download from [wireshark.org](https://www.wireshark.org/download.html)

## Installation

1. **Clone the repository**:
```bash
git clone https://github.com/kriztalz/SharkMCP.git
cd SharkMCP
```

2. **Install dependencies**:
```bash
pnpm install
```

3. **Build the project**:
```bash
pnpm run build
```

4. **Run the server**:
```bash
pnpm start
```

## Testing

SharkMCP includes comprehensive integration tests that verify packet capture functionality.

### Running Tests

```bash
# Run all tests
pnpm test
```

## Configuration

### MCP Client Setup

```json
{
  "mcpServers": {
    "sharkmcp": {
      "command": "node",
      "args": ["/path/to/SharkMCP/dist/index.js"],
    }
  }
}
```

### SSL/TLS Decryption (Optional)

To decrypt HTTPS traffic, export the `SSLKEYLOGFILE` environment variable:

```bash
export SSLKEYLOGFILE=/path/to/sslkeylog.log
```

Then configure your applications to log SSL keys to this file. Many applications support this automatically when the environment variable is set.

Then pass the log file pathname to the MCP server in the `stop_capture_session` tool.

## Usage

### Available Tools

1. **start_capture_session**: Start background packet capture
2. **stop_capture_session**: Stop capture and analyze results  
3. **analyze_pcap_file**: Analyze existing PCAP files
4. **manage_config**: Save/load reusable configurations

### Basic Examples

**Start a capture session**:
```
Interface: en0
Capture Filter: port 443
Timeout: 30 seconds
```

**Analyze captured traffic**:
```
Display Filter: tls.handshake.type == 1
Output Format: json
```

**Save a configuration**:
```json
{
  "name": "https-monitoring",
  "description": "Monitor HTTPS traffic",
  "captureFilter": "port 443",
  "displayFilter": "tls.handshake.type == 1",
  "outputFormat": "json",
  "timeout": 60,
  "interface": "en0"
}
```

## Development

### Project Structure

```
SharkMCP/
├── src/
│   ├── index.ts              # Main server setup
│   ├── types.ts              # TypeScript interfaces
│   ├── utils.ts              # Utility functions
│   └── tools/                # Individual tool implementations
│       ├── start-capture-session.ts
│       ├── stop-capture-session.ts
│       ├── analyze-pcap-file.ts
│       └── manage-config.ts
├── test/                     # Test files
│   └── integration.test.js   # Integration tests
├── package.json
└── README.md
```

### Development Commands

```bash
# Development mode with auto-reload
pnpm run dev

# Build for production
pnpm run build

# Run tests
pnpm run test

# Type checking
pnpm run build
```

## Security Considerations

- **Network Permissions**: Packet capture requires elevated privileges
- **File Access**: Temporary files are created in `/tmp/`
- **Docker Security**: Container runs as non-root user
- **SSL Keylog**: Sensitive SSL keys should be handled securely

## Troubleshooting

### Common Issues

**"tshark not found"**:
- Ensure Wireshark is installed and tshark is in PATH
- Check installation with: `tshark -v`

**Permission denied for packet capture**:
- On Linux: Add user to `wireshark` group or run with `sudo`
- On macOS: Grant Terminal network access in System Preferences
- On Windows: Run as Administrator

**No packets captured**:
- Verify network interface name (`ip link` on Linux, `ifconfig` on macOS)
- Check capture filter syntax
- Ensure traffic is present on the interface

## Contributing (Very welcome!)

1. Fork the repository
2. Create a feature branch
3. Make your changes following the existing code style
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License

## Issues / Suggestions

Feel free to open an issue with any question or suggestion you may have.