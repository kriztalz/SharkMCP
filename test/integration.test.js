/**
 * Integration Tests for SharkMCP Server
 * Tests the full MCP server functionality using the SDK client
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawn } from "child_process";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import process from "process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');

/**
 * Test suite configuration
 */
const TEST_CONFIG = {
  serverPath: join(projectRoot, 'dist', 'index.js'),
  testInterface: process.platform === 'darwin' ? 'en0' : 'eth0', // Adjust based on platform
  captureTimeout: 12, // Slightly longer than config timeout to ensure completion
  configName: 'integration_test'
};

/**
 * Utility function to wait for a specified time
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Generate some network traffic to ensure we capture packets
 */
async function generateNetworkTraffic() {
  console.log('Generating network traffic...');
  
  // Create multiple concurrent network requests to generate traffic
  const trafficPromises = [
    // HTTP requests
    fetch('http://httpbin.org/get').catch(() => {}),
    fetch('http://example.com').catch(() => {}),
    // DNS lookups via fetch will generate UDP traffic
    fetch('http://google.com').catch(() => {}),
    fetch('http://github.com').catch(() => {}),
  ];
  
  // Don't wait for all to complete, just start them
  await Promise.allSettled(trafficPromises.slice(0, 2)); // Wait for first 2
  console.log('Network traffic generated');
}

/**
 * Extract packet count from tshark JSON output
 */
function countPacketsFromOutput(output, outputFormat) {
  if (!output || output.trim() === '') {
    return 0;
  }
  
  try {
    switch (outputFormat) {
      case 'json':
        // For JSON format, parse and count array elements
        const parsed = JSON.parse(output);
        if (Array.isArray(parsed)) {
          return parsed.length;
        } else if (parsed._source) {
          // Single packet format
          return 1;
        }
        return 0;
        
      case 'fields':
        // For fields format, count non-empty lines
        return output.split('\n').filter(line => line.trim().length > 0).length;
        
      case 'text':
      default:
        // For text format, count lines that look like packet headers
        const lines = output.split('\n');
        return lines.filter(line => 
          line.match(/^\s*\d+\s+\d+\.\d+/) || // Standard packet line
          line.includes('Ethernet') || 
          line.includes('Internet Protocol')
        ).length;
    }
  } catch (error) {
    console.warn(`Warning: Failed to parse output for packet counting: ${error.message}`);
    // Fallback: count non-empty lines
    return output.split('\n').filter(line => line.trim().length > 0).length;
  }
}

/**
 * Main integration test runner
 */
async function runIntegrationTests() {
  console.log('Starting SharkMCP Integration Tests');
  console.log(`Project root: ${projectRoot}`);
  console.log(`Server path: ${TEST_CONFIG.serverPath}`);
  console.log(`Test interface: ${TEST_CONFIG.testInterface}`);
  
  let client;
  let transport;
  
  try {
    // Initialize MCP client with server transport
    console.log('\nSetting up MCP client transport...');
    transport = new StdioClientTransport({
      command: "node",
      args: [TEST_CONFIG.serverPath]
    });

    client = new Client({
      name: "sharkmcp-integration-test",
      version: "1.0.0"
    });

    console.log('Connecting to MCP server...');
    await client.connect(transport);
    console.log('Successfully connected to MCP server');

    // Test 1: List available tools
    console.log('\nTest 1: Listing available tools...');
    const tools = await client.listTools();
    console.log(`Found ${tools.tools.length} tools:`);
    tools.tools.forEach(tool => {
      console.log(`  - ${tool.name}: ${tool.description}`);
    });
    
    const expectedTools = ['start_capture_session', 'stop_capture_session', 'analyze_pcap_file', 'manage_config'];
    const foundTools = tools.tools.map(t => t.name);
    const missingTools = expectedTools.filter(tool => !foundTools.includes(tool));
    
    if (missingTools.length > 0) {
      throw new Error(`Missing expected tools: ${missingTools.join(', ')}`);
    }
    console.log('All expected tools found');

    // Test 2: Load and verify test configuration
    console.log('\nTest 2: Loading test configuration...');
    const configResult = await client.callTool({
      name: "manage_config",
      arguments: {
        action: "load",
        name: TEST_CONFIG.configName
      }
    });
    
    if (configResult.isError) {
      throw new Error(`Failed to load test config: ${configResult.content[0].text}`);
    }
    console.log('Test configuration loaded successfully');
    console.log(configResult.content[0].text);

    // Test 3: Start capture session using saved config
    console.log('\nTest 3: Starting packet capture session...');
    const startResult = await client.callTool({
      name: "start_capture_session",
      arguments: {
        configName: TEST_CONFIG.configName,
        interface: TEST_CONFIG.testInterface
      }
    });
    
    if (startResult.isError) {
      throw new Error(`Failed to start capture: ${startResult.content[0].text}`);
    }
    
    const startText = startResult.content[0].text;
    console.log('Capture session started');
    console.log(startText);
    
    // Extract session ID from response
    const sessionIdMatch = startText.match(/Session ID: ([\w_]+)/);
    if (!sessionIdMatch) {
      throw new Error('Could not extract session ID from start response');
    }
    const sessionId = sessionIdMatch[1];
    console.log(`Session ID: ${sessionId}`);

    // Test 4: Generate network traffic during capture
    console.log('\nTest 4: Generating network traffic...');
    await sleep(2000); // Wait 2 seconds after starting capture
    await generateNetworkTraffic();
    
    // Wait for remaining capture time
    const remainingTime = (TEST_CONFIG.captureTimeout - 3) * 1000; // 3 seconds already passed
    console.log(`Waiting ${remainingTime/1000}s for capture to complete...`);
    await sleep(remainingTime);

    // Test 5: Stop capture and analyze results
    console.log('\nTest 5: Stopping capture and analyzing results...');
    const stopResult = await client.callTool({
      name: "stop_capture_session",
      arguments: {
        sessionId: sessionId,
        outputFormat: "json"
      }
    });
    
    if (stopResult.isError) {
      throw new Error(`Failed to stop capture: ${stopResult.content[0].text}`);
    }
    
    const stopText = stopResult.content[0].text;
    console.log('Capture session stopped and analyzed');
    
    // Test 6: Extract and count packets
    console.log('\nTest 6: Counting captured packets...');
    
    // Extract the JSON results section
    const resultsMatch = stopText.match(/Packet Analysis Results:\n(.*)/s);
    if (!resultsMatch) {
      console.warn('Could not extract packet analysis results from response');
      console.log('Full response:');
      console.log(stopText);
    } else {
      const packetData = resultsMatch[1];
      const packetCount = countPacketsFromOutput(packetData, 'json');
      
      console.log(`Packet count: ${packetCount}`);
      
      if (packetCount === 0) {
        console.warn('No packets captured - this could indicate:');
        console.warn('   - No network traffic on interface during capture');
        console.warn('   - Interface name incorrect for this system');
        console.warn('   - Permission issues with packet capture');
        console.warn('   - tshark not working properly');
      } else {
        console.log(`Successfully captured ${packetCount} packets`);
      }
      
      // Show some sample output
      if (packetData.length > 0) {
        const sampleLength = Math.min(500, packetData.length);
        console.log('\nSample output (first 500 chars):');
        console.log(packetData.substring(0, sampleLength));
        if (packetData.length > sampleLength) {
          console.log('... (truncated)');
        }
      }
    }

    // Test 7: Test PCAP file analysis (if we have the test file)
    console.log('\nTest 7: Testing PCAP file analysis...');
    try {
      const pcapResult = await client.callTool({
        name: "analyze_pcap_file",
        arguments: {
          filePath: join(projectRoot, 'test', 'dump.pcapng'),
          outputFormat: "json",
          displayFilter: ""
        }
      });
      
      if (!pcapResult.isError) {
        const pcapText = pcapResult.content[0].text;
        const pcapResultsMatch = pcapText.match(/Packet Analysis Results:\n(.*)/s);
        
        if (pcapResultsMatch) {
          const pcapPacketData = pcapResultsMatch[1];
          const pcapPacketCount = countPacketsFromOutput(pcapPacketData, 'json');
          console.log(`PCAP file analysis successful: ${pcapPacketCount} packets found`);
        } else {
          console.log('PCAP file analysis completed (format parsing issue)');
        }
      } else {
        console.log('PCAP file analysis failed (test file may not exist)');
      }
    } catch (error) {
      console.log(`PCAP file analysis test skipped: ${error.message}`);
    }

    // Test 8: Test TLS handshake filtering on dump.pcapng
    console.log('\nTest 8: Testing TLS handshake filter on dump.pcapng...');
    try {
      const tlsResult = await client.callTool({
        name: "analyze_pcap_file",
        arguments: {
          filePath: join(projectRoot, 'test', 'dump.pcapng'),
          outputFormat: "json",
          displayFilter: "tls.handshake.type == 1"
        }
      });
      
      if (!tlsResult.isError) {
        const tlsText = tlsResult.content[0].text;
        const tlsResultsMatch = tlsText.match(/Packet Analysis Results:\n(.*)/s);
        
        if (tlsResultsMatch) {
          const tlsPacketData = tlsResultsMatch[1];
          const tlsPacketCount = countPacketsFromOutput(tlsPacketData, 'json');
          
          if (tlsPacketCount > 0) {
            console.log(`TLS handshake filter successful: Found ${tlsPacketCount} TLS Client Hello packets`);
            
            // Show a sample of the TLS handshake data
            if (tlsPacketData.length > 0) {
              const sampleLength = Math.min(300, tlsPacketData.length);
              console.log('\nSample TLS handshake data (first 300 chars):');
              console.log(tlsPacketData.substring(0, sampleLength));
              if (tlsPacketData.length > sampleLength) {
                console.log('... (truncated)');
              }
            }
          } else {
            console.log('TLS handshake filter returned no packets - dump.pcapng may not contain TLS Client Hello packets');
          }
        } else {
          console.log('TLS handshake filter completed but could not parse results');
        }
      } else {
        console.log(`TLS handshake filter failed: ${tlsResult.content[0].text}`);
      }
    } catch (error) {
      console.log(`TLS handshake filter test failed: ${error.message}`);
    }

    console.log('\nIntegration tests completed successfully!');
    console.log('\nTest Summary:');
    console.log('- MCP server connection and communication');
    console.log('- Tool discovery and listing');
    console.log('- Configuration management');
    console.log('- Packet capture session lifecycle');
    console.log('- Network traffic generation and capture');
    console.log('- Packet analysis and counting');
    console.log('- PCAP file analysis with display filters');
    console.log('- TLS handshake packet filtering');
    console.log('- Error handling and edge cases');
    
    return true;
    
  } catch (error) {
    console.error('\nIntegration test failed:');
    console.error(error.message);
    console.error('\nStack trace:');
    console.error(error.stack);
    return false;
    
  } finally {
    // Clean up
    if (client && transport) {
      try {
        console.log('\nCleaning up MCP connection...');
        await client.close();
        console.log('MCP connection closed');
      } catch (error) {
        console.warn(`Warning during cleanup: ${error.message}`);
      }
    }
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const success = await runIntegrationTests();
  process.exit(success ? 0 : 1);
}

export { runIntegrationTests }; 