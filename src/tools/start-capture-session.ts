import { z } from "zod";
import { spawn } from "child_process";
import { CaptureSession } from "../types.js";
import { findTshark, loadFilterConfig } from "../utils.js";

/**
 * Input schema for start capture session tool
 */
export const startCaptureSessionSchema = {
  interface: z.string().optional().default('lo0').describe('Network interface to capture from (e.g., eth0, en0, lo0)'),
  captureFilter: z.string().optional().describe('Optional BPF capture filter to apply while capturing (e.g., "port 443")'),
  timeout: z.number().optional().default(60).describe('Timeout in seconds before auto-stopping capture (default: 60s to prevent orphaned sessions)'),
  maxPackets: z.number().optional().default(100000).describe('Maximum number of packets to capture (safety limit, default: 100,000)'),
  sessionName: z.string().optional().describe('Optional session name for easier identification'),
  configName: z.string().optional().describe('Name of saved configuration to use (will override other parameters)')
};

/**
 * Tool handler for starting background packet capture session
 * This tool starts a detached tshark process to capture network packets
 */
export async function startCaptureSessionHandler(args: any, activeSessions: Map<string, CaptureSession>) {
  try {
    const tsharkPath = await findTshark();
    let { interface: networkInterface, captureFilter, timeout, maxPackets, sessionName, configName } = args;
    
    // If configName is provided, load and use that configuration
    if (configName) {
      const savedConfig = await loadFilterConfig(configName);
      if (!savedConfig) {
        return {
          content: [{
            type: 'text' as const,
            text: `Error: Configuration '${configName}' not found. Use manage_config with action 'list' to see available configurations.`,
          }],
          isError: true
        };
      }
      
      // Override parameters with saved config (saved config takes precedence)
      if (savedConfig.interface) networkInterface = savedConfig.interface;
      if (savedConfig.captureFilter) captureFilter = savedConfig.captureFilter;
      if (savedConfig.timeout) timeout = savedConfig.timeout;
      if (savedConfig.maxPackets) maxPackets = savedConfig.maxPackets;
      
      console.error(`Using saved configuration '${configName}': ${JSON.stringify(savedConfig)}`);
    }
    
    // Generate unique session ID
    const sessionId = sessionName || `capture_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Check if session already exists
    if (activeSessions.has(sessionId)) {
      return {
        content: [{
          type: 'text' as const,
          text: `Error: Session '${sessionId}' already exists. Use a different session name or stop the existing session.`,
        }],
        isError: true
      };
    }

    const tempFile = `/tmp/shark_${sessionId}.pcap`;
    console.error(`Starting capture session: ${sessionId} on ${networkInterface}`);

    // Build comprehensive tshark command for background capture
    // Use timeout as primary stopping mechanism, with maxPackets as safety limit
    const args_array = [
      '-i', networkInterface,
      '-a', `duration:${timeout}`,  // Auto-stop after timeout seconds
      '-c', maxPackets.toString(),  // Safety limit to prevent excessive capture
      '-w', tempFile
    ];
    
    // Add capture filter if provided (as a single argument to -f)
    if (captureFilter) {
      args_array.push('-f', captureFilter);
    }

    // Set up basic environment
    const captureEnv: Record<string, string> = {
      ...process.env,
      PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`
    };
    
    // Log the command with proper quoting for copy-paste debugging
    const quotedArgs = args_array.map(arg => {
      // Quote arguments that contain spaces or special characters
      if (arg.includes(' ') || arg.includes('|') || arg.includes('&') || arg.includes('(') || arg.includes(')')) {
        return `"${arg}"`;
      }
      return arg;
    });
    console.error(`Running background command: ${tsharkPath} ${quotedArgs.join(' ')}`);

    // Start background capture process with stderr logging
    const captureProcess = spawn(tsharkPath, args_array, {
      env: captureEnv,
      stdio: ['ignore', 'ignore', 'pipe'], // Capture stderr for error logging
      detached: true   // Fully detach the process
    });
    
    // Log any errors from tshark
    if (captureProcess.stderr) {
      captureProcess.stderr.on('data', (data) => {
        console.error(`tshark stderr [${sessionId}]: ${data.toString().trim()}`);
      });
    }
    
    // Unref the process so the parent can exit independently
    captureProcess.unref();

    // Store session info
    const session: CaptureSession = {
      id: sessionId,
      process: captureProcess,
      interface: networkInterface,
      captureFilter,
      timeout,
      maxPackets,
      startTime: new Date(),
      tempFile,
      status: 'running'
    };
    
    activeSessions.set(sessionId, session);

    // Handle process completion - KEEP SESSION ALIVE for result retrieval
    captureProcess.on('exit', (code) => {
      console.error(`Capture session ${sessionId} exited with code: ${code}`);
      if (activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        session.process = null;
        session.status = code === 0 ? 'completed' : 'error';
        session.endTime = new Date();
        if (code !== null) {
          session.exitCode = code;
        }
        console.error(`Session ${sessionId} marked as ${session.status}, file: ${session.tempFile}`);
      }
    });

    captureProcess.on('error', (error) => {
      console.error(`Capture session ${sessionId} error: ${error.message}`);
      if (activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        session.process = null;
        session.status = 'error';
        session.endTime = new Date();
      }
    });

    const configInfo = configName ? `\nUsing saved config: ${configName}` : '';
    
    return {
      content: [{
        type: 'text' as const,
        text: `Capture session started successfully!${configInfo}\nSession ID: ${sessionId}\nInterface: ${networkInterface}\nCapture Filter: ${captureFilter || 'none'}\nTimeout: ${timeout}s (auto-stop)\nMax Packets: ${maxPackets} (safety limit)\n\nCapture will auto-stop after ${timeout} seconds or use 'stop_capture_session' with session ID '${sessionId}' to stop manually and retrieve results.`,
      }],
    };
  } catch (error: any) {
    console.error(`Error starting capture session: ${error.message}`);
    return { 
      content: [{ type: 'text' as const, text: `Error: ${error.message}` }], 
      isError: true 
    };
  }
} 