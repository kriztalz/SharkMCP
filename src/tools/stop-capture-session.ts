import { z } from "zod";
import fs from "fs/promises";
import { CaptureSession } from "../types.js";
import { analyzePcap, trimOutput, loadFilterConfig } from "../utils.js";

/**
 * Input schema for stop capture session tool
 */
export const stopCaptureSessionSchema = {
  sessionId: z.string().describe('Session ID returned from start_capture_session'),
  displayFilter: z.string().optional().describe('Wireshark display filter for analysis (e.g., "tls.handshake.type == 1")'),
  outputFormat: z.enum(['json', 'fields', 'text']).optional().default('text').describe('Output format: json (-T json), fields (custom -e), or text (default wireshark output)'),
  customFields: z.string().optional().describe('Custom tshark field list (only used with outputFormat=fields)'),
  sslKeylogFile: z.string().optional().describe('ABSOLUTE path to SSL keylog file for TLS decryption'),
  configName: z.string().optional().describe('Name of saved configuration to use for analysis parameters')
};

/**
 * Tool handler for stopping capture session and retrieving results
 * This tool stops a running capture session and analyzes the captured packets
 */
export async function stopCaptureSessionHandler(args: any, activeSessions: Map<string, CaptureSession>) {
  try {
    let { sessionId, displayFilter, outputFormat, customFields, sslKeylogFile, configName } = args;
    const session = activeSessions.get(sessionId);
    
    if (!session) {
      return {
        content: [{
          type: 'text' as const,
          text: `Error: No active session found with ID '${sessionId}'. Use 'list_capture_sessions' to see active sessions.`,
        }],
        isError: true
      };
    }

    // If configName is provided, load and use that configuration for analysis
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
      
      // Override analysis parameters with saved config (saved config takes precedence)
      if (savedConfig.displayFilter) displayFilter = savedConfig.displayFilter;
      if (savedConfig.outputFormat) outputFormat = savedConfig.outputFormat;
      if (savedConfig.customFields) customFields = savedConfig.customFields;
      
      console.error(`Using saved configuration '${configName}' for analysis: ${JSON.stringify(savedConfig)}`);
    }

    console.error(`Stopping capture session: ${sessionId}`);

    // Check if the capture process has already completed naturally
    if (session.process && !session.process.killed && session.status === 'running') {
      console.error(`Terminating capture process for session ${sessionId}`);
      session.process.kill('SIGTERM');
      // Wait a moment for graceful termination
      await new Promise(resolve => setTimeout(resolve, 2000));
    } else if (session.status === 'completed') {
      console.error(`Capture session ${sessionId} already completed naturally`);
    } else {
      console.error(`Capture session ${sessionId} process already terminated`);
    }

    // Remove from active sessions
    activeSessions.delete(sessionId);

    try {
      // Check if file exists
      await fs.access(session.tempFile);
      
      // Wait a bit more to ensure file is fully written
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Analyze captured file using the reusable function
      const output = await analyzePcap(
        session.tempFile,
        displayFilter,
        outputFormat,
        customFields,
        sslKeylogFile
      );
      
      const keylogToUse = sslKeylogFile || process.env.SSLKEYLOGFILE;

      // Clean up temporary file
      await fs.unlink(session.tempFile).catch(err => 
        console.error(`Failed to delete ${session.tempFile}: ${err.message}`)
      );

      const duration = new Date().getTime() - session.startTime.getTime();
      const durationSec = (duration / 1000).toFixed(1);

      // Trim output if too large
      const trimmedOutput = trimOutput(output, outputFormat);

      const configInfo = configName ? `\nUsing saved config: ${configName}` : '';

      return {
        content: [{
          type: 'text' as const,
          text: `Capture session '${sessionId}' completed!${configInfo}\nInterface: ${session.interface}\nDuration: ${durationSec}s\nDisplay Filter: ${displayFilter || 'none'}\nOutput Format: ${outputFormat}\nSSL Decryption: ${keylogToUse ? 'Enabled' : 'Disabled'}\n\nPacket Analysis Results:\n${trimmedOutput}`,
        }],
      };

    } catch (fileError: any) {
      console.error(`Error analyzing session ${sessionId}: ${fileError.message}`);
      return {
        content: [{
          type: 'text' as const,
          text: `Error analyzing session '${sessionId}': Capture file not found or unreadable. This could mean no packets were captured.\nDetails: ${fileError.message}`,
        }],
        isError: true,
      };
    }
  } catch (error: any) {
    console.error(`Error stopping capture session: ${error.message}`);
    return { 
      content: [{ type: 'text' as const, text: `Error: ${error.message}` }], 
      isError: true 
    };
  }
} 