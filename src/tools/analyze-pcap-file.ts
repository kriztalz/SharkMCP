import { z } from "zod";
import fs from "fs/promises";
import { analyzePcap, trimOutput, loadFilterConfig } from "../utils.js";

/**
 * Input schema for analyze pcap file tool
 */
export const analyzePcapFileSchema = {
  filePath: z.string().describe('Path to the local .pcap or .pcapng file to analyze.'),
  displayFilter: z.string().optional().describe('Wireshark display filter for analysis (e.g., "tls.handshake.type == 1")'),
  outputFormat: z.enum(['json', 'fields', 'text']).optional().default('text').describe('Output format: json (-T json), fields (custom -e), or text (default wireshark output)'),
  customFields: z.string().optional().describe('Custom tshark field list (only used with outputFormat=fields)'),
  sslKeylogFile: z.string().optional().describe('ABSOLUTE path to SSL keylog file for TLS decryption'),
  configName: z.string().optional().describe('Name of saved configuration to use for analysis parameters')
};

/**
 * Tool handler for analyzing an existing PCAP file
 * This tool analyzes pre-existing PCAP/PCAPNG files without needing to capture
 */
export async function analyzePcapFileHandler(args: any) {
  try {
    let { filePath, displayFilter, outputFormat, customFields, sslKeylogFile, configName } = args;

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

    // Verify file exists before proceeding
    await fs.access(filePath);

    // Analyze the file using the reusable function
    const output = await analyzePcap(
      filePath,
      displayFilter,
      outputFormat,
      customFields,
      sslKeylogFile
    );

    const keylogToUse = sslKeylogFile || process.env.SSLKEYLOGFILE;

    // Trim output if too large
    const trimmedOutput = trimOutput(output, outputFormat);

    const configInfo = configName ? `\nUsing saved config: ${configName}` : '';
    
    return {
      content: [{
        type: 'text' as const,
        text: `Analysis of '${filePath}' complete!${configInfo}\nDisplay Filter: ${displayFilter || 'none'}\nOutput Format: ${outputFormat}\nSSL Decryption: ${keylogToUse ? 'Enabled' : 'Disabled'}\n\nPacket Analysis Results:\n${trimmedOutput}`,
      }],
    };
  } catch (error: any) {
    console.error(`Error analyzing PCAP file: ${error.message}`);
    return { 
      content: [{ type: 'text' as const, text: `Error: ${error.message}` }], 
      isError: true 
    };
  }
} 