import { promisify } from "util";
import { exec } from "child_process";
import which from "which";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { OutputFormat, TsharkEnvironment, FilterConfig, ConfigFile } from "./types.js";

// Promisify exec for async/await usage
const execAsync = promisify(exec);

// Get the directory of this file and construct config path relative to project root
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_FILE_PATH = path.join(__dirname, '..', 'sharkmcp-configs.json');

/**
 * Dynamically locate tshark executable with cross-platform support
 */
export async function findTshark(): Promise<string> {
  // First, try to find tshark in PATH
  try {
    const tsharkPath = await which('tshark');
    if (!tsharkPath) {
      throw new Error('tshark not found in PATH');
    }
    const pathString = Array.isArray(tsharkPath) ? tsharkPath[0] : tsharkPath;
    
    // Verify the executable works
    await execAsync(`"${pathString}" -v`, { timeout: 5000 });
    console.error(`Found tshark at: ${pathString}`);
    return pathString;
  } catch (err: any) {
    console.error('tshark not found in PATH, trying fallback locations...');
  }

  // Platform-specific fallback paths
  const getFallbackPaths = (): string[] => {
    switch (process.platform) {
      case 'win32':
        return [
          'C:\\Program Files\\Wireshark\\tshark.exe',
          'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
          ...(process.env.ProgramFiles ? [`${process.env.ProgramFiles}\\Wireshark\\tshark.exe`] : []),
          ...(process.env['ProgramFiles(x86)'] ? [`${process.env['ProgramFiles(x86)']}\\Wireshark\\tshark.exe`] : [])
        ];
      
      case 'darwin':
        return [
          '/opt/homebrew/bin/tshark',
          '/usr/local/bin/tshark',
          '/Applications/Wireshark.app/Contents/MacOS/tshark',
          '/usr/bin/tshark'
        ];
      
      case 'linux':
        return [
          '/usr/bin/tshark',
          '/usr/local/bin/tshark',
          '/snap/bin/tshark',
          '/usr/sbin/tshark'
        ];
      
      default:
        return ['/usr/bin/tshark', '/usr/local/bin/tshark'];
    }
  };

  // Try fallback paths
  const fallbackPaths = getFallbackPaths();
  for (const candidatePath of fallbackPaths) {
    try {
      await execAsync(`"${candidatePath}" -v`, { timeout: 5000 });
      console.error(`Found tshark at fallback: ${candidatePath}`);
      return candidatePath;
    } catch {
      // Continue to next fallback
    }
  }

  throw new Error(
    'tshark not found. Please install Wireshark (https://www.wireshark.org/download.html) and ensure tshark is in your PATH.'
  );
}

/**
 * Load config file, creating default if it doesn't exist
 */
export async function loadConfigFile(): Promise<ConfigFile> {
  try {
    const configContent = await fs.readFile(CONFIG_FILE_PATH, 'utf8');
    return JSON.parse(configContent);
  } catch (error) {
    // Create default config file if it doesn't exist
    const defaultConfig: ConfigFile = {
      version: "0.1.0",
      configs: {}
    };
    await saveConfigFile(defaultConfig);
    return defaultConfig;
  }
}

/**
 * Save config file
 */
export async function saveConfigFile(config: ConfigFile): Promise<void> {
  await fs.writeFile(CONFIG_FILE_PATH, JSON.stringify(config, null, 2));
}

/**
 * Save a filter configuration
 */
export async function saveFilterConfig(filterConfig: FilterConfig): Promise<void> {
  const configFile = await loadConfigFile();
  configFile.configs[filterConfig.name] = filterConfig;
  await saveConfigFile(configFile);
}

/**
 * Load a filter configuration by name
 */
export async function loadFilterConfig(name: string): Promise<FilterConfig | null> {
  const configFile = await loadConfigFile();
  return configFile.configs[name] || null;
}

/**
 * List all available filter configurations
 */
export async function listFilterConfigs(): Promise<FilterConfig[]> {
  const configFile = await loadConfigFile();
  return Object.values(configFile.configs);
}

/**
 * Delete a filter configuration
 */
export async function deleteFilterConfig(name: string): Promise<boolean> {
  const configFile = await loadConfigFile();
  if (configFile.configs[name]) {
    delete configFile.configs[name];
    await saveConfigFile(configFile);
    return true;
  }
  return false;
}

/**
 * Process tshark output based on format
 */
export function processTsharkOutput(
  stdout: string,
  outputFormat: OutputFormat
): string {
  switch (outputFormat) {
    case 'json':
      // Try to parse and format JSON for readability
      try {
        const parsed = JSON.parse(stdout);
        return JSON.stringify(parsed, null, 2);
      } catch {
        return stdout; // Return raw if parsing fails
      }
    case 'fields':
    case 'text':
    default:
      return stdout; // Return raw output
  }
}

/**
 * Reusable function for PCAP analysis with comprehensive cross-platform error handling
 */
export async function analyzePcap(
  filePath: string,
  displayFilter: string = '',
  outputFormat: OutputFormat = 'text',
  customFields?: string,
  sslKeylogFile?: string
): Promise<string> {
  const tsharkPath = await findTshark();
      
  // Set up SSL keylog for decryption during analysis
  const analysisEnv: TsharkEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([_, value]) => value !== undefined)
  ) as TsharkEnvironment;
  
  const keylogToUse = sslKeylogFile || process.env.SSLKEYLOGFILE;
  if (keylogToUse) {
    console.error(`Using SSL keylog file for decryption: ${keylogToUse}`);
    analysisEnv.SSLKEYLOGFILE = keylogToUse;
  }
  
  // Build command based on output format using absolute tshark path
  let command: string;
  const sslOptions = keylogToUse ? `-o tls.keylog_file:"${keylogToUse}"` : '';
  const filterOption = displayFilter ? `-Y "${displayFilter}"` : '';
  const quotedTsharkPath = `"${tsharkPath}"`;
  
  switch (outputFormat) {
    case 'json':
      command = `${quotedTsharkPath} -r "${filePath}" ${sslOptions} ${filterOption} -T json`;
      break;
    case 'fields':
      const fieldsToUse = customFields || 'frame.number,frame.time_relative,ip.src,ip.dst,tcp.srcport,tcp.dstport';
      const fieldArgs = fieldsToUse.split(',').map(field => `-e ${field.trim()}`).join(' ');
      command = `${quotedTsharkPath} -r "${filePath}" ${sslOptions} ${filterOption} -T fields ${fieldArgs}`;
      break;
    case 'text':
    default:
      command = `${quotedTsharkPath} -r "${filePath}" ${sslOptions} ${filterOption}`;
      break;
  }
  
  // Execution options with increased buffer
  const execOptions = { 
    env: analysisEnv,
    maxBuffer: 50 * 1024 * 1024 // 50MB buffer
  };
  
  console.error(`Analyzing capture with command: ${command}`);
  const { stdout } = await execAsync(command, execOptions);
  return processTsharkOutput(stdout, outputFormat);
}

/**
 * Trim output if it exceeds maximum character limits
 * Different formats have different optimal limits for readability
 */
export function trimOutput(output: string, outputFormat: OutputFormat): string {
  // Format-specific limits for optimal readability
  const maxChars = outputFormat === 'json' ? 500000 : 
                   outputFormat === 'fields' ? 800000 : 
                   720000; // text format default
  
  if (output.length > maxChars) {
    const trimPoint = maxChars - 500;
    const formatInfo = outputFormat !== 'text' ? ` (${outputFormat} format)` : '';
    const trimmed = output.substring(0, trimPoint) + `\n\n... [Output truncated due to size${formatInfo}] ...`;
    console.error(`Trimmed ${outputFormat} output from ${output.length} to ${maxChars} chars`);
    return trimmed;
  }
  return output;
} 