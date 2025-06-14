import { ChildProcess } from "child_process";

/**
 * Represents an active packet capture session
 */
export interface CaptureSession {
  id: string;
  process: ChildProcess | null;
  interface: string;
  captureFilter?: string;
  timeout: number;
  maxPackets: number;
  startTime: Date;
  tempFile: string;
  status: 'running' | 'completed' | 'error';
  endTime?: Date;
  exitCode?: number;
}

/**
 * Output format options for packet analysis
 */
export type OutputFormat = 'json' | 'fields' | 'text';

/**
 * Environment configuration for tshark processes
 */
export interface TsharkEnvironment {
  [key: string]: string;
}

/**
 * Configuration for PCAP analysis
 */
export interface AnalysisConfig {
  filePath: string;
  displayFilter: string;
  outputFormat: OutputFormat;
  customFields?: string;
  sslKeylogFile?: string;
}

/**
 * Reusable filter configuration that LLMs can save and reuse
 */
export interface FilterConfig {
  name: string;
  description?: string;
  captureFilter?: string;
  displayFilter?: string;
  outputFormat?: OutputFormat;
  customFields?: string;
  timeout?: number;
  maxPackets?: number;
  interface?: string;
}

/**
 * Config file structure
 */
export interface ConfigFile {
  version: string;
  configs: { [name: string]: FilterConfig };
} 