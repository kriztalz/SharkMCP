import { z } from "zod";
import { FilterConfig } from "../types.js";
import { 
  saveFilterConfig, 
  loadFilterConfig, 
  listFilterConfigs, 
  deleteFilterConfig 
} from "../utils.js";

/**
 * Input schema for config management tool
 */
export const manageConfigSchema = {
  action: z.enum(['save', 'load', 'list', 'view', 'delete']).describe('Action to perform: save, load, list (brief), view (detailed), or delete a configuration'),
  name: z.string().optional().describe('Name of the configuration (required for save, load, delete)'),
  detailed: z.boolean().optional().default(false).describe('Show detailed configuration info when listing (only used with list action)'),
  config: z.object({
    description: z.string().optional().describe('Description of what this config does'),
    captureFilter: z.string().optional().describe('BPF capture filter for packet capture'),
    displayFilter: z.string().optional().describe('Wireshark display filter for analysis'),
    outputFormat: z.enum(['json', 'fields', 'text']).optional().describe('Output format for analysis'),
    customFields: z.string().optional().describe('Custom field list for fields format'),
    timeout: z.number().optional().describe('Timeout in seconds for capture sessions'),
    maxPackets: z.number().optional().describe('Maximum packets to capture'),
    interface: z.string().optional().describe('Network interface to use')
  }).optional().describe('Configuration object (required for save action)')
};

/**
 * Tool handler for managing filter configurations
 * Allows LLMs to save, load, list, and delete reusable filter configurations
 */
export async function manageConfigHandler(args: any) {
  try {
    const { action, name, config, detailed } = args;

    switch (action) {
      case 'save':
        if (!name || !config) {
          return {
            content: [{
              type: 'text' as const,
              text: 'Error: Both name and config are required for save action.',
            }],
            isError: true
          };
        }

        const filterConfig: FilterConfig = {
          name,
          ...config
        };

        await saveFilterConfig(filterConfig);
        return {
          content: [{
            type: 'text' as const,
            text: `Configuration '${name}' saved successfully!\n\nSaved config:\n${JSON.stringify(filterConfig, null, 2)}`,
          }],
        };

      case 'load':
        if (!name) {
          return {
            content: [{
              type: 'text' as const,
              text: 'Error: Name is required for load action.',
            }],
            isError: true
          };
        }

        const loadedConfig = await loadFilterConfig(name);
        if (!loadedConfig) {
          return {
            content: [{
              type: 'text' as const,
              text: `Error: Configuration '${name}' not found.`,
            }],
            isError: true
          };
        }

        return {
          content: [{
            type: 'text' as const,
            text: `Configuration '${name}' loaded:\n\n${JSON.stringify(loadedConfig, null, 2)}`,
          }],
        };

      case 'list':
        const allConfigs = await listFilterConfigs();
        if (allConfigs.length === 0) {
          return {
            content: [{
              type: 'text' as const,
              text: 'No saved configurations found.',
            }],
          };
        }

        if (detailed) {
          // Show detailed information for all configurations
          const detailedList = allConfigs.map(cfg => {
            const configDetails = [
              `Name: ${cfg.name}`,
              ...(cfg.description ? [`Description: ${cfg.description}`] : []),
              ...(cfg.captureFilter ? [`Capture Filter: ${cfg.captureFilter}`] : []),
              ...(cfg.displayFilter ? [`Display Filter: ${cfg.displayFilter}`] : []),
              ...(cfg.outputFormat ? [`Output Format: ${cfg.outputFormat}`] : []),
              ...(cfg.customFields ? [`Custom Fields: ${cfg.customFields}`] : []),
              ...(cfg.interface ? [`Interface: ${cfg.interface}`] : []),
              ...(cfg.timeout ? [`Timeout: ${cfg.timeout}s`] : []),
              ...(cfg.maxPackets ? [`Max Packets: ${cfg.maxPackets}`] : [])
            ];
            return configDetails.join('\n  ');
          }).join('\n\n' + '─'.repeat(50) + '\n\n');

          return {
            content: [{
              type: 'text' as const,
              text: `Available configurations (${allConfigs.length}) - Detailed View:\n\n${'─'.repeat(50)}\n\n${detailedList}\n\n${'─'.repeat(50)}\n\nUse 'load' action with a specific name to get the full JSON configuration.`,
            }],
          };
        } else {
          // Show brief list (existing behavior)
          const configList = allConfigs.map(cfg => 
            `• ${cfg.name}${cfg.description ? `: ${cfg.description}` : ''}`
          ).join('\n');

          return {
            content: [{
              type: 'text' as const,
              text: `Available configurations (${allConfigs.length}):\n\n${configList}\n\nUse 'load' action to get full details of any configuration, or use 'view' action to see all configurations with full details.`,
            }],
          };
        }

      case 'view':
        const allConfigsForView = await listFilterConfigs();
        if (allConfigsForView.length === 0) {
          return {
            content: [{
              type: 'text' as const,
              text: 'No saved configurations found.',
            }],
          };
        }

        const configDetails = allConfigsForView.map(cfg => 
          `${cfg.name}:\n${JSON.stringify(cfg, null, 2)}`
        ).join('\n\n' + '─'.repeat(60) + '\n\n');

        return {
          content: [{
            type: 'text' as const,
            text: `All configurations (${allConfigsForView.length}) - Full Details:\n\n${'─'.repeat(60)}\n\n${configDetails}\n\n${'─'.repeat(60)}`,
          }],
        };

      case 'delete':
        if (!name) {
          return {
            content: [{
              type: 'text' as const,
              text: 'Error: Name is required for delete action.',
            }],
            isError: true
          };
        }

        const deleted = await deleteFilterConfig(name);
        if (!deleted) {
          return {
            content: [{
              type: 'text' as const,
              text: `Error: Configuration '${name}' not found.`,
            }],
            isError: true
          };
        }

        return {
          content: [{
            type: 'text' as const,
            text: `Configuration '${name}' deleted successfully.`,
          }],
        };

      default:
        return {
          content: [{
            type: 'text' as const,
            text: `Error: Unknown action '${action}'. Use save, load, list, view, or delete.`,
          }],
          isError: true
        };
    }
  } catch (error: any) {
    console.error(`Error managing config: ${error.message}`);
    return { 
      content: [{ type: 'text' as const, text: `Error: ${error.message}` }], 
      isError: true 
    };
  }
} 