/**
 * Export Service for AD Tier Model
 * Handles exporting reports using Tauri's file dialog and filesystem plugins
 */

import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { generateHtmlReport } from "./reportGenerator";
import type { ReportData } from "./reportGenerator";

export type { ReportData };

export interface ExportResult {
  success: boolean;
  filePath?: string;
  error?: string;
}

/**
 * Export compliance report to HTML file
 */
export async function exportHtmlReport(data: ReportData): Promise<ExportResult> {
  try {
    // Generate the HTML content
    const htmlContent = generateHtmlReport(data);

    // Generate default filename with timestamp
    const timestamp = new Date().toISOString().slice(0, 10);
    const domain = data.domainInfo?.netbiosName || "ADTierModel";
    const defaultFilename = `${domain}_Compliance_Report_${timestamp}.html`;

    // Show save dialog
    const filePath = await save({
      title: "Export Compliance Report",
      defaultPath: defaultFilename,
      filters: [
        {
          name: "HTML Document",
          extensions: ["html", "htm"],
        },
        {
          name: "All Files",
          extensions: ["*"],
        },
      ],
    });

    // User cancelled the dialog
    if (!filePath) {
      return {
        success: false,
        error: "Export cancelled",
      };
    }

    // Write the file
    await writeTextFile(filePath, htmlContent);

    return {
      success: true,
      filePath,
    };
  } catch (error) {
    console.error("Failed to export report:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Failed to export report",
    };
  }
}

/**
 * Export compliance report to JSON file (for data analysis)
 */
export async function exportJsonReport(data: ReportData): Promise<ExportResult> {
  try {
    // Generate default filename with timestamp
    const timestamp = new Date().toISOString().slice(0, 10);
    const domain = data.domainInfo?.netbiosName || "ADTierModel";
    const defaultFilename = `${domain}_Compliance_Data_${timestamp}.json`;

    // Show save dialog
    const filePath = await save({
      title: "Export Compliance Data",
      defaultPath: defaultFilename,
      filters: [
        {
          name: "JSON File",
          extensions: ["json"],
        },
        {
          name: "All Files",
          extensions: ["*"],
        },
      ],
    });

    // User cancelled the dialog
    if (!filePath) {
      return {
        success: false,
        error: "Export cancelled",
      };
    }

    // Format JSON with indentation for readability
    const jsonContent = JSON.stringify(
      {
        ...data,
        generatedAt: data.generatedAt.toISOString(),
      },
      null,
      2
    );

    // Write the file
    await writeTextFile(filePath, jsonContent);

    return {
      success: true,
      filePath,
    };
  } catch (error) {
    console.error("Failed to export data:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Failed to export data",
    };
  }
}
