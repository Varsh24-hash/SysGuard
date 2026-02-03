
import { SyscallData } from '../types';

export interface ParsedData {
  [key: string]: number;
}

/**
 * Parses raw file content into a frequency map of syscalls.
 */
export const parseSyscallFile = (content: string): ParsedData => {
  const lines = content.split(/\r?\n/);
  const data: ParsedData = {};

  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed) return;

    if (trimmed.includes(',')) {
      const [name, countStr] = trimmed.split(',');
      const count = parseInt(countStr.trim(), 10);
      if (name && !isNaN(count)) {
        data[name.trim()] = (data[name.trim()] || 0) + count;
      }
    } else {
      const name = trimmed.toLowerCase();
      data[name] = (data[name] || 0) + 1;
    }
  });

  return data;
};

/**
 * Compares two datasets and generates SyscallData for the UI.
 * Now penalizes new syscalls heavily (500% deviation).
 */
export const analyzeDeviations = (
  baseline: ParsedData, 
  test: ParsedData
): { syscalls: SyscallData[], avgDeviation: number } => {
  const allKeys = Array.from(new Set([...Object.keys(baseline), ...Object.keys(test)]));
  
  const syscalls: SyscallData[] = allKeys.map(name => {
    const bCount = baseline[name] || 0;
    const tCount = test[name] || 0;
    
    let deviation = 0;
    if (bCount === 0 && tCount > 0) {
      // NEW BEHAVIOR: Extremely high signal in IDS
      deviation = 500; 
    } else if (bCount > 0) {
      deviation = (Math.abs(tCount - bCount) / bCount) * 100;
    }

    return {
      name,
      baseline: bCount,
      test: tCount,
      deviation
    };
  });

  syscalls.sort((a, b) => b.deviation - a.deviation);

  const avgDeviation = syscalls.reduce((acc, curr) => acc + curr.deviation, 0) / (syscalls.length || 1);

  return { syscalls, avgDeviation };
};

export const getSampleCSV = (type: 'normal' | 'intrusion'): string => {
  if (type === 'normal') {
    return `read,450\nwrite,380\nopenat,120\nclose,115\nmmap,90\nmprotect,40\nioctl,25`;
  }
  return `read,850\nwrite,900\nopenat,450\nclose,430\nmmap,120\nmprotect,850\nexecve,15\nsocket,22\nconnect,18`;
};
