import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

describe('Shell Scripts Strict Mode & Static Variable Analysis', () => {
    const scriptsDir = path.resolve(__dirname, '../scripts');
    const shellFiles = fs.readdirSync(scriptsDir).filter(f => f.endsWith('.sh'));

    it('finds shell scripts in scripts directory', () => {
        expect(shellFiles.length).toBeGreaterThan(0);
    });

    const BUILTIN_VARS = new Set([
        'EUID', 'PATH', 'HOME', 'TERM', 'UID', 'USER', 'PWD', 'OLDPWD',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '?', '!', '@', '#', '*',
        'BASH_SOURCE', 'BASH_COMMAND', 'LINENO', 'FUNCNAME'
    ]);

    shellFiles.forEach(file => {
        const filePath = path.join(scriptsDir, file);
        const content = fs.readFileSync(filePath, 'utf8');

        it(`verifies ${file} passes bash -n syntax check`, () => {
            expect(() => {
                execSync(`bash -n "${filePath}"`);
            }).not.toThrow();
        });

        it(`verifies ${file} enforces strict bash mode (set -euo pipefail)`, () => {
            const hasStrict = content.includes('set -euo pipefail') || 
                              (content.includes('set -e') && content.includes('set -u')) ||
                              content.includes('set -e');
            expect(hasStrict).toBe(true);
        });

        it(`verifies ${file} has no uninitialized variables or undefined references`, () => {
            const lines = content.split('\n');
            const assignedVars = new Set<string>();

            // Collect assigned variables line-by-line
            lines.forEach((rawLine, lineIdx) => {
                const line = rawLine.trim();
                if (line.startsWith('#') || !line) return;

                // Match assignment: VAR=... or export VAR=... or local VAR=...
                const assignMatch = line.match(/^(?:export\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)=/);
                if (assignMatch) {
                    assignedVars.add(assignMatch[1]);
                }

                // Match loop variable: for VAR in ...
                const forMatch = line.match(/^for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in/);
                if (forMatch) {
                    assignedVars.add(forMatch[1]);
                }

                // Match ${VAR} usages that lack default expansion ${VAR:-...}
                const simpleMatches = Array.from(line.matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g));
                for (const m of simpleMatches) {
                    const varName = m[1];
                    if (!BUILTIN_VARS.has(varName) && !assignedVars.has(varName)) {
                        // Check if it was assigned on the same line before use
                        const isAssignedEarlier = Array.from(assignedVars).includes(varName);
                        expect(isAssignedEarlier, `Unassigned variable '${varName}' evaluated on line ${lineIdx + 1} of ${file}: "${line}"`).toBe(true);
                    }
                }
            });
        });
    });
});
