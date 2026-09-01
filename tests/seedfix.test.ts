import { describe, it, expect } from 'vitest';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

function levenshtein(a: string, b: string): number {
    if (a === b) return 0;
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

function getValid12thWords(words11: string[]): string[] {
    const valid: string[] = [];
    for (const w of wordlist) {
        const full = [...words11, w].join(' ');
        if (bip39.validateMnemonic(full, wordlist)) {
            valid.push(w);
        }
    }
    return valid;
}

describe('BIP-39 SeedFix 12th-Word Candidate Solver', () => {
    it('finds exactly 128 mathematically valid 12th words for any 11 words', () => {
        const words11 = "salt option burden habit silent tone breeze fade idle dilemma subway".split(' ');
        const valid = getValid12thWords(words11);
        expect(valid.length).toBe(128);
        expect(valid.includes('mix')).toBe(true);
        expect(valid.includes('fix')).toBe(false);
    });

    it('ranks "mix" as Rank 1 when typo "fix" is entered', () => {
        const words11 = "salt option burden habit silent tone breeze fade idle dilemma subway".split(' ');
        const valid = getValid12thWords(words11);
        
        const typo = 'fix';
        valid.sort((a, b) => {
            const distA = levenshtein(typo, a);
            const distB = levenshtein(typo, b);
            if (distA !== distB) return distA - distB;
            return a.localeCompare(b);
        });

        expect(valid[0]).toBe('mix');
        expect(levenshtein(typo, valid[0])).toBe(1);
    });
});
