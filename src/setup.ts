import { stdin, stdout } from 'node:process';
import { createInterface } from 'node:readline/promises';
import { displayPath, saveConfig } from './config.js';

// Prompt that hides keystrokes — used for the password. Node's readline doesn't have a
// built-in masked input, so we put stdin in raw mode and consume bytes ourselves.
async function promptHidden(question: string): Promise<string> {
    stdout.write(question);
    if (!stdin.isTTY) {
        // Non-TTY (piped) input: fall back to plain readline. The hidden behavior is a
        // UX nicety; piping defeats it but shouldn't error out.
        const rl = createInterface({ input: stdin, output: stdout });
        const answer = await rl.question('');
        rl.close();
        stdout.write('\n');
        return answer;
    }
    return new Promise<string>((resolve, reject) => {
        stdin.setRawMode(true);
        stdin.resume();
        stdin.setEncoding('utf8');
        let buf = '';
        // Use explicit unicode escapes for the control bytes so the file stays portable
        // (literal 0x03/0x04/0x7f bytes in source are invisible in most editors).
        const ETX = ''; // Ctrl-C
        const EOT = ''; // Ctrl-D
        const DEL = ''; // backspace on most terminals
        const onData = (ch: string) => {
            switch (ch) {
                case '\n':
                case '\r':
                case EOT:
                    finish();
                    return;
                case ETX:
                    cleanup();
                    stdout.write('\n');
                    reject(new Error('aborted'));
                    return;
                case DEL:
                case '\b':
                    if (buf.length) buf = buf.slice(0, -1);
                    return;
                default:
                    if (ch.charCodeAt(0) >= 32) buf += ch;
            }
        };
        const cleanup = () => {
            stdin.setRawMode(false);
            stdin.pause();
            stdin.removeListener('data', onData);
        };
        const finish = () => {
            cleanup();
            stdout.write('\n');
            resolve(buf);
        };
        stdin.on('data', onData);
    });
}

export async function runSetup() {
    if (!stdin.isTTY) {
        console.error('setup must be run in an interactive terminal.');
        process.exit(1);
    }
    const rl = createInterface({ input: stdin, output: stdout });
    try {
        console.error('Configure Scrypted credentials. Press Ctrl-C to abort.');
        const baseUrl =
            (await rl.question('Scrypted URL [https://localhost:10443]: ')).trim() || 'https://localhost:10443';
        const username = (await rl.question('Username: ')).trim();
        if (!username) throw new Error('username is required');
        rl.close();
        const password = await promptHidden('Password: ');
        if (!password) throw new Error('password is required');
        const path = saveConfig({ baseUrl, username, password });
        console.error(`Saved credentials to ${displayPath(path)} (mode 0600).`);
    } catch (e: any) {
        rl.close();
        console.error(`setup failed: ${e?.message ?? e}`);
        process.exit(1);
    }
}
