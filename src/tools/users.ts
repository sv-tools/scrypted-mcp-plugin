import { z } from 'zod';
import { getComponent } from '../scrypted';

interface UsersComponent {
    getAllUsers(): Promise<Array<{ username: string; admin: boolean }>>;
    addUserInternal(username: string, password: string, aclId?: string): Promise<unknown>;
    removeUser(username: string): Promise<void>;
}

export const listUsersInput = z.object({});

export async function listUsers() {
    const users = await getComponent<UsersComponent>('users');
    const all = await users.getAllUsers();
    return { count: all.length, users: all };
}

export const addUserInput = z.object({
    username: z.string().min(1).describe('Login username for the new Scrypted user.'),
    password: z.string().min(1).describe('Password for the new user. Stored hashed (sha256+salt) on the server.'),
    aclId: z
        .string()
        .optional()
        .describe(
            'Optional ACL device id. If omitted the user is created as an admin (Scrypted treats absence of aclId as admin).',
        ),
});

export async function addUser(args: z.infer<typeof addUserInput>) {
    const users = await getComponent<UsersComponent>('users');
    await users.addUserInternal(args.username, args.password, args.aclId);
    return { added: args.username, admin: !args.aclId };
}

export const removeUserInput = z.object({
    username: z.string().describe('Username to delete.'),
});

export async function removeUser(args: z.infer<typeof removeUserInput>) {
    const users = await getComponent<UsersComponent>('users');
    await users.removeUser(args.username);
    return { removed: args.username };
}
