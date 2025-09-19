import { createAuthClient } from 'better-auth/react';
import {
    adminClient,
    genericOAuthClient,
    inferAdditionalFields,
} from 'better-auth/client/plugins';
import type { auth } from './server';

export const authClient = createAuthClient({
    baseURL: process.env.NEXT_PUBLIC_APP_URL,
    plugins: [
        inferAdditionalFields<typeof auth>(),
        adminClient(),
        genericOAuthClient(),
    ],
});

export const { signIn, signOut, signUp, useSession } = authClient;
