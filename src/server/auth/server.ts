import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { db } from '@/server/db';
import { nextCookies } from 'better-auth/next-js';
import { admin, genericOAuth } from 'better-auth/plugins';
import { sendEmail } from '@/lib/email';
import {
    createVerificationEmail,
    createResetPasswordEmail,
} from '@/lib/email-templates';

if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not set');
}

export const auth = betterAuth({
    database: drizzleAdapter(db, {
        provider: 'pg',
        usePlural: true,
    }),
    plugins: [
        nextCookies(),
        admin({
            defaultRole: 'user',
            impersonationSessionDuration: 60 * 60 * 24,
        }),
        genericOAuth({
            config: [
                {
                    providerId: 'authx',
                    clientId: 'client_o6gd5avj04gtiiwbg7w8m',
                    clientSecret: 'secret_ba8t5vny2mv8jnxurdlh1b',
                    scopes: ['openid', 'profile', 'email'],
                    discoveryUrl:
                        'http://localhost:3000/api/auth/.well-known/openid-configuration',
                    redirectURI:
                        'http://localhost:3002/api/auth/oauth2/callback/authx',
                },
            ],
        }),
    ],
    trustedOrigins: ['http://localhost:3002', 'http://localhost:3001'],
    emailVerification: {
        sendVerificationEmail: async ({ user, url }) => {
            const { subject, html } = createVerificationEmail(url);
            await sendEmail({ to: user.email, subject, html });
        },
        sendOnSignUp: true,
        autoSignInAfterVerification: true,
        expiresIn: 3600,
    },
    emailAndPassword: {
        enabled: true,
        disableSignUp: true,
        requireEmailVerification: true,
        minPasswordLength: 8,
        maxPasswordLength: 128,
        autoSignIn: true,
        sendResetPassword: async ({ user, url }) => {
            const { subject, html } = createResetPasswordEmail(url);
            await sendEmail({ to: user.email, subject, html });
        },
        resetPasswordTokenExpiresIn: 3600,
    },
    session: {
        cookieCache: {
            enabled: true,
            maxAge: 5 * 60,
        },
    },
});

export async function getUserSession(headers?: Headers) {
    return auth.api.getSession({
        headers: headers ?? new Headers(),
    });
}
