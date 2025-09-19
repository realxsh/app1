'use client';
import React from 'react';
import { authClient, useSession } from '@/server/auth/client';

export default function Home() {
    const { data } = useSession();
    const handleAuthRedirection = async () => {
        await authClient.signIn.oauth2({
            providerId: 'authx',
            scopes: ['openid', 'profile', 'email'],
        });
    };
    return (
        <>
            <button
                onClick={handleAuthRedirection}
                className="bg-white p-2 text-black"
            >
                Login app1
            </button>
            <h1>Welcome to App 1, {data?.user?.name}</h1>
        </>
    );
}
