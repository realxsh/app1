'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { httpBatchLink } from '@trpc/client';
import { createTRPCReact } from '@trpc/react-query';
import * as React from 'react';
import superjson from 'superjson';
import type { AppRouter } from '@/server/trpc/router';

// Create tRPC React hooks
export const trpc = createTRPCReact<AppRouter>();

// Provider to wrap your app with both tRPC and React Query
export function TRPCProvider({ children }: React.PropsWithChildren<object>) {
    const [queryClient] = React.useState(() => new QueryClient());
    const [trpcClient] = React.useState(() =>
        trpc.createClient({
            links: [
                httpBatchLink({
                    url: '/api/trpc',
                    transformer: superjson,
                }),
            ],
        }),
    );

    return (
        <trpc.Provider client={trpcClient} queryClient={queryClient}>
            <QueryClientProvider client={queryClient}>
                {children}
            </QueryClientProvider>
        </trpc.Provider>
    );
}
