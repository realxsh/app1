import { initTRPC } from '@trpc/server';
import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import superjson from 'superjson';

// Initialize tRPC with a JSON transformer
const t = initTRPC.context<object>().create({
    transformer: superjson,
});
const router = t.router;
const publicProcedure = t.procedure;

// Root router with hello world route
const appRouter = router({
    hello: publicProcedure.query(() => 'Hello world'),
});

// Export type definition of the API
export type AppRouter = typeof appRouter;

// Next.js App Router handlers
const handler = (req: Request) =>
    fetchRequestHandler({
        endpoint: '/api/trpc',
        req,
        router: appRouter,
        createContext: () => ({}),
    });

export { handler as GET, handler as POST };
