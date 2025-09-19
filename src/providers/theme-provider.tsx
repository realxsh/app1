'use client';

import { ThemeProvider as NextThemesProvider } from 'next-themes';
import * as React from 'react';

interface ThemeProviderProps {
    children: React.ReactNode;
    [key: string]: unknown;
}

export function ThemeProvider({ children, ...props }: ThemeProviderProps) {
    return (
        <NextThemesProvider
            attribute="class"
            defaultTheme="system"
            enableSystem
            {...props}
        >
            {children}
        </NextThemesProvider>
    );
}
