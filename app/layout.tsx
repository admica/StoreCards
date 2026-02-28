import type { Metadata, Viewport } from 'next'
import { Inter } from 'next/font/google'
import Script from 'next/script'
import './globals.css'
import BottomNav from './components/BottomNav'
import { ThemeProvider } from './providers/theme-provider'
import { auth } from '@/auth'
import { prisma } from '@/lib/prisma'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
    title: 'StoreCard - Your Loyalty Cards',
    description: 'Organize and access your store loyalty cards instantly.',
    generator: 'Next.js',
    manifest: '/manifest.json',
    keywords: ['loyalty cards', 'wallet', 'store cards', 'digital wallet'],
    authors: [{ name: 'StoreCard Team' }],
    icons: [
        { rel: 'apple-touch-icon', url: '/icon-192.png' },
        { rel: 'icon', url: '/icon-192.png' },
    ],
}

export const viewport: Viewport = {
    width: 'device-width',
    initialScale: 1,
    maximumScale: 1,
    userScalable: false, // Prevent zooming on mobile for app-like feel
}

async function getInitialTheme(): Promise<'light' | 'dark'> {
    try {
        const session = await auth()
        if (session?.user?.email) {
            const user = await prisma.user.findUnique({
                where: { email: session.user.email },
                select: { darkMode: true }
            })
            return user?.darkMode ? 'dark' : 'light'
        }
    } catch {
        // If auth fails, default to light
    }
    return 'light'
}

export default async function RootLayout({
    children,
}: {
    children: React.ReactNode
}) {
    const initialTheme = await getInitialTheme()
    
    return (
        <html lang="en" className={initialTheme === 'dark' ? 'dark no-transitions' : 'no-transitions'}>
            <body className={`${inter.className} bg-background text-primary antialiased`}>
                <ThemeProvider initialTheme={initialTheme}>
                    {children}
                    <BottomNav />
                </ThemeProvider>
                <Script
                    id="register-sw"
                    strategy="afterInteractive"
                    dangerouslySetInnerHTML={{
                        __html: `if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js'); }`,
                    }}
                />
            </body>
        </html>
    )
}
