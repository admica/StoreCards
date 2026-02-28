'use client'

import { Toaster } from 'sonner'
import { useTheme } from '@/app/providers/theme-provider'

export function ToasterWithTheme() {
    const { theme } = useTheme()

    return (
        <Toaster
            theme={theme}
            position="top-center"
            richColors
            offset={16}
            toastOptions={{
                duration: 4000,
                classNames: {
                    toast: 'rounded-xl text-sm',
                },
            }}
        />
    )
}
