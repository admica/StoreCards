'use client'

import { useFormStatus } from 'react-dom'

interface SubmitButtonProps {
    label: string
    pendingLabel?: string
    className?: string
}

export function SubmitButton({ label, pendingLabel = 'Saving...', className = '' }: SubmitButtonProps) {
    const { pending } = useFormStatus()

    return (
        <button
            type="submit"
            disabled={pending}
            className={`flex w-full justify-center items-center gap-2 rounded-xl bg-gradient-to-r from-accent to-accent-light px-4 py-3.5 text-sm font-semibold text-white shadow-lg shadow-accent/25 hover:shadow-accent/40 hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 transition-all ${className}`}
        >
            {pending ? (
                <>
                    <svg
                        className="animate-spin h-4 w-4 text-white"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                    >
                        <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                        />
                        <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                        />
                    </svg>
                    {pendingLabel}
                </>
            ) : (
                label
            )}
        </button>
    )
}
