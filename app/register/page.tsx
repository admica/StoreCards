'use client'

import { useActionState } from 'react'
import { useFormStatus } from 'react-dom'
import { register } from '@/app/lib/actions'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useEffect, useRef, useState } from 'react'

export default function Page() {
    const [errorMessage, dispatch, _isPending] = useActionState(register, undefined)
    const router = useRouter()
    const formRef = useRef<HTMLFormElement>(null)
    const [email, setEmail] = useState('')

    // Handle successful registration redirect
    useEffect(() => {
        if (errorMessage === 'success') {
            router.push('/subscribe')
        }
    }, [errorMessage, router, email])

    return (
        <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
            {/* Decorative background elements */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="absolute -top-40 -left-40 w-80 h-80 bg-accent/10 rounded-full blur-3xl" />
                <div className="absolute -bottom-40 -right-40 w-80 h-80 bg-accent/5 rounded-full blur-3xl" />
            </div>

            <div className="relative w-full max-w-md space-y-8 rounded-2xl bg-surface dark:bg-surface p-8 card-shadow dark:card-shadow-dark border border-border-light dark:border-border">
                {/* Logo/Header */}
                <div className="text-center">
                    <div className="mx-auto h-14 w-14 rounded-2xl bg-gradient-to-br from-accent to-accent-light flex items-center justify-center text-white text-2xl font-bold shadow-lg mb-4">
                        S
                    </div>
                    <h2 className="text-2xl font-bold tracking-tight text-primary">
                        Create your account
                    </h2>
                    <p className="mt-2 text-sm text-muted">
                        Start organizing your loyalty cards today
                    </p>
                </div>

                <form ref={formRef} action={dispatch} className="space-y-5">
                    <div>
                        <label htmlFor="email" className="block text-sm font-medium text-primary mb-1.5">
                            Email address
                        </label>
                        <input
                            id="email"
                            name="email"
                            type="email"
                            autoComplete="email"
                            required
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            className="block w-full rounded-xl border border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-3 text-primary placeholder-muted shadow-sm focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 transition-all text-sm"
                            placeholder="you@example.com"
                        />
                    </div>

                    <div>
                        <label htmlFor="password" className="block text-sm font-medium text-primary mb-1.5">
                            Password
                        </label>
                        <input
                            id="password"
                            name="password"
                            type="password"
                            autoComplete="new-password"
                            required
                            className="block w-full rounded-xl border border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-3 text-primary placeholder-muted shadow-sm focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 transition-all text-sm"
                            placeholder="••••••••"
                        />
                        <p className="mt-1.5 text-xs text-muted">Must be at least 6 characters</p>
                    </div>

                    <div className="pt-2">
                        <RegisterButton />
                    </div>

                    <div
                        className="flex h-8 items-center justify-center"
                        aria-live="polite"
                        aria-atomic="true"
                    >
                        {errorMessage && errorMessage !== 'success' && (
                            <div className="flex items-center gap-2 text-sm text-error">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                                </svg>
                                {errorMessage}
                            </div>
                        )}
                    </div>
                </form>

                <div className="text-center">
                    <p className="text-sm text-muted">
                        Already have an account?{' '}
                        <Link href="/login" className="font-semibold text-accent hover:text-accent-dark transition-colors">
                            Sign in
                        </Link>
                    </p>
                </div>
            </div>
        </div>
    )
}

function RegisterButton() {
    const { pending } = useFormStatus()

    return (
        <button
            type="submit"
            disabled={pending}
            className="flex w-full justify-center items-center gap-2 rounded-xl bg-gradient-to-r from-accent to-accent-light px-4 py-3.5 text-sm font-semibold text-white shadow-lg shadow-accent/25 hover:shadow-accent/40 hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 transition-all"
        >
            {pending ? (
                <>
                    <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Creating account...
                </>
            ) : (
                'Create account'
            )}
        </button>
    )
}
