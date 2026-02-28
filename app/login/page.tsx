'use client'

import { useActionState, useState } from 'react'
import { authenticate } from '@/app/lib/actions'
import { loginSchema, validateField } from '@/app/lib/validation'
import { SubmitButton } from '@/app/components/SubmitButton'
import Link from 'next/link'

export default function Page() {
    const [errorMessage, dispatch, _isPending] = useActionState(authenticate, undefined)

    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

    return (
        <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
            {/* Decorative background elements */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="absolute -top-40 -right-40 w-80 h-80 bg-accent/10 rounded-full blur-3xl" />
                <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-accent/5 rounded-full blur-3xl" />
            </div>

            <div className="relative w-full max-w-md space-y-8 rounded-2xl bg-surface dark:bg-surface p-8 card-shadow dark:card-shadow-dark border border-border-light dark:border-border">
                {/* Logo/Header */}
                <div className="text-center">
                    <div className="mx-auto h-14 w-14 rounded-2xl bg-gradient-to-br from-accent to-accent-light flex items-center justify-center text-white text-2xl font-bold shadow-lg mb-4">
                        S
                    </div>
                    <h2 className="text-2xl font-bold tracking-tight text-primary">
                        Welcome back
                    </h2>
                    <p className="mt-2 text-sm text-muted">
                        Sign in to access your loyalty cards
                    </p>
                </div>

                <form action={dispatch} className="space-y-5">
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
                            onChange={(e) => {
                                setEmail(e.target.value)
                                if (fieldErrors.email) {
                                    const error = validateField(loginSchema, 'email', e.target.value)
                                    if (!error) setFieldErrors(prev => { const next = { ...prev }; delete next.email; return next })
                                }
                            }}
                            onBlur={(e) => {
                                const error = validateField(loginSchema, 'email', e.target.value)
                                if (error) setFieldErrors(prev => ({ ...prev, email: error }))
                                else setFieldErrors(prev => { const next = { ...prev }; delete next.email; return next })
                            }}
                            className={`block w-full rounded-xl border bg-background dark:bg-surface-elevated px-4 py-3 text-primary placeholder-muted shadow-sm focus:outline-none focus:ring-2 transition-all text-sm ${fieldErrors.email
                                ? 'border-error focus:border-error focus:ring-error/20'
                                : 'border-border dark:border-border focus:border-accent focus:ring-accent/20'}`}
                            placeholder="you@example.com"
                        />
                        {fieldErrors.email && (
                            <p className="mt-1 text-xs text-error" role="alert">{fieldErrors.email}</p>
                        )}
                    </div>

                    <div>
                        <label htmlFor="password" className="block text-sm font-medium text-primary mb-1.5">
                            Password
                        </label>
                        <input
                            id="password"
                            name="password"
                            type="password"
                            autoComplete="current-password"
                            required
                            value={password}
                            onChange={(e) => {
                                setPassword(e.target.value)
                                if (fieldErrors.password) {
                                    const error = validateField(loginSchema, 'password', e.target.value)
                                    if (!error) setFieldErrors(prev => { const next = { ...prev }; delete next.password; return next })
                                }
                            }}
                            onBlur={(e) => {
                                const error = validateField(loginSchema, 'password', e.target.value)
                                if (error) setFieldErrors(prev => ({ ...prev, password: error }))
                                else setFieldErrors(prev => { const next = { ...prev }; delete next.password; return next })
                            }}
                            className={`block w-full rounded-xl border bg-background dark:bg-surface-elevated px-4 py-3 text-primary placeholder-muted shadow-sm focus:outline-none focus:ring-2 transition-all text-sm ${fieldErrors.password
                                ? 'border-error focus:border-error focus:ring-error/20'
                                : 'border-border dark:border-border focus:border-accent focus:ring-accent/20'}`}
                            placeholder="••••••••"
                        />
                        {fieldErrors.password && (
                            <p className="mt-1 text-xs text-error" role="alert">{fieldErrors.password}</p>
                        )}
                    </div>

                    <div className="pt-2">
                        <SubmitButton label="Sign in" pendingLabel="Signing in..." />
                    </div>

                    <div
                        className="flex h-8 items-center justify-center"
                        aria-live="polite"
                        aria-atomic="true"
                    >
                        {errorMessage && (
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
                        Don&apos;t have an account?{' '}
                        <Link href="/register" className="font-semibold text-accent hover:text-accent-dark transition-colors">
                            Create one
                        </Link>
                    </p>
                </div>
            </div>
        </div>
    )
}
