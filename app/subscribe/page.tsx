'use client'

import { useActionState } from 'react'
import { useFormStatus } from 'react-dom'
import { continueWithFree } from '@/app/lib/actions'

const initialState = {
    error: '',
}

function PlanButton({ children, disabled }: { children: React.ReactNode; disabled?: boolean }) {
    const { pending } = useFormStatus()
    const isDisabled = disabled || pending

    return (
        <button
            type="submit"
            disabled={isDisabled}
            className="w-full rounded-xl bg-gradient-to-r from-accent to-accent-light px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-accent/25 hover:shadow-accent/40 hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 transition-all"
        >
            {pending ? 'Saving...' : children}
        </button>
    )
}

export default function SubscribePage() {
    const [state, formAction, _isPending] = useActionState(continueWithFree, initialState)

    return (
        <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <div className="absolute -top-40 -left-40 w-80 h-80 bg-accent/10 rounded-full blur-3xl" />
                <div className="absolute -bottom-40 -right-40 w-80 h-80 bg-accent/5 rounded-full blur-3xl" />
            </div>

            <div className="relative w-full max-w-3xl space-y-8 rounded-2xl bg-surface dark:bg-surface p-8 card-shadow dark:card-shadow-dark border border-border-light dark:border-border">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight text-primary">Choose your plan</h1>
                    <p className="mt-1 text-sm text-muted">
                        Start with the Free plan today. Upgrades are coming soon.
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <form action={formAction} className="h-full">
                        <div className="flex h-full flex-col gap-4 rounded-2xl border border-border-light dark:border-border bg-background dark:bg-surface-elevated p-6 shadow-sm">
                            <div className="space-y-1">
                                <p className="text-xs font-semibold uppercase tracking-wider text-accent">Free</p>
                                <h3 className="text-xl font-bold text-primary">Starter</h3>
                                <p className="text-3xl font-bold text-primary">$0</p>
                                <p className="text-sm text-muted">Keep all your cards organized for free.</p>
                            </div>
                            <ul className="space-y-2 text-sm text-primary/80 flex-1">
                                <li>• Unlimited cards</li>
                                <li>• Sync across devices</li>
                                <li>• Quick barcode access</li>
                            </ul>
                            <PlanButton>Continue with Free</PlanButton>
                        </div>
                    </form>

                    <div className="h-full">
                        <div className="flex h-full flex-col gap-4 rounded-2xl border border-border-light dark:border-border bg-background dark:bg-surface-elevated p-6 shadow-sm">
                            <div className="space-y-1">
                                <p className="text-xs font-semibold uppercase tracking-wider text-muted">Coming Soon</p>
                                <h3 className="text-xl font-bold text-primary">Monthly</h3>
                                <p className="text-3xl font-bold text-primary">$4</p>
                                <p className="text-sm text-muted">Future premium features and perks.</p>
                            </div>
                            <ul className="space-y-2 text-sm text-primary/60 flex-1">
                                <li>• Priority support</li>
                                <li>• Advanced analytics</li>
                                <li>• Cloud backups</li>
                            </ul>
                            <button
                                type="button"
                                disabled
                                className="w-full rounded-xl bg-gradient-to-r from-accent to-accent-light px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-accent/25 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                            >
                                Upgrade soon
                            </button>
                        </div>
                    </div>

                    <div className="h-full">
                        <div className="flex h-full flex-col gap-4 rounded-2xl border border-border-light dark:border-border bg-background dark:bg-surface-elevated p-6 shadow-sm">
                            <div className="space-y-1">
                                <p className="text-xs font-semibold uppercase tracking-wider text-muted">Coming Soon</p>
                                <h3 className="text-xl font-bold text-primary">Yearly</h3>
                                <p className="text-3xl font-bold text-primary">$40</p>
                                <p className="text-sm text-muted">Save with an annual plan when upgrades launch.</p>
                            </div>
                            <ul className="space-y-2 text-sm text-primary/60 flex-1">
                                <li>• Everything in Monthly</li>
                                <li>• Best value</li>
                                <li>• Early feature access</li>
                            </ul>
                            <button
                                type="button"
                                disabled
                                className="w-full rounded-xl bg-gradient-to-r from-accent to-accent-light px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-accent/25 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                            >
                                Upgrade soon
                            </button>
                        </div>
                    </div>
                </div>

                {state?.error && (
                    <div className="flex items-center gap-2 text-sm text-error bg-error/10 dark:bg-error/20 px-3 py-2 rounded-lg">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4 flex-shrink-0">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                        </svg>
                        {state.error}
                    </div>
                )}
            </div>
        </div>
    )
}
