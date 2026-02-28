/* eslint-disable @next/next/no-img-element */
import { auth } from '@/auth'
import { prisma } from '@/lib/prisma'
import Link from 'next/link'
import { redirect } from 'next/navigation'

function formatRelativeTime(date: Date | null): string {
    if (!date) return 'Never used'

    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)
    const diffDays = Math.floor(diffMs / 86400000)

    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays === 1) return 'Yesterday'
    if (diffDays < 7) return `${diffDays}d ago`
    if (diffDays < 30) return `${Math.floor(diffDays / 7)}w ago`
    return date.toLocaleDateString()
}

function getGradient(name: string) {
    const gradients = [
        'from-blue-500 to-cyan-400',
        'from-purple-500 to-pink-400',
        'from-emerald-500 to-teal-400',
        'from-orange-500 to-amber-400',
        'from-rose-500 to-red-400',
        'from-indigo-500 to-violet-400',
    ]
    const index = name.length % gradients.length
    return gradients[index]
}

export default async function Dashboard() {
    const session = await auth()
    if (!session?.user?.email) {
        redirect('/login')
    }

    const user = await prisma.user.findUnique({
        where: { email: session.user.email },
        select: { darkMode: true }
    })

    const isDarkMode = user?.darkMode || false

    const cards = await prisma.card.findMany({
        where: {
            user: {
                email: session.user.email,
            },
        },
        orderBy: {
            lastUsed: 'desc',
        },
    })

    return (
        <div className="min-h-screen bg-background pb-32">
            <main className="px-4 pt-6 pb-6 max-w-md mx-auto space-y-4">
                <div className="flex items-center justify-between">
                    <h1 className="text-xl font-semibold text-primary">Your cards</h1>
                    <Link
                        href="/subscribe"
                        className="text-sm font-semibold text-accent hover:text-accent-dark transition-colors"
                    >
                        Upgrade
                    </Link>
                </div>
                {cards.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-20 text-center">
                        <div className="h-20 w-20 rounded-full bg-accent/10 flex items-center justify-center mb-6">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-10 h-10 text-accent">
                                <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 8.25h19.5M2.25 9h19.5m-16.5 5.25h6m-6 2.25h3m-3.75 3h15a2.25 2.25 0 002.25-2.25V6.75A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25v10.5A2.25 2.25 0 004.5 19.5z" />
                            </svg>
                        </div>
                        <h3 className="text-lg font-semibold text-primary">No cards yet</h3>
                        <p className="text-muted mt-2 mb-8 max-w-xs">Add your first loyalty card to start organizing your wallet.</p>
                        <Link
                            href="/add"
                            className="rounded-full bg-gradient-to-r from-accent to-accent-light px-8 py-3 text-sm font-semibold text-white shadow-lg shadow-accent/30 hover:shadow-accent/40 hover:scale-[1.02] transition-all active:scale-95"
                        >
                            Add your first card
                        </Link>
                    </div>
                ) : (
                    <div className="grid gap-4">
                        {cards.map((card, index) => {
                            const hasCustomColors = card.colorLight && card.colorDark
                            const bgColor = hasCustomColors 
                                ? (isDarkMode ? card.colorDark : card.colorLight)
                                : null
                            
                            // Determine text colors based on background
                            const textColorClass = hasCustomColors && !isDarkMode
                                ? 'text-gray-800'
                                : 'text-white'
                            const mutedTextColorClass = hasCustomColors && !isDarkMode
                                ? 'text-gray-600'
                                : 'text-white/70'
                            
                            return (
                                <Link
                                    key={card.id}
                                    href={`/card/${card.id}`}
                                    className={`group relative overflow-hidden rounded-2xl p-6 shadow-lg transition-all hover:scale-[1.02] hover:shadow-xl active:scale-[0.98] animate-enter ${
                                        hasCustomColors 
                                            ? '' 
                                            : `bg-gradient-to-br ${getGradient(card.retailer)}`
                                    }`}
                                    style={{ 
                                        animationDelay: `${index * 50}ms`,
                                        ...(hasCustomColors ? { backgroundColor: bgColor! } : {})
                                    }}
                                >
                                    {/* Decorative glow effects */}
                                    <div className="absolute top-0 right-0 -mt-8 -mr-8 h-32 w-32 rounded-full bg-white/20 blur-2xl" />
                                    <div className="absolute bottom-0 left-0 -mb-8 -ml-8 h-32 w-32 rounded-full bg-black/10 blur-2xl" />

                                    <div className="relative z-10 flex justify-between items-start">
                                        <div className="flex-1">
                                            <h3 className={`text-xl font-bold tracking-tight ${textColorClass}`}>{card.retailer}</h3>
                                            {card.note && (
                                                <p className={`text-sm mt-1 truncate pr-4 ${mutedTextColorClass}`}>{card.note}</p>
                                            )}
                                        </div>
                                        {card.logo ? (
                                            <div className="h-16 w-16 rounded-xl bg-white p-2 shadow-lg flex items-center justify-center overflow-hidden">
                                                <img src={card.logo} alt={card.retailer} className="h-full w-full object-contain" />
                                            </div>
                                        ) : (
                                            <div className="h-16 w-16 rounded-xl bg-white/20 backdrop-blur-sm flex items-center justify-center text-white font-bold text-2xl shadow-sm">
                                                {card.retailer[0].toUpperCase()}
                                            </div>
                                        )}
                                    </div>

                                    <div className="relative z-10 mt-6 flex items-end justify-between">
                                        <div className="flex flex-col">
                                            <span className={`text-[10px] font-medium uppercase tracking-wider ${mutedTextColorClass}`}>Last Used</span>
                                            <span className={`text-xs font-semibold mt-0.5 ${textColorClass}`}>{formatRelativeTime(card.lastUsed)}</span>
                                        </div>
                                    </div>
                                </Link>
                            )
                        })}
                    </div>
                )}
            </main>
        </div>
    )
}
