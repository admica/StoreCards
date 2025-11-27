import { auth, signOut } from '@/auth'
import { prisma } from '@/lib/prisma'
import Link from 'next/link'
import { redirect } from 'next/navigation'

export default async function Dashboard() {
    const session = await auth()
    if (!session?.user?.email) {
        redirect('/login')
    }

    const cards = await prisma.card.findMany({
        where: {
            user: {
                email: session.user.email,
            },
        },
        orderBy: {
            createdAt: 'desc',
        },
    })

    return (
        <div className="min-h-screen bg-gray-50 pb-20">
            <header className="bg-white shadow">
                <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-6 sm:px-6 lg:px-8">
                    <h1 className="text-3xl font-bold tracking-tight text-gray-900">My Cards</h1>
                    <form
                        action={async () => {
                            'use server'
                            await signOut()
                        }}
                    >
                        <button
                            type="submit"
                            className="text-sm font-medium text-gray-500 hover:text-gray-700"
                        >
                            Sign out
                        </button>
                    </form>
                </div>
            </header>
            <main>
                <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
                    {cards.length === 0 ? (
                        <div className="flex flex-col items-center justify-center rounded-lg border-2 border-dashed border-gray-300 p-12 text-center">
                            <h3 className="mt-2 text-sm font-semibold text-gray-900">No cards</h3>
                            <p className="mt-1 text-sm text-gray-500">Get started by adding a new loyalty card.</p>
                            <div className="mt-6">
                                <Link
                                    href="/add"
                                    className="inline-flex items-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                                >
                                    Add Card
                                </Link>
                            </div>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
                            {cards.map((card) => (
                                <Link
                                    key={card.id}
                                    href={`/card/${card.id}`}
                                    className="relative flex items-center space-x-3 rounded-lg border border-gray-300 bg-white px-6 py-5 shadow-sm focus-within:ring-2 focus-within:ring-indigo-500 focus-within:ring-offset-2 hover:border-gray-400"
                                >
                                    <div className="min-w-0 flex-1">
                                        <span className="absolute inset-0" aria-hidden="true" />
                                        <p className="text-sm font-medium text-gray-900">{card.retailer}</p>
                                        <p className="truncate text-sm text-gray-500">{card.note}</p>
                                    </div>
                                </Link>
                            ))}
                        </div>
                    )}
                </div>
            </main>
            <div className="fixed bottom-6 right-6">
                <Link
                    href="/add"
                    className="flex h-14 w-14 items-center justify-center rounded-full bg-indigo-600 text-white shadow-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                >
                    <span className="sr-only">Add Card</span>
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-8 w-8">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
                    </svg>
                </Link>
            </div>
        </div>
    )
}
