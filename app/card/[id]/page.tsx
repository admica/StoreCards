import { auth } from '@/auth'
import { prisma } from '@/lib/prisma'
import { redirect, notFound } from 'next/navigation'
import Link from 'next/link'
import Barcode from '@/app/components/Barcode'
import { deleteCard } from '@/app/lib/actions'

export default async function CardPage({ params }: { params: { id: string } }) {
    const session = await auth()
    if (!session?.user?.email) {
        redirect('/login')
    }

    const card = await prisma.card.findUnique({
        where: { id: params.id },
        include: { user: true },
    })

    if (!card || card.user.email !== session.user.email) {
        notFound()
    }

    return (
        <div className="flex min-h-screen flex-col bg-white">
            <header className="flex items-center justify-between bg-gray-50 px-4 py-4 shadow-sm">
                <Link href="/" className="text-sm font-medium text-indigo-600 hover:text-indigo-500">
                    &larr; Back
                </Link>
                <h1 className="text-lg font-bold text-gray-900">{card.retailer}</h1>
                <form action={deleteCard.bind(null, card.id)}>
                    <button type="submit" className="text-sm text-red-600 hover:text-red-500">
                        Delete
                    </button>
                </form>
            </header>

            <main className="flex flex-1 flex-col items-center justify-center p-4">
                <div className="w-full max-w-md space-y-8 text-center">
                    <div className="rounded-xl bg-white p-8 shadow-lg ring-1 ring-gray-900/5">
                        {card.barcodeValue && card.barcodeFormat ? (
                            <div className="flex justify-center py-8">
                                <Barcode value={card.barcodeValue} format={card.barcodeFormat} />
                            </div>
                        ) : (
                            <div className="py-8 text-gray-400 italic">No barcode data</div>
                        )}

                        {card.image && (
                            <div className="mt-4">
                                <img src={card.image} alt="Card Image" className="mx-auto max-h-64 rounded-lg object-contain" />
                            </div>
                        )}

                        <div className="mt-6">
                            <p className="text-2xl font-mono font-bold tracking-wider text-gray-900">
                                {card.barcodeValue}
                            </p>
                            {card.note && <p className="mt-2 text-sm text-gray-500">{card.note}</p>}
                        </div>
                    </div>

                    <p className="text-xs text-gray-400">
                        Tip: Turn up your screen brightness for easier scanning.
                    </p>
                </div>
            </main>
        </div>
    )
}
