'use client'

import { useFormState, useFormStatus } from 'react-dom'
import { createCard } from '@/app/lib/actions'
import { useState } from 'react'
import Link from 'next/link'
import { useZxing } from 'react-zxing'

export default function AddCardPage() {
    const [errorMessage, dispatch] = useFormState(createCard, undefined)
    const [scannedResult, setScannedResult] = useState('')
    const [isScanning, setIsScanning] = useState(false)

    const { ref } = useZxing({
        onDecodeResult(result) {
            setScannedResult(result.getText())
            setIsScanning(false)
        },
        paused: !isScanning,
    })

    return (
        <div className="min-h-screen bg-gray-50 p-4">
            <div className="mx-auto max-w-md rounded-lg bg-white p-6 shadow-md">
                <div className="mb-6 flex items-center justify-between">
                    <h1 className="text-2xl font-bold text-gray-900">Add New Card</h1>
                    <Link href="/" className="text-sm text-indigo-600 hover:text-indigo-500">
                        Cancel
                    </Link>
                </div>

                {isScanning ? (
                    <div className="mb-6">
                        <div className="relative aspect-video w-full overflow-hidden rounded-lg bg-black">
                            <video ref={ref} className="h-full w-full object-cover" />
                            <button
                                type="button"
                                onClick={() => setIsScanning(false)}
                                className="absolute top-2 right-2 rounded-full bg-white/80 p-2 text-gray-800"
                            >
                                Close
                            </button>
                        </div>
                        <p className="mt-2 text-center text-sm text-gray-500">Point camera at barcode</p>
                    </div>
                ) : (
                    <button
                        type="button"
                        onClick={() => setIsScanning(true)}
                        className="mb-6 flex w-full items-center justify-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50"
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="mr-2 h-5 w-5">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 013.75 9.375v-4.5zM3.75 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 01-1.125-1.125v-4.5zM13.5 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0113.5 9.375v-4.5z" />
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 6.75h.75v.75h-.75v-.75zM6.75 16.5h.75v.75h-.75v-.75zM16.5 6.75h.75v.75h-.75v-.75zM13.5 13.5h.75v.75h-.75v-.75zM13.5 19.5h.75v.75h-.75v-.75zM19.5 13.5h.75v.75h-.75v-.75zM19.5 19.5h.75v.75h-.75v-.75zM16.5 16.5h.75v.75h-.75v-.75z" />
                        </svg>
                        Scan Barcode
                    </button>
                )}

                <form action={dispatch} className="space-y-6">
                    <div>
                        <label htmlFor="retailer" className="block text-sm font-medium text-gray-700">
                            Retailer Name *
                        </label>
                        <input
                            type="text"
                            name="retailer"
                            id="retailer"
                            required
                            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm"
                            placeholder="e.g. Starbucks"
                        />
                    </div>

                    <div>
                        <label htmlFor="barcodeValue" className="block text-sm font-medium text-gray-700">
                            Barcode Number
                        </label>
                        <div className="flex space-x-2">
                            <input
                                type="text"
                                name="barcodeValue"
                                id="barcodeValue"
                                defaultValue={scannedResult}
                                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm"
                            />
                        </div>
                    </div>

                    <div>
                        <label htmlFor="barcodeFormat" className="block text-sm font-medium text-gray-700">
                            Barcode Format
                        </label>
                        <select
                            name="barcodeFormat"
                            id="barcodeFormat"
                            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm"
                        >
                            <option value="code128">Code 128</option>
                            <option value="ean13">EAN-13</option>
                            <option value="upca">UPC-A</option>
                            <option value="qrcode">QR Code</option>
                            <option value="pdf417">PDF417</option>
                            <option value="datamatrix">Data Matrix</option>
                            <option value="aztec">Aztec</option>
                            <option value="code39">Code 39</option>
                        </select>
                    </div>

                    <div>
                        <label htmlFor="note" className="block text-sm font-medium text-gray-700">
                            Note (Optional)
                        </label>
                        <textarea
                            name="note"
                            id="note"
                            rows={3}
                            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm"
                        />
                    </div>

                    <div>
                        <label htmlFor="image" className="block text-sm font-medium text-gray-700">
                            Card Image (Optional)
                        </label>
                        <input
                            type="file"
                            name="image"
                            id="image"
                            accept="image/*"
                            className="mt-1 block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100"
                        />
                    </div>

                    <div>
                        <SubmitButton />
                    </div>
                    <div className="flex h-8 items-end space-x-1" aria-live="polite" aria-atomic="true">
                        {errorMessage && <p className="text-sm text-red-500">{errorMessage}</p>}
                    </div>
                </form>
            </div>
        </div>
    )
}

function SubmitButton() {
    const { pending } = useFormStatus()

    return (
        <button
            type="submit"
            disabled={pending}
            className="flex w-full justify-center rounded-md border border-transparent bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:bg-gray-400"
        >
            {pending ? 'Saving...' : 'Save Card'}
        </button>
    )
}
