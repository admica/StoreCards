'use client'
/* eslint-disable @next/next/no-img-element */

import { useActionState } from 'react'
import { useFormStatus } from 'react-dom'
import { createCard } from '@/app/lib/actions'
import { useState, useRef } from 'react'
import Link from 'next/link'

import LogoPicker from '@/components/logo-picker'
import { useBarcodeScanner } from '@/app/hooks/useBarcodeScanner'

export default function AddCardForm({ nerdMode }: { nerdMode: boolean }) {
    const [errorMessage, dispatch, _isPending] = useActionState(createCard, undefined)
    const [imagePreview, setImagePreview] = useState<string | null>(null)
    const [retailerName, setRetailerName] = useState('')
    const [selectedLogo, setSelectedLogo] = useState<string | null>(null)
    const [selectedColorLight, setSelectedColorLight] = useState<string | null>(null)
    const [selectedColorDark, setSelectedColorDark] = useState<string | null>(null)
    const [isLogoPickerOpen, setIsLogoPickerOpen] = useState(false)
    const fileInputRef = useRef<HTMLInputElement>(null)
    const imageFileInputRef = useRef<HTMLInputElement>(null)

    const {
        scannedResult,
        detectedFormat,
        isScanning,
        scanStatus,
        ref,
        setScannedResult,
        setDetectedFormat,
        setIsScanning,
        handleImageUpload: handleBarcodeImageUpload,
    } = useBarcodeScanner()

    // Auto-open logo picker when retailer name is entered and blurred
    const handleRetailerBlur = () => {
        if (retailerName && !selectedLogo) {
            setIsLogoPickerOpen(true)
        }
    }

    // Handle image upload: show preview and scan for barcode
    const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0]
        if (!file) return

        // Show preview
        const reader = new FileReader()
        reader.onload = (event) => {
            setImagePreview(event.target?.result as string)
        }
        reader.readAsDataURL(file)

        // Delegate barcode scanning to the hook
        await handleBarcodeImageUpload(e)
    }

    return (
        <div className="min-h-screen bg-background p-4 pb-24">
            <div className="mx-auto max-w-md rounded-2xl bg-surface dark:bg-surface p-6 card-shadow dark:card-shadow-dark border border-border-light dark:border-border">
                <div className="mb-6 flex items-center justify-between">
                    <h1 className="text-2xl font-bold text-primary">Add New Card</h1>
                    <Link href="/dashboard" className="text-sm font-medium text-accent hover:text-accent-dark transition-colors">
                        Cancel
                    </Link>
                </div>

                {/* Scanning Options */}
                <div className="mb-6 space-y-3">
                    {isScanning ? (
                        <div>
                            <div className="relative aspect-video w-full overflow-hidden rounded-xl bg-black">
                                <video ref={ref} className="h-full w-full object-cover" />
                                <button
                                    type="button"
                                    onClick={() => setIsScanning(false)}
                                    className="absolute top-3 right-3 rounded-full bg-white/90 dark:bg-surface px-4 py-2 text-sm font-medium text-primary hover:bg-white transition-colors"
                                >
                                    Close
                                </button>
                            </div>
                            <p className="mt-3 text-center text-sm text-muted">Point camera at barcode</p>
                        </div>
                    ) : (
                        <>
                            <button
                                type="button"
                                onClick={() => setIsScanning(true)}
                                className="flex w-full items-center justify-center gap-2 rounded-xl border border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-3 text-sm font-medium text-primary hover:bg-surface dark:hover:bg-border transition-colors"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-5 w-5 text-accent">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 013.75 9.375v-4.5zM3.75 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 01-1.125-1.125v-4.5zM13.5 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0113.5 9.375v-4.5z" />
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 6.75h.75v.75h-.75v-.75zM6.75 16.5h.75v.75h-.75v-.75zM16.5 6.75h.75v.75h-.75v-.75zM13.5 13.5h.75v.75h-.75v-.75zM13.5 19.5h.75v.75h-.75v-.75zM19.5 13.5h.75v.75h-.75v-.75zM19.5 19.5h.75v.75h-.75v-.75zM16.5 16.5h.75v.75h-.75v-.75z" />
                                </svg>
                                Scan with Camera
                            </button>

                            <button
                                type="button"
                                onClick={() => fileInputRef.current?.click()}
                                className="flex w-full items-center justify-center gap-2 rounded-xl border-2 border-dashed border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-4 text-sm font-medium text-primary hover:border-accent dark:hover:border-accent transition-colors"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-5 w-5 text-accent">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                                </svg>
                                Upload Photo to Scan Barcode
                            </button>
                            <input
                                ref={fileInputRef}
                                type="file"
                                accept="image/*"
                                onChange={handleImageUpload}
                                className="hidden"
                            />
                        </>
                    )}
                </div>

                {/* Scan Status Messages */}
                {scanStatus === 'scanning' && (
                    <div className="mb-4 p-3 bg-accent/10 border border-accent/20 rounded-xl flex items-center">
                        <svg className="animate-spin h-5 w-5 mr-3 text-accent" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        <p className="text-sm text-accent font-medium">Scanning image for barcode...</p>
                    </div>
                )}

                {scanStatus === 'success' && (
                    <div className="mb-4 p-3 bg-success/10 border border-success/20 rounded-xl flex items-center gap-2">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5 text-success">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <p className="text-sm text-success font-medium">Barcode detected! Fields auto-filled.</p>
                    </div>
                )}

                {scanStatus === 'error' && (
                    <div className="mb-4 p-3 bg-warning/10 border border-warning/20 rounded-xl">
                        <div className="flex items-center gap-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className="w-5 h-5 text-warning">
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                            </svg>
                            <p className="text-sm text-warning font-medium">No barcode found. You can still enter it manually.</p>
                        </div>
                    </div>
                )}

                {/* Image Preview */}
                {imagePreview && (
                    <div className="mb-4">
                        <label className="block text-sm font-medium text-primary mb-2">
                            Uploaded Image Preview
                        </label>
                        <img
                            src={imagePreview}
                            alt="Card preview"
                            className="w-full max-h-48 object-contain rounded-xl border border-border dark:border-border"
                        />
                    </div>
                )}

                <form action={dispatch} className="space-y-5">
                    <div>
                        <div className="flex items-center justify-between mb-1.5">
                            <label htmlFor="retailer" className="block text-sm font-medium text-primary">
                                Retailer Name *
                            </label>
                            <LogoPicker
                                searchTerm={retailerName}
                                onSelect={(selection) => {
                                    setSelectedLogo(selection.url || null)
                                    setSelectedColorLight(selection.colorLight || null)
                                    setSelectedColorDark(selection.colorDark || null)
                                }}
                                initialLogo={null}
                                isOpen={isLogoPickerOpen}
                                onOpenChange={setIsLogoPickerOpen}
                            />
                        </div>
                        <input
                            type="text"
                            name="retailer"
                            id="retailer"
                            required
                            value={retailerName}
                            onChange={(e) => setRetailerName(e.target.value)}
                            onBlur={handleRetailerBlur}
                            className="block w-full rounded-xl border border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-3 text-primary placeholder-muted shadow-sm focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 transition-all text-sm"
                            placeholder="e.g. Starbucks"
                        />
                        <input type="hidden" name="logo" value={selectedLogo || ''} />
                        <input type="hidden" name="colorLight" value={selectedColorLight || ''} />
                        <input type="hidden" name="colorDark" value={selectedColorDark || ''} />
                    </div>

                    <div>
                        <label htmlFor="barcodeValue" className="block text-sm font-medium text-primary mb-1.5">
                            Barcode Number
                        </label>
                        <input
                            type="text"
                            name="barcodeValue"
                            id="barcodeValue"
                            value={scannedResult}
                            onChange={(e) => setScannedResult(e.target.value)}
                            className="block w-full rounded-xl border border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-3 text-primary placeholder-muted shadow-sm focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 transition-all text-sm font-mono"
                            placeholder="Scanned or manually entered"
                        />
                    </div>

                    {nerdMode && (
                        <div>
                            <label htmlFor="barcodeFormat" className="block text-sm font-medium text-primary mb-1.5">
                                Barcode Format
                            </label>
                            <select
                                name="barcodeFormat"
                                id="barcodeFormat"
                                value={detectedFormat}
                                onChange={(e) => setDetectedFormat(e.target.value)}
                                className="block w-full rounded-xl border border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-3 text-primary shadow-sm focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 transition-all text-sm"
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
                    )}

                    {/* Hidden input to always submit the format */}
                    {!nerdMode && (
                        <input type="hidden" name="barcodeFormat" value={detectedFormat} />
                    )}

                    <div>
                        <label htmlFor="note" className="block text-sm font-medium text-primary mb-1.5">
                            Note (Optional)
                        </label>
                        <textarea
                            name="note"
                            id="note"
                            rows={3}
                            className="block w-full rounded-xl border border-border dark:border-border bg-background dark:bg-surface-elevated px-4 py-3 text-primary placeholder-muted shadow-sm focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20 transition-all text-sm resize-none"
                            placeholder="Add a note about this card..."
                        />
                    </div>

                    {nerdMode && (
                        <div>
                            <label htmlFor="image" className="block text-sm font-medium text-primary mb-1.5">
                                Card Image (Optional)
                            </label>
                            <p className="text-xs text-muted mb-2">
                                {imagePreview ? 'Image already uploaded above. Select a different file to replace it.' : 'Upload a photo of your card'}
                            </p>
                            <input
                                ref={imageFileInputRef}
                                type="file"
                                name="image"
                                id="image"
                                accept="image/*"
                                className="block w-full text-sm text-muted file:mr-4 file:py-2.5 file:px-4 file:rounded-xl file:border-0 file:text-sm file:font-medium file:bg-accent/10 file:text-accent hover:file:bg-accent/20 file:cursor-pointer file:transition-colors"
                            />
                        </div>
                    )}

                    <div className="pt-2">
                        <SubmitButton />
                    </div>
                    <div className="flex h-8 items-center justify-center" aria-live="polite" aria-atomic="true">
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
            className="flex w-full justify-center items-center gap-2 rounded-xl bg-gradient-to-r from-accent to-accent-light px-4 py-3.5 text-sm font-semibold text-white shadow-lg shadow-accent/25 hover:shadow-accent/40 hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 transition-all"
        >
            {pending ? (
                <>
                    <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Saving...
                </>
            ) : (
                'Save Card'
            )}
        </button>
    )
}
