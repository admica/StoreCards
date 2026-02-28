'use client'

import { BrowserMultiFormatReader, BarcodeFormat } from '@zxing/browser'
import { DecodeHintType } from '@zxing/library'
import { useState } from 'react'
import { useZxing } from 'react-zxing'
import { preprocessImage, getRotatedCanvases } from '@/app/lib/image-utils'

export type ScanStatus = 'idle' | 'scanning' | 'success' | 'error'
export type ScanErrorType = 'permission-denied' | 'camera-not-found' | 'decode-failure' | null

export interface UseBarcodeScanner {
    scannedResult: string
    detectedFormat: string
    isScanning: boolean
    scanStatus: ScanStatus
    scanErrorType: ScanErrorType
    ref: React.RefObject<HTMLVideoElement | null>
    setScannedResult: (value: string) => void
    setDetectedFormat: (value: string) => void
    setIsScanning: (value: boolean) => void
    handleImageUpload: (e: React.ChangeEvent<HTMLInputElement>) => Promise<void>
    startScanning: () => Promise<void>
    clearScanError: () => void
}

// Map ZXing format to our format strings
function mapBarcodeFormat(format: BarcodeFormat): string {
    const formatMap: Record<number, string> = {
        [BarcodeFormat.CODE_128]: 'code128',
        [BarcodeFormat.EAN_13]: 'ean13',
        [BarcodeFormat.UPC_A]: 'upca',
        [BarcodeFormat.QR_CODE]: 'qrcode',
        [BarcodeFormat.PDF_417]: 'pdf417',
        [BarcodeFormat.DATA_MATRIX]: 'datamatrix',
        [BarcodeFormat.AZTEC]: 'aztec',
        [BarcodeFormat.CODE_39]: 'code39',
    }
    return formatMap[format] || 'code128'
}

interface UseBarcodeOptions {
    initialBarcodeValue?: string
    initialBarcodeFormat?: string
}

export function useBarcodeScanner({
    initialBarcodeValue = '',
    initialBarcodeFormat = 'code128',
}: UseBarcodeOptions = {}): UseBarcodeScanner {
    const [scannedResult, setScannedResult] = useState(initialBarcodeValue)
    const [detectedFormat, setDetectedFormat] = useState(initialBarcodeFormat)
    const [isScanning, setIsScanning] = useState(false)
    const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
    const [scanErrorType, setScanErrorType] = useState<ScanErrorType>(null)

    const { ref } = useZxing({
        onResult(result) {
            setScannedResult(result.getText())
            setDetectedFormat(mapBarcodeFormat(result.getBarcodeFormat()))
            setIsScanning(false)
        },
        onError(error) {
            if (error.name === 'NotAllowedError') {
                setScanErrorType('permission-denied')
                setScanStatus('error')
                setIsScanning(false)
            } else if (error.name === 'NotFoundError') {
                setScanErrorType('camera-not-found')
                setScanStatus('error')
                setIsScanning(false)
            }
            // Other errors (decode errors during live scan) are normal — don't change state
        },
        paused: !isScanning,
    })

    // Proactively check camera permission before starting scanning
    const startScanning = async () => {
        try {
            const permission = await navigator.permissions.query({ name: 'camera' as PermissionName })
            if (permission.state === 'denied') {
                setScanErrorType('permission-denied')
                setScanStatus('error')
                return
            }
        } catch {
            // permissions.query not supported — fall through to useZxing
        }
        setScanErrorType(null)
        setScanStatus('idle')
        setIsScanning(true)
    }

    const clearScanError = () => {
        setScanErrorType(null)
        setScanStatus('idle')
    }

    const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0]
        if (!file) return

        // Scan for barcode with TRY_HARDER mode for better detection
        setScanStatus('scanning')
        try {
            const hints = new Map()
            hints.set(DecodeHintType.TRY_HARDER, true)

            const codeReader = new BrowserMultiFormatReader(hints)

            let result
            let foundBarcode = false

            // Method 1: Use preprocessed canvas with EXIF orientation handling
            // This should work for most mobile photos now
            try {
                const canvas = await preprocessImage(file)
                result = codeReader.decodeFromCanvas(canvas)
                foundBarcode = true
            } catch {
                console.log('Initial canvas decode failed, trying rotations...')
            }

            // Method 2: Try different rotations (in case EXIF handling didn't work)
            // This is a fallback for edge cases where the barcode might be rotated
            if (!foundBarcode) {
                try {
                    const canvas = await preprocessImage(file)
                    const rotatedCanvases = getRotatedCanvases(canvas)

                    for (let i = 0; i < rotatedCanvases.length; i++) {
                        try {
                            result = codeReader.decodeFromCanvas(rotatedCanvases[i])
                            console.log(`Found barcode at rotation ${i * 90}°`)
                            foundBarcode = true
                            break
                        } catch {
                            // Try next rotation
                        }
                    }
                } catch (e) {
                    console.log('Rotation attempts failed:', e)
                }
            }

            // Method 3: Try decoding directly from image element as last resort
            if (!foundBarcode) {
                console.log('Trying direct image element decode...')
                const imgElement = document.createElement('img')
                const imgUrl = URL.createObjectURL(file)
                imgElement.src = imgUrl

                await new Promise<void>((resolve, reject) => {
                    imgElement.onload = () => resolve()
                    imgElement.onerror = () => reject(new Error('Failed to load image'))
                })

                try {
                    result = await codeReader.decodeFromImageElement(imgElement)
                    foundBarcode = true
                } finally {
                    URL.revokeObjectURL(imgUrl)
                }
            }

            if (!foundBarcode || !result) {
                throw new Error('No barcode found in image')
            }

            // Success! Found a barcode
            setScannedResult(result.getText())
            setDetectedFormat(mapBarcodeFormat(result.getBarcodeFormat()))
            setScanStatus('success')
        } catch (error) {
            console.error('Barcode detection failed:', error)
            setScanErrorType('decode-failure')
            setScanStatus('error')
            // User can still manually enter barcode
        }
    }

    return {
        scannedResult,
        detectedFormat,
        isScanning,
        scanStatus,
        scanErrorType,
        ref,
        setScannedResult,
        setDetectedFormat,
        setIsScanning,
        handleImageUpload,
        startScanning,
        clearScanError,
    }
}
