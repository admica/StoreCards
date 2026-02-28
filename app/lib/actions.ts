'use server'

import { signIn, auth } from '@/auth'
import { prisma } from '@/lib/prisma'
import bcrypt from 'bcryptjs'
import { AuthError } from 'next-auth'
import { z } from 'zod'
import { revalidatePath } from 'next/cache'
import { redirect } from 'next/navigation'
import { writeFile, mkdir, unlink } from 'fs/promises'
import { randomUUID } from 'crypto'
import path from 'path'
import { SubscriptionStatus, SubscriptionTier } from '@prisma/client'
import sharp from 'sharp'

const ALLOWED_IMAGE_FORMATS = ['jpeg', 'png', 'webp'] as const

async function processUploadedImage(buffer: Buffer): Promise<Buffer> {
    let metadata
    try {
        metadata = await sharp(buffer).metadata()
    } catch {
        throw new Error('Only JPG, PNG, and WebP images are accepted.')
    }
    if (!metadata.format || !ALLOWED_IMAGE_FORMATS.includes(metadata.format as typeof ALLOWED_IMAGE_FORMATS[number])) {
        throw new Error('Only JPG, PNG, and WebP images are accepted.')
    }
    return sharp(buffer)
        .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
        .webp({ quality: 80 })
        .toBuffer()
}

const ALLOWED_BARCODE_FORMATS = [
    'code128', 'ean13', 'upca', 'qrcode', 'pdf417', 'datamatrix', 'aztec', 'code39'
] as const

function validateBarcodeFormat(format: string | null | undefined): string | null {
    if (!format) return null
    return (ALLOWED_BARCODE_FORMATS as readonly string[]).includes(format.toLowerCase())
        ? format.toLowerCase()
        : null
}

type ClearbitSuggestion = {
    name: string
    domain: string
    logo: string
}

type LogoDevResult = {
    name?: string | null
    domain?: string | null
    logo_url: string
}

export async function authenticate(prevState: string | undefined, formData: FormData) {
    try {
        await signIn('credentials', formData)
    } catch (error) {
        if (error instanceof AuthError) {
            switch (error.type) {
                case 'CredentialsSignin':
                    return 'Invalid credentials.'
                default:
                    return 'Something went wrong.'
            }
        }
        throw error
    }
}

export async function register(prevState: string | undefined, formData: FormData) {
    try {
        const email = formData.get('email') as string
        const password = formData.get('password') as string

        const parsed = z.object({
            email: z.string().email(),
            password: z.string().min(6),
        }).safeParse({ email, password })

        if (!parsed.success) {
            return 'Invalid fields'
        }

        const existingUser = await prisma.user.findUnique({
            where: { email },
        })

        if (existingUser) {
            return 'User already exists.'
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
            },
        })

        await prisma.subscription.create({
            data: {
                userId: user.id,
                tier: SubscriptionTier.FREE,
                status: SubscriptionStatus.INACTIVE,
            },
        })

        // Sign the user in immediately so they can pick a plan
        await signIn('credentials', { redirect: false, email, password })

        return 'success'

    } catch (error) {
        if (error instanceof Error) {
            if (error.message.includes('connect')) {
                return 'Database connection failed. Please try again.'
            }
        }

        return 'Failed to create account. Please try again.'
    }
}

export async function createCard(prevState: string | undefined, formData: FormData) {
    const session = await auth()
    if (!session?.user?.email) {
        return 'Not authenticated'
    }

    const user = await prisma.user.findUnique({
        where: { email: session.user.email },
    })

    if (!user) {
        return 'User not found'
    }

    const retailer = formData.get('retailer') as string
    const note = formData.get('note') as string
    const barcodeValue = formData.get('barcodeValue') as string
    const barcodeFormat = formData.get('barcodeFormat') as string
    const imageFile = formData.get('image') as File
    const logo = formData.get('logo') as string
    const colorLight = formData.get('colorLight') as string
    const colorDark = formData.get('colorDark') as string

    if (!retailer) {
        return 'Retailer name is required'
    }

    const MAX_FILE_SIZE = 5 * 1024 * 1024 // 5MB

    const validatedFormat = validateBarcodeFormat(barcodeFormat)

    let imagePath = null
    if (imageFile && imageFile.size > 0) {
        if (imageFile.size > MAX_FILE_SIZE) {
            return 'Image must be under 5MB'
        }
        try {
            const rawBuffer = Buffer.from(await imageFile.arrayBuffer())
            const processedBuffer = await processUploadedImage(rawBuffer)
            const filename = `${randomUUID()}.webp`
            const uploadsDir = path.join(process.cwd(), 'public', 'uploads')
            await mkdir(uploadsDir, { recursive: true })
            await writeFile(path.join(uploadsDir, filename), processedBuffer)
            imagePath = `/uploads/${filename}`
        } catch (err) {
            if (err instanceof Error && err.message.includes('Only JPG')) {
                return err.message
            }
            // Continue without image for other errors rather than failing completely
        }
    }

    await prisma.card.create({
        data: {
            retailer,
            barcodeValue,
            barcodeFormat: validatedFormat,
            note,
            image: imagePath,
            logo: logo || null,
            colorLight: colorLight || null,
            colorDark: colorDark || null,
            userId: user.id,
        },
    })

    // Cache logo and colors if provided
    if (logo) {
        const normalizedName = retailer.toLowerCase().trim()
            .replace(/\s+(store|inc|llc|ltd|corp|corporation)$/g, '')
            .trim()

        try {
            await prisma.brandLogo.upsert({
                where: { name: normalizedName },
                update: {
                    logoUrl: logo,
                    ...(colorLight ? { colorLight } : {}),
                    ...(colorDark ? { colorDark } : {}),
                },
                create: {
                    name: normalizedName,
                    logoUrl: logo,
                    colorLight: colorLight || null,
                    colorDark: colorDark || null,
                }
            })
        } catch {
            // Logo caching is best-effort
        }
    }

    revalidatePath('/dashboard')
    redirect('/dashboard')
}

export async function deleteCard(id: string) {
    const session = await auth()
    if (!session?.user?.email) return

    const card = await prisma.card.findUnique({
        where: { id },
        include: { user: true }
    })

    if (card && card.user.email === session.user.email) {
        await prisma.card.delete({ where: { id } })
        if (card.image) {
            const filePath = path.join(process.cwd(), 'public', card.image)
            await unlink(filePath).catch(() => {})
        }
        revalidatePath('/dashboard')
        redirect('/dashboard')
    }
}

export async function updateCard(id: string, prevState: string | undefined, formData: FormData) {
    const session = await auth()
    if (!session?.user?.email) {
        return 'Not authenticated'
    }

    const retailer = formData.get('retailer') as string
    const note = formData.get('note') as string
    const barcodeValue = formData.get('barcodeValue') as string
    const barcodeFormat = formData.get('barcodeFormat') as string
    const imageFile = formData.get('image') as File
    const logo = formData.get('logo') as string
    const colorLight = formData.get('colorLight') as string
    const colorDark = formData.get('colorDark') as string

    if (!retailer) {
        return 'Retailer name is required'
    }

    const existingCard = await prisma.card.findUnique({
        where: { id },
        include: { user: true }
    })

    if (!existingCard || existingCard.user.email !== session.user.email) {
        return 'Card not found or unauthorized'
    }

    const MAX_FILE_SIZE = 5 * 1024 * 1024 // 5MB

    const validatedFormat = validateBarcodeFormat(barcodeFormat)

    let imagePath = existingCard.image
    if (imageFile && imageFile.size > 0) {
        if (imageFile.size > MAX_FILE_SIZE) {
            return 'Image must be under 5MB'
        }
        try {
            const rawBuffer = Buffer.from(await imageFile.arrayBuffer())
            const processedBuffer = await processUploadedImage(rawBuffer)
            const filename = `${randomUUID()}.webp`
            const uploadsDir = path.join(process.cwd(), 'public', 'uploads')
            await mkdir(uploadsDir, { recursive: true })
            await writeFile(path.join(uploadsDir, filename), processedBuffer)
            // Clean up old image file after new one is written successfully
            if (existingCard.image) {
                const oldPath = path.join(process.cwd(), 'public', existingCard.image)
                await unlink(oldPath).catch(() => {})
            }
            imagePath = `/uploads/${filename}`
        } catch (err) {
            if (err instanceof Error && err.message.includes('Only JPG')) {
                return err.message
            }
            // Keep existing image for other errors
        }
    }

    await prisma.card.update({
        where: { id },
        data: {
            retailer,
            note,
            barcodeValue,
            barcodeFormat: validatedFormat,
            image: imagePath,
            ...(logo ? { logo } : {}),
            ...(colorLight ? { colorLight } : {}),
            ...(colorDark ? { colorDark } : {}),
        },
    })

    // Cache logo and colors if provided
    if (logo) {
        const normalizedName = retailer.toLowerCase().trim()
            .replace(/\s+(store|inc|llc|ltd|corp|corporation)$/g, '')
            .trim()

        try {
            await prisma.brandLogo.upsert({
                where: { name: normalizedName },
                update: {
                    logoUrl: logo,
                    ...(colorLight ? { colorLight } : {}),
                    ...(colorDark ? { colorDark } : {}),
                },
                create: {
                    name: normalizedName,
                    logoUrl: logo,
                    colorLight: colorLight || null,
                    colorDark: colorDark || null,
                }
            })
        } catch {
            // Logo caching is best-effort
        }
    }

    revalidatePath('/dashboard')
    revalidatePath(`/card/${id}`)
    redirect(`/card/${id}`)
}

export async function updateLastUsed(cardId: string) {
    const session = await auth()
    if (!session?.user?.email) return

    const card = await prisma.card.findUnique({
        where: { id: cardId },
        include: { user: true }
    })

    if (card && card.user.email === session.user.email) {
        await prisma.card.update({
            where: { id: cardId },
            data: { lastUsed: new Date() }
        })
        revalidatePath('/dashboard')
    }
}

export async function updateNerdMode(enabled: boolean) {
    const session = await auth()
    if (!session?.user?.email) return

    await prisma.user.update({
        where: { email: session.user.email },
        data: { nerdMode: enabled }
    })

    revalidatePath('/settings')
    revalidatePath('/add')
    revalidatePath('/card/[id]/edit')
}

export async function updateDarkMode(enabled: boolean) {
    const session = await auth()
    if (!session?.user?.email) return

    await prisma.user.update({
        where: { email: session.user.email },
        data: { darkMode: enabled }
    })

    revalidatePath('/settings')
    revalidatePath('/')
}

export async function continueWithFree(_prevState: { error: string }): Promise<{ error: string }> {
    const session = await auth()
    if (!session?.user?.email) {
        return { error: 'Not authenticated' }
    }

    const user = await prisma.user.findUnique({
        where: { email: session.user.email },
        select: { id: true },
    })

    if (!user) {
        return { error: 'User not found' }
    }

    await prisma.subscription.upsert({
        where: { userId: user.id },
        update: {
            tier: SubscriptionTier.FREE,
            status: SubscriptionStatus.ACTIVE,
        },
        create: {
            userId: user.id,
            tier: SubscriptionTier.FREE,
            status: SubscriptionStatus.ACTIVE,
        },
    })

    await prisma.user.update({
        where: { id: user.id },
        data: { subscriptionSelected: true },
    })

    revalidatePath('/dashboard')
    redirect('/dashboard')
}

export async function searchLogos(query: string) {
    if (!query || query.length < 2) return []

    // Normalize query
    const normalizedQuery = query.toLowerCase().trim()
        .replace(/\s+(store|inc|llc|ltd|corp|corporation)$/g, '')
        .trim()

    // 1. Check cache first
    const cachedLogo = await prisma.brandLogo.findUnique({
        where: { name: normalizedQuery }
    })

    const results: {
        source: 'cache' | 'api' | 'fallback';
        url: string;
        name: string;
        colorLight?: string | null;
        colorDark?: string | null;
    }[] = []

    if (cachedLogo) {
        results.push({
            source: 'cache',
            url: cachedLogo.logoUrl,
            name: query, // Use original query as display name
            colorLight: cachedLogo.colorLight,
            colorDark: cachedLogo.colorDark,
        })
    }

    // 2. Always add Google Favicon fallback
    // Try to guess domain by removing spaces
    const domainGuess = normalizedQuery.replace(/\s+/g, '')
    results.push({
        source: 'fallback',
        url: `https://www.google.com/s2/favicons?domain=${domainGuess}.com&sz=128`,
        name: `${query} (Favicon)`
    })

    // 3. Call Clearbit and logo.dev in parallel (PERF-03)
    const [clearbitResult, logoDevResult] = await Promise.allSettled([
        fetch(`https://autocomplete.clearbit.com/v1/companies/suggest?query=${encodeURIComponent(normalizedQuery)}`),
        process.env.LOGO_DEV_SECRET
            ? fetch(`https://api.logo.dev/search?q=${encodeURIComponent(normalizedQuery)}`, {
                headers: { Authorization: `Bearer ${process.env.LOGO_DEV_SECRET}` }
            })
            : Promise.resolve(null),
    ])

    // Process Clearbit results
    if (clearbitResult.status === 'fulfilled' && clearbitResult.value?.ok) {
        try {
            const data: ClearbitSuggestion[] = await clearbitResult.value.json()
            data.forEach((item) => {
                const isDuplicate = results.some(r => r.url === item.logo)
                if (!isDuplicate && cachedLogo?.logoUrl !== item.logo) {
                    results.push({
                        source: 'api',
                        url: item.logo,
                        name: item.name
                    })
                }
            })
        } catch {
            // Clearbit parse error is best-effort
        }
    }

    // Process logo.dev results
    if (logoDevResult.status === 'fulfilled' && logoDevResult.value?.ok) {
        try {
            const data: LogoDevResult[] = await logoDevResult.value.json()
            data.slice(0, 5).forEach((item) => {
                const isDuplicate = results.some(r => r.url === item.logo_url)
                if (!isDuplicate && cachedLogo?.logoUrl !== item.logo_url) {
                    results.push({
                        source: 'api',
                        url: item.logo_url,
                        name: item.name || item.domain || ''
                    })
                }
            })
        } catch {
            // Logo.dev parse error is best-effort
        }
    }

    return results
}

