'use server'

import { signIn, signOut, auth } from '@/auth'
import { prisma } from '@/lib/prisma'
import bcrypt from 'bcryptjs'
import { AuthError } from 'next-auth'
import { z } from 'zod'
import { revalidatePath } from 'next/cache'
import { redirect } from 'next/navigation'

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

    await prisma.user.create({
        data: {
            email,
            password: hashedPassword,
        },
    })

    try {
        await signIn('credentials', formData)
    } catch (error) {
        if (error instanceof AuthError) {
            throw error
        }
        throw error
    }
}

export async function createCard(prevState: string | undefined, formData: FormData) {
    const session = await auth()
    if (!session?.user?.email) {
        return 'Not authenticated'
    }

    const retailer = formData.get('retailer') as string
    const note = formData.get('note') as string
    const barcodeValue = formData.get('barcodeValue') as string
    const barcodeFormat = formData.get('barcodeFormat') as string
    const imageFile = formData.get('image') as File

    if (!retailer) {
        return 'Retailer name is required'
    }

    let imagePath = null
    if (imageFile && imageFile.size > 0) {
        // Convert to base64 for storage (Vercel doesn't have persistent file system)
        const buffer = Buffer.from(await imageFile.arrayBuffer())
        const base64 = buffer.toString('base64')
        const mimeType = imageFile.type || 'image/jpeg'
        imagePath = `data:${mimeType};base64,${base64}`
    }

    await prisma.card.create({
        data: {
            retailer,
            note,
            barcodeValue,
            barcodeFormat,
            image: imagePath,
            user: {
                connect: {
                    email: session.user.email,
                },
            },
        },
    })

    revalidatePath('/')
    redirect('/')
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
        revalidatePath('/')
    }
}
