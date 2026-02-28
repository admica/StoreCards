import { z } from 'zod'

export const loginSchema = z.object({
    email: z.string().email('Enter a valid email address'),
    password: z.string().min(1, 'Password is required'),
})

export const registerSchema = z.object({
    email: z.string().email('Enter a valid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters'),
})

export const cardSchema = z.object({
    retailer: z.string().min(1, 'Retailer name is required'),
})

export function validateField(
    schema: z.ZodObject<z.ZodRawShape>,
    name: string,
    value: string
): string | null {
    const fieldSchema = schema.shape[name] as z.ZodTypeAny | undefined
    if (!fieldSchema) return null

    const result = fieldSchema.safeParse(value)
    if (!result.success) {
        return result.error.issues[0]?.message ?? null
    }
    return null
}
