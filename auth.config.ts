import type { NextAuthConfig } from 'next-auth'
import type { JWT } from 'next-auth/jwt'
import type { SubscriptionStatus, SubscriptionTier } from '@prisma/client'
import { prisma } from '@/lib/prisma'

type SubscriptionPayload = {
    tier: SubscriptionTier
    status: SubscriptionStatus
    currentPeriodEnd: Date | null
    isActive: boolean
    isFree: boolean
}

type ExtendedToken = JWT & {
    id?: string
    subscriptionSelected?: boolean
    subscription?: SubscriptionPayload
}

export const authConfig = {
    pages: {
        signIn: '/login',
    },
    callbacks: {
        async session({ session, token }) {
            // Use data from JWT token instead of querying database
            // This allows the session callback to run on Edge Runtime
            const typedToken = token as ExtendedToken

            if (typedToken && session.user) {
                session.user.id = typedToken.id as string
                session.user.subscriptionSelected = Boolean(typedToken.subscriptionSelected)

                if (typedToken.subscription) {
                    session.user.subscription = typedToken.subscription
                }
            }

            return session
        },
        async jwt({ token, user, trigger }) {
            const typedToken = token as ExtendedToken

            // Add user data to token on sign in
            if (user) {
                const userData = user as {
                    id?: string
                    subscriptionSelected?: boolean
                }
                if (userData.id) {
                    typedToken.id = userData.id
                }
                typedToken.subscriptionSelected = userData.subscriptionSelected

                // Attach subscription data on initial sign-in
                if (userData.id) {
                    const subscription = await prisma.subscription.findUnique({
                        where: { userId: userData.id },
                        select: {
                            tier: true,
                            status: true,
                            currentPeriodEnd: true,
                        },
                    })

                    if (subscription) {
                        typedToken.subscription = {
                            tier: subscription.tier,
                            status: subscription.status,
                            currentPeriodEnd: subscription.currentPeriodEnd,
                            isActive: subscription.status === 'ACTIVE',
                            isFree: subscription.tier === 'FREE',
                        }
                    }
                }
            }

            // Refresh user data from database when needed or when missing in token
            const needsRefresh = trigger === 'update' || !typedToken.subscriptionSelected || !typedToken.subscription
            if (needsRefresh && token.email) {
                try {
                    const dbUser = await prisma.user.findUnique({
                        where: { email: token.email },
                        select: {
                            id: true,
                            subscriptionSelected: true,
                        },
                    })

                    if (dbUser) {
                        typedToken.id = dbUser.id
                        typedToken.subscriptionSelected = dbUser.subscriptionSelected

                        // Add subscription data
                        const subscription = await prisma.subscription.findUnique({
                            where: { userId: dbUser.id },
                            select: {
                                tier: true,
                                status: true,
                                currentPeriodEnd: true,
                            },
                        })

                        if (subscription) {
                            typedToken.subscription = {
                                tier: subscription.tier,
                                status: subscription.status,
                                currentPeriodEnd: subscription.currentPeriodEnd,
                                isActive: subscription.status === 'ACTIVE',
                                isFree: subscription.tier === 'FREE',
                            }
                        }
                    }
                } catch (error) {
                    console.warn('JWT callback database error:', error)
                }
            }

            return typedToken
        },
        authorized({ auth, request: { nextUrl } }) {
            const isLoggedIn = !!auth?.user
            const hasSelectedPlan = !!auth?.user?.subscriptionSelected
            const isOnSubscribe = nextUrl.pathname === '/subscribe'
            const isPublic = nextUrl.pathname === '/' || nextUrl.pathname === '/login' || nextUrl.pathname === '/register'

            if (!isLoggedIn) {
                return isPublic
            }

            if (!hasSelectedPlan && !isOnSubscribe) {
                return Response.redirect(new URL('/subscribe', nextUrl))
            }

            if (isPublic && hasSelectedPlan) {
                return Response.redirect(new URL('/dashboard', nextUrl))
            }

            return true
        },
    },
    providers: [], // Configured in auth.ts
} satisfies NextAuthConfig
