import { Stripe } from 'stripe'
import { prisma } from './prisma'
import { SubscriptionStatus, SubscriptionTier } from '@prisma/client'

function getStripe(): Stripe {
  const apiKey = process.env.STRIPE_SECRET_KEY
  if (!apiKey) {
    throw new Error('STRIPE_SECRET_KEY is not configured')
  }
  return new Stripe(apiKey, { apiVersion: '2025-11-17.clover' })
}

// Lazy-initialized: only created when actually used at runtime
let _stripe: Stripe | null = null
function stripe(): Stripe {
  if (!_stripe) {
    _stripe = getStripe()
  }
  return _stripe
}

export { stripe }

const getPeriodEndDate = (subscription: Stripe.Subscription) => {
  const periodEnd = (subscription as { current_period_end?: number | null }).current_period_end
  return periodEnd ? new Date(periodEnd * 1000) : null
}

// Subscription utility functions
export class SubscriptionService {
  /**
   * Create or retrieve a Stripe customer for a user
   */
  static async createOrGetCustomer(userId: string, email: string) {
    const subscription = await prisma.subscription.findUnique({
      where: { userId },
      select: { stripeCustomerId: true }
    })

    if (!subscription) {
      throw new Error('Subscription not found')
    }

    if (subscription.stripeCustomerId) {
      // Customer already exists
      return await stripe().customers.retrieve(subscription.stripeCustomerId)
    }

    // Create new customer
    const customer = await stripe().customers.create({
      email: email,
      metadata: {
        userId: userId,
      },
    })

    // Update subscription with customer ID
    await prisma.subscription.update({
      where: { userId },
      data: { stripeCustomerId: customer.id },
    })

    return customer
  }

  /**
   * Create a checkout session for subscription
   */
  static async createCheckoutSession(
    userId: string,
    priceId: string,
    successUrl: string,
    cancelUrl: string
  ) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { email: true }
    })

    if (!user) {
      throw new Error('User not found')
    }

    const customer = await this.createOrGetCustomer(userId, user.email)

    const session = await stripe().checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: {
        userId: userId,
      },
    })

    return session
  }

  /**
   * Cancel a subscription
   */
  static async cancelSubscription(userId: string) {
    const subscription = await prisma.subscription.findUnique({
      where: { userId },
      select: { stripeSubscriptionId: true }
    })

    if (!subscription || !subscription.stripeSubscriptionId) {
      throw new Error('No active subscription found')
    }

    const stripeSubscription = await stripe().subscriptions.update(subscription.stripeSubscriptionId, {
      cancel_at_period_end: true,
    }) as Stripe.Subscription

    // Update subscription status
    await prisma.subscription.update({
      where: { userId },
      data: {
        status: SubscriptionStatus.ACTIVE, // Still active until period end
        currentPeriodEnd: getPeriodEndDate(stripeSubscription),
      },
    })

    return stripeSubscription
  }

  /**
   * Update subscription (upgrade/downgrade)
   */
  static async updateSubscription(userId: string, newPriceId: string, newTier: SubscriptionTier) {
    const subscription = await prisma.subscription.findUnique({
      where: { userId },
      select: { stripeSubscriptionId: true }
    })

    if (!subscription || !subscription.stripeSubscriptionId) {
      throw new Error('No active subscription found')
    }

    // Get current subscription
    const stripeSubscription = await stripe().subscriptions.retrieve(subscription.stripeSubscriptionId)

    // Update the subscription with new price
    const updatedSubscription = await stripe().subscriptions.update(subscription.stripeSubscriptionId, {
      items: [
        {
          id: stripeSubscription.items.data[0].id,
          price: newPriceId,
        },
      ],
      proration_behavior: 'create_prorations',
    }) as Stripe.Subscription

    // Update database
    await prisma.subscription.update({
      where: { userId },
      data: {
        tier: newTier,
        currentPeriodEnd: getPeriodEndDate(updatedSubscription),
      },
    })

    return updatedSubscription
  }

  /**
   * Get subscription status for a user
   */
  static async getSubscriptionStatus(userId: string) {
    const subscription = await prisma.subscription.findUnique({
      where: { userId },
      select: {
        stripeSubscriptionId: true,
        status: true,
        tier: true,
        currentPeriodEnd: true
      }
    })

    if (!subscription) {
      throw new Error('Subscription not found')
    }

    return {
      subscriptionId: subscription.stripeSubscriptionId,
      status: subscription.status,
      tier: subscription.tier,
      currentPeriodEnd: subscription.currentPeriodEnd,
      isActive: subscription.status === SubscriptionStatus.ACTIVE,
      isPastDue: subscription.status === SubscriptionStatus.PAST_DUE,
      isFree: subscription.tier === SubscriptionTier.FREE,
    }
  }

  /**
   * Sync subscription data from Stripe webhook
   */
  static async syncSubscriptionFromStripe(stripeSubscription: Stripe.Subscription) {
    const customer = await stripe().customers.retrieve(stripeSubscription.customer as string)
    if (!('metadata' in customer) || !customer.metadata?.userId) {
      throw new Error('Customer metadata not found')
    }
    const userId = customer.metadata.userId

    if (!userId) {
      throw new Error('No userId found in customer metadata')
    }

    // Map Stripe status to our enum
    const statusMap: Record<string, SubscriptionStatus> = {
      'active': SubscriptionStatus.ACTIVE,
      'past_due': SubscriptionStatus.PAST_DUE,
      'canceled': SubscriptionStatus.CANCELED,
      'unpaid': SubscriptionStatus.UNPAID,
      'incomplete': SubscriptionStatus.INCOMPLETE,
      'incomplete_expired': SubscriptionStatus.INCOMPLETE_EXPIRED,
      'trialing': SubscriptionStatus.TRIALING,
    }

    // Determine tier based on price ID
    const priceId = stripeSubscription.items.data[0]?.price.id
    let tier: SubscriptionTier = SubscriptionTier.FREE
    if (priceId === process.env.STRIPE_MONTHLY_PRICE_ID) {
      tier = SubscriptionTier.MONTHLY
    } else if (priceId === process.env.STRIPE_YEARLY_PRICE_ID) {
      tier = SubscriptionTier.YEARLY
    }

    const status = statusMap[stripeSubscription.status] || SubscriptionStatus.INACTIVE

    await prisma.subscription.update({
      where: { userId },
      data: {
        stripeSubscriptionId: stripeSubscription.id,
        status: status,
        tier: tier,
        currentPeriodEnd: getPeriodEndDate(stripeSubscription),
      },
    })

    return { userId, status, tier }
  }
}
