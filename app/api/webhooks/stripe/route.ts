import { NextRequest, NextResponse } from 'next/server'
import { headers } from 'next/headers'
import type { Stripe } from 'stripe'
import { stripe, SubscriptionService } from '@/lib/stripe'
import { prisma } from '@/lib/prisma'
import { SubscriptionStatus } from '@prisma/client'

type InvoiceWithSubscription = Stripe.Invoice & {
  subscription?: string | Stripe.Subscription | null
}

export async function POST(request: NextRequest) {
  try {
    // Check if Stripe is properly configured
    if (!process.env.STRIPE_WEBHOOK_SECRET || !process.env.STRIPE_SECRET_KEY) {
      console.error('Stripe environment variables not configured')
      return NextResponse.json({ error: 'Service temporarily unavailable' }, { status: 503 })
    }

    const body = await request.text()
    const headersList = await headers()

    const signature = headersList.get('stripe-signature')
    if (!signature) {
      return NextResponse.json({ error: 'No signature' }, { status: 400 })
    }

    // Verify webhook signature
    let event: Stripe.Event
    try {
      event = stripe().webhooks.constructEvent(
        body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET
      )
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      console.error('Webhook signature verification failed:', message)
      return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
    }

    console.log('Received webhook event:', event.type)

    // Handle different event types
    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const subscription = event.data.object as Stripe.Subscription
        await SubscriptionService.syncSubscriptionFromStripe(subscription)
        break
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object as Stripe.Invoice
        await handlePaymentSucceeded(invoice)
        break
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object as Stripe.Invoice
        await handlePaymentFailed(invoice)
        break
      }

      default:
        console.log(`Unhandled event type: ${event.type}`)
    }

    return NextResponse.json({ received: true })
  } catch (error) {
    console.error('Webhook error:', error)
    return NextResponse.json(
      { error: 'Webhook handler failed' },
      { status: 500 }
    )
  }
}

async function handlePaymentSucceeded(invoice: InvoiceWithSubscription) {
  // Payment succeeded - ensure subscription is marked as active
  const subscriptionId = typeof invoice.subscription === 'string'
    ? invoice.subscription
    : invoice.subscription?.id

  if (subscriptionId) {
    const subscription = await stripe().subscriptions.retrieve(subscriptionId)
    await SubscriptionService.syncSubscriptionFromStripe(subscription)
  }
}

async function handlePaymentFailed(invoice: InvoiceWithSubscription) {
  // Payment failed - mark subscription as past due
  const subscriptionId = typeof invoice.subscription === 'string'
    ? invoice.subscription
    : invoice.subscription?.id

  if (subscriptionId) {
    const subscription = await stripe().subscriptions.retrieve(subscriptionId)
    const customer = await stripe().customers.retrieve(subscription.customer as string)

    // Check if customer is not deleted and has metadata
    if (!customer.deleted && customer.metadata?.userId) {
      const userId = customer.metadata.userId

      await prisma.subscription.update({
        where: { userId },
        data: {
          status: SubscriptionStatus.PAST_DUE,
        },
      })
    }
  }
}
