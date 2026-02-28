import { LRUCache } from 'lru-cache'

type RateLimitEntry = { count: number }

const cache = new LRUCache<string, RateLimitEntry>({
  max: 500,
  ttl: 15 * 60 * 1000, // 15 minutes
})

const RATE_LIMIT = 5

export function checkRateLimit(ip: string): { allowed: boolean; minutesLeft: number } {
  const existing = cache.get(ip)
  if (!existing) {
    cache.set(ip, { count: 1 })
    return { allowed: true, minutesLeft: 0 }
  }
  if (existing.count >= RATE_LIMIT) {
    const ms = cache.getRemainingTTL(ip)
    return { allowed: false, minutesLeft: Math.ceil(ms / 60000) }
  }
  existing.count++ // mutate in place — does NOT reset TTL
  return { allowed: true, minutesLeft: 0 }
}
