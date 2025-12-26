import Stripe from 'stripe'
import { randomBytes } from 'node:crypto'

// Map of key_type to Stripe Price ID
// Update these with your actual Stripe Price IDs
export const KEY_TYPE_TO_PRICE_ID: Record<string, string> = {
    'matrx': 'price_1RKPK1AgCDl6UP1XeXfY5nJp',      // Replace with actual Stripe Price ID
    'lantern': 'price_1SiMuWAgCDl6UP1X95EVJr8B',    // Replace with actual Stripe Price ID
}

export function generateLicenseKey(): string {
    const bytes = randomBytes(16)
    const hex = bytes.toString('hex')
    // Format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
    return hex.match(/.{1,4}/g)?.join('-').toUpperCase() || hex.toUpperCase()
}

export function initStripe(secretKey: string): Stripe {
    return new Stripe(secretKey, {
        apiVersion: '2025-12-15.clover'
    })
}
