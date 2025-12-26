import { Hono } from 'hono'
import type { Context } from 'hono'
import { cors } from 'hono/cors'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { extractCsr, generateJwt } from './helpers'
import {
  csrBodySchema,
  deviceIdSchema,
  dsParamsSchema,
  checkoutBodySchema,
  redeemBodySchema,
  swaggerDocument,
  type CloudflareBindings,
  type DsParams
} from './types'
import { initStripe, generateLicenseKey, KEY_TYPE_TO_PRICE_ID } from './license'

type Variables = {
  user_id: string
}

const app = new Hono<{ Bindings: CloudflareBindings; Variables: Variables }>()
const issuerJwksCache = new Map<string, string>()

type ErrorStatus = 400 | 401 | 403 | 404 | 422 | 429 | 500 | 502

const jsonError = (c: Context, status: ErrorStatus, message: string) => c.json({ error: message }, status)

async function resolveIssuerJwks(issuer: string) {
  const normalizedIssuer = issuer.trim().replace(/\/+$/, '')
  if (issuerJwksCache.has(normalizedIssuer)) {
    return issuerJwksCache.get(normalizedIssuer) as string
  }

  try {
    new URL(normalizedIssuer)
  } catch (error) {
    throw new Error('OIDC issuer is not a valid URL')
  }

  const discoveryUrl = `${normalizedIssuer}/.well-known/openid-configuration`
  const response = await fetch(discoveryUrl, {
    headers: { Accept: 'application/json' }
  })
  if (!response.ok) {
    throw new Error('Unable to fetch OIDC discovery document')
  }

  const json = await response.json() as { jwks_uri?: string }
  if (!json.jwks_uri) {
    throw new Error('OIDC discovery document missing jwks_uri')
  }

  issuerJwksCache.set(normalizedIssuer, json.jwks_uri)
  return json.jwks_uri
}

app.use(
  '*',
  cors({
    origin: '*',
    allowHeaders: ['Authorization', 'Content-Type', 'x-device-id'],
    allowMethods: ['GET', 'POST', 'OPTIONS']
  })
)

app.onError((err, c) => {
  console.error(err)
  return jsonError(c, 500, 'Unexpected error')
})

app.get('/swagger.json', (c) => {
  c.header('Cache-Control', 'no-store')
  return c.json(swaggerDocument)
})

app.use('/v1/factory/*', async (c, next) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return jsonError(c, 401, 'Missing Authorization header')
  }

  const token = authHeader.slice('Bearer '.length).trim()
  if (!token) {
    return jsonError(c, 401, 'Missing token')
  }

  try {
    const jwksUri = await resolveIssuerJwks(c.env.OIDC_ISSUER)
    const jwks = createRemoteJWKSet(new URL(jwksUri))
    const { payload } = await jwtVerify(token, jwks, { issuer: c.env.OIDC_ISSUER })
    const roles = Array.isArray(payload?.roles) ? (payload.roles as string[]) : []
    const groups = Array.isArray(payload?.groups) ? (payload.groups as string[]) : []
    if (!roles.includes('koios-factory') && !groups.includes('koios-factory')) {
      return jsonError(c, 403, 'User unauthorized')
    }
  } catch (error) {
    console.error(error)
    return jsonError(c, 401, 'Invalid token')
  }

  await next()
})

app.post('/v1/factory/provision', async (c) => {
  const formData = await c.req.parseBody()
  const csrField = formData?.['csr']

  let csrValue: string | undefined
  if (typeof csrField === 'string') {
    csrValue = csrField
  } else if (csrField instanceof File) {
    csrValue = await csrField.text()
  }

  const csrValidation = csrBodySchema.safeParse({ csr: csrValue })
  if (!csrValidation.success) {
    const message = csrValidation.error.issues[0]?.message ?? 'Invalid CSR'
    return jsonError(c, 400, message)
  }

  let cn: string
  try {
    const metadata = await extractCsr(csrValidation.data.csr)
    cn = metadata.commonName
  } catch (error) {
    console.error(error)
    return jsonError(c, 400, 'Invalid CSR')
  }

  const signUrl = new URL('/1.0/sign', c.env.STEP_CA_HOST)

  let token: string
  try {
    token = await generateJwt({
      commonName: cn,
      subjectAlternativeNames: [],
      audience: signUrl.toString(),
      issuer: 'provisioner',
      jwk: c.env.PROVISIONING_JWK
    })
  } catch (error) {
    console.error(error)
    return jsonError(c, 500, 'Unable to generate provisioning token')
  }

  const response = await fetch(signUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csr: csrValidation.data.csr, ott: token, notAfter: '262800h' })
  })

  if (!response.ok) {
    const details = await response.text()
    return jsonError(c, 502, `Error signing CSR: ${details}`)
  }

  const payload = await response.json() as { crt?: string }
  if (!payload.crt) {
    return jsonError(c, 502, 'Signer returned an invalid payload')
  }

  c.header('Content-Type', 'application/x-x509-ca-cert')
  c.header('Content-Disposition', 'attachment; filename="leaf.crt"')
  c.header('Cache-Control', 'no-store')

  return c.body(payload.crt, 200)
})

app.post('/v1/ds_params', async (c) => {
  const header = c.req.header('x-device-id') ?? ''
  const deviceIdResult = deviceIdSchema.safeParse(header)
  if (!deviceIdResult.success) {
    return jsonError(c, 400, 'Invalid or missing device_id header')
  }

  let json: unknown
  try {
    json = await c.req.json()
  } catch (error) {
    return jsonError(c, 400, 'Body must be JSON')
  }

  const paramsResult = dsParamsSchema.safeParse(json)
  if (!paramsResult.success) {
    return jsonError(c, 400, 'Invalid ds_params payload')
  }

  const deviceId = deviceIdResult.data
  const existing = await c.env.db
    .prepare('SELECT ds_json FROM ds_data WHERE device_id = ?')
    .bind(deviceId)
    .first<{ ds_json: string }>()

  if (existing) {
    return c.json({ status: 'exists' })
  }

  await c.env.db
    .prepare('INSERT INTO ds_data (device_id, ds_json) VALUES (?, ?)')
    .bind(deviceId, JSON.stringify(paramsResult.data))
    .run()

  return c.json({ status: 'created' })
})

app.get('/v1/ds_params', async (c) => {
  const header = c.req.header('x-device-id') ?? ''
  const deviceIdResult = deviceIdSchema.safeParse(header)
  if (!deviceIdResult.success) {
    return jsonError(c, 400, 'Invalid or missing device_id header')
  }

  const row = await c.env.db
    .prepare('SELECT ds_json FROM ds_data WHERE device_id = ?')
    .bind(deviceIdResult.data)
    .first<{ ds_json: string }>()

  if (!row) {
    return jsonError(c, 404, 'Device not found')
  }

  let parsed: DsParams
  try {
    parsed = dsParamsSchema.parse(JSON.parse(row.ds_json))
  } catch (error) {
    console.error('Corrupt ds_json payload for device', deviceIdResult.data, error)
    return jsonError(c, 500, 'Stored device parameters are invalid')
  }

  return c.json(parsed)
})

// Middleware for JWT verification on license endpoints
app.use('/v1/license/*', async (c, next) => {
  // Skip auth for callback endpoint (authenticated via Stripe session)
  if (c.req.path === '/v1/license/checkout/callback') {
    return next()
  }

  const authHeader = c.req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return jsonError(c, 401, 'Missing Authorization header')
  }

  const token = authHeader.slice('Bearer '.length).trim()
  if (!token) {
    return jsonError(c, 401, 'Missing token')
  }

  try {
    const jwksUri = await resolveIssuerJwks(c.env.OIDC_ISSUER)
    const jwks = createRemoteJWKSet(new URL(jwksUri))
    const { payload } = await jwtVerify(token, jwks, { issuer: c.env.OIDC_ISSUER })
    // Store user_id from token for later use
    const userId = typeof payload.sub === 'string' ? payload.sub :
                   typeof payload.email === 'string' ? payload.email : null

    if (!userId) {
      return jsonError(c, 401, 'Token missing user identifier')
    }

    c.set('user_id', userId)
  } catch (error) {
    console.error('JWT verification failed:', error instanceof Error ? error.message : 'Unknown error')
    return jsonError(c, 401, 'Invalid token')
  }

  await next()
})

// Initiate Stripe checkout session
app.post('/v1/license/checkout', async (c) => {
  let json: unknown
  try {
    json = await c.req.json()
  } catch (error) {
    return jsonError(c, 400, 'Body must be JSON')
  }

  const bodyResult = checkoutBodySchema.safeParse(json)
  if (!bodyResult.success) {
    const message = bodyResult.error.issues[0]?.message ?? 'Invalid request body'
    return jsonError(c, 400, message)
  }

  const { key_type, return_url } = bodyResult.data
  const priceId = KEY_TYPE_TO_PRICE_ID[key_type]

  if (!priceId) {
    return jsonError(c, 400, `Invalid key_type: ${key_type}`)
  }

  // Validate return_url against whitelist
  const allowedOrigins = c.env.ALLOWED_RETURN_DOMAINS.split(',').map(d => d.trim())
  try {
    const returnUrlObj = new URL(return_url)
    const returnOrigin = `${returnUrlObj.protocol}//${returnUrlObj.hostname}${returnUrlObj.port ? ':' + returnUrlObj.port : ''}`

    const isAllowed = allowedOrigins.some(allowed => {
      // Handle exact origin match (e.g., "http://localhost:5173")
      if (allowed.startsWith('http://') || allowed.startsWith('https://')) {
        const allowedUrl = new URL(allowed)
        const allowedOrigin = `${allowedUrl.protocol}//${allowedUrl.hostname}${allowedUrl.port ? ':' + allowedUrl.port : ''}`
        return returnOrigin === allowedOrigin
      }
      // Handle hostname-only match for backwards compatibility
      return returnUrlObj.hostname === allowed || returnUrlObj.hostname.endsWith('.' + allowed)
    })

    if (!isAllowed) {
      return jsonError(c, 400, 'return_url origin not allowed')
    }
  } catch (error) {
    return jsonError(c, 400, 'Invalid return_url format')
  }

  const stripe = initStripe(c.env.STRIPE_SECRET_KEY)
  const userId = c.get('user_id') as string

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [
        {
          price: priceId,
          quantity: 1
        }
      ],
      success_url: `${new URL(c.req.url).origin}/v1/license/checkout/callback?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: return_url,
      metadata: {
        user_id: userId,
        key_type: key_type,
        return_url: return_url
      }
    })

    return c.json({ url: session.url })
  } catch (error) {
    console.error('Stripe checkout error:', error)
    return jsonError(c, 500, 'Failed to create checkout session')
  }
})

// Stripe checkout callback - verify payment and generate license key
app.get('/v1/license/checkout/callback', async (c) => {
  const sessionId = c.req.query('session_id')
  if (!sessionId) {
    return jsonError(c, 400, 'Missing session_id')
  }

  const stripe = initStripe(c.env.STRIPE_SECRET_KEY)

  try {
    // Check if this session has already been processed (prevent replay attacks)
    const existingKey = await c.env.db
      .prepare('SELECT license_key FROM license_keys WHERE session_id = ?')
      .bind(sessionId)
      .first<{ license_key: string }>()

    if (existingKey) {
      // Session already processed, redirect with existing key
      const session = await stripe.checkout.sessions.retrieve(sessionId)
      const returnUrl = session.metadata?.return_url
      if (returnUrl) {
        const redirectUrl = new URL(returnUrl)
        redirectUrl.searchParams.set('license_key', existingKey.license_key)
        return c.redirect(redirectUrl.toString())
      }
      return jsonError(c, 400, 'Session already processed')
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId)

    if (session.payment_status !== 'paid') {
      return jsonError(c, 400, 'Payment not completed')
    }

    const userId = session.metadata?.user_id
    const keyType = session.metadata?.key_type
    const returnUrl = session.metadata?.return_url

    if (!userId || !keyType || !returnUrl) {
      return jsonError(c, 500, 'Session metadata is incomplete')
    }

    // Generate license key
    const licenseKey = generateLicenseKey()

    // Store in database with session_id to prevent replay
    await c.env.db
      .prepare('INSERT INTO license_keys (user_id, license_key, key_type, used, session_id) VALUES (?, ?, ?, ?, ?)')
      .bind(userId, licenseKey, keyType, 0, sessionId)
      .run()

    // Redirect back to return_url with license key as query parameter
    const redirectUrl = new URL(returnUrl)
    redirectUrl.searchParams.set('license_key', licenseKey)
    return c.redirect(redirectUrl.toString())
  } catch (error) {
    console.error('Checkout callback failed:', error instanceof Error ? error.message : 'Unknown error')
    return jsonError(c, 500, 'Failed to process checkout callback')
  }
})

// Redeem license key - validate key, sign CSR, mark as used
app.post('/v1/license/redeem', async (c) => {
  let json: unknown
  try {
    json = await c.req.json()
  } catch (error) {
    return jsonError(c, 400, 'Body must be JSON')
  }

  const bodyResult = redeemBodySchema.safeParse(json)
  if (!bodyResult.success) {
    const message = bodyResult.error.issues[0]?.message ?? 'Invalid request body'
    return jsonError(c, 400, message)
  }

  const { license_key, csr } = bodyResult.data

  // Atomically mark key as used and retrieve data (prevents race condition)
  // This UPDATE will only succeed if the key exists and used=0
  const updateResult = await c.env.db
    .prepare('UPDATE license_keys SET used = 1, redeemed_at = unixepoch() WHERE license_key = ? AND used = 0 RETURNING user_id, key_type')
    .bind(license_key)
    .first<{ user_id: string; key_type: string }>()

  if (!updateResult) {
    // Either key doesn't exist or already used
    const checkExists = await c.env.db
      .prepare('SELECT used FROM license_keys WHERE license_key = ?')
      .bind(license_key)
      .first<{ used: number }>()

    if (!checkExists) {
      return jsonError(c, 404, 'Invalid license key')
    }
    return jsonError(c, 400, 'License key already used')
  }

  // License key is now marked as used, proceed with CSR signing
  let cn: string
  try {
    const metadata = await extractCsr(csr)
    cn = metadata.commonName
  } catch (error) {
    console.error('CSR extraction failed:', error instanceof Error ? error.message : 'Unknown error')
    // Rollback: Mark key as unused since we can't proceed
    await c.env.db
      .prepare('UPDATE license_keys SET used = 0, redeemed_at = NULL WHERE license_key = ?')
      .bind(license_key)
      .run()
    return jsonError(c, 400, 'Invalid CSR')
  }

  // Generate JWT for Step CA
  const signUrl = new URL('/1.0/sign', c.env.STEP_CA_HOST)

  let token: string
  try {
    token = await generateJwt({
      commonName: cn,
      subjectAlternativeNames: [],
      audience: signUrl.toString(),
      issuer: 'provisioner',
      jwk: c.env.PROVISIONING_JWK
    })
  } catch (error) {
    console.error('JWT generation failed:', error instanceof Error ? error.message : 'Unknown error')
    // Rollback: Mark key as unused
    await c.env.db
      .prepare('UPDATE license_keys SET used = 0, redeemed_at = NULL WHERE license_key = ?')
      .bind(license_key)
      .run()
    return jsonError(c, 500, 'Unable to generate provisioning token')
  }

  // Sign the CSR
  const response = await fetch(signUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csr: csr, ott: token, notAfter: '262800h' })
  })

  if (!response.ok) {
    const details = await response.text()
    console.error('CSR signing failed:', details)
    // Rollback: Mark key as unused
    await c.env.db
      .prepare('UPDATE license_keys SET used = 0, redeemed_at = NULL WHERE license_key = ?')
      .bind(license_key)
      .run()
    return jsonError(c, 502, 'Error signing CSR')
  }

  const payload = await response.json() as { crt?: string }
  if (!payload.crt) {
    // Rollback: Mark key as unused
    await c.env.db
      .prepare('UPDATE license_keys SET used = 0, redeemed_at = NULL WHERE license_key = ?')
      .bind(license_key)
      .run()
    return jsonError(c, 502, 'Signer returned an invalid payload')
  }

  c.header('Content-Type', 'application/x-x509-ca-cert')
  c.header('Content-Disposition', 'attachment; filename="license-cert.crt"')
  c.header('Cache-Control', 'no-store')

  return c.body(payload.crt, 200)
})

app.get('/', (c) => c.redirect('https://github.com/koiosdigital/device-provisioning-api'))

export default app
