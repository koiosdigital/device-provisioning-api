import { Hono } from 'hono'
import type { Context } from 'hono'
import { cors } from 'hono/cors'
import { createRemoteJWKSet, jwtVerify } from 'jose'
import { extractCsr, generateJwt } from './helpers'
import {
  csrBodySchema,
  deviceIdSchema,
  dsParamsSchema,
  swaggerDocument,
  type CloudflareBindings,
  type DsParams
} from './types'

const app = new Hono<{ Bindings: CloudflareBindings }>()
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
    if (!roles.includes('koios-factory')) {
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

app.get('/', (c) => c.redirect('https://github.com/koiosdigital/device-provisioning-api'))

export default app
