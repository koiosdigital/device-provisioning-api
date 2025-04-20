import { Hono } from 'hono'
import { z } from 'zod'
import { generate_jwt, extract_csr } from './helpers'
import { jwtVerify } from 'jose'
import { Agent } from 'https'
import { type D1Database } from '@cloudflare/workers-types'

const agent = new Agent({
  rejectUnauthorized: false
})

type Bindings = {
  PROVISIONING_JWK: string
  STEP_CA_HOST: string
  TOKEN_SECRET: string
  db: D1Database
}

const dsParamsSchema = z.object({
  ds_key_id: z.number().min(1).max(7),
  rsa_len: z.number().min(31).max(128),
  cipher_c: z.string().base64(),
  iv: z.string().base64()
});

const app = new Hono<{ Bindings: Bindings }>()

app.post('/sign', async (c) => {
  const body = await c.req.parseBody()

  if (!body || !body['csr']) {
    return c.text('Missing CSR!', 400)
  }

  //auth header
  const authHeader = c.req.header('Authorization')
  if (!authHeader) {
    return c.text('Missing Authorization header!', 400)
  }
  const token = authHeader.split(' ')[1]

  const csr = await (body['csr'] as File).text()
  const data = await extract_csr(csr)

  if (!data) {
    return c.text('Invalid CSR!', 400)
  }

  //verify the token
  const tokenSecret = new TextEncoder().encode(c.env.TOKEN_SECRET)
  const { payload } = await jwtVerify(token, tokenSecret, {
    audience: 'pki-api',
    algorithms: ['HS256'],
  }).catch((err) => {
    console.error('JWT verification failed:', err)
    return { payload: null }
  })

  if (!payload) {
    return c.text('Invalid token!', 400)
  }

  if (!payload.sub || payload.sub !== data.commonName) {
    return c.text('Invalid token subject!', 400)
  }

  const jwk = c.env.PROVISIONING_JWK

  const audience = `${c.env.STEP_CA_HOST}/1.0/sign`
  const issuer = "provisioner"

  const jwt = await generate_jwt(
    data.commonName,
    [],
    audience,
    issuer,
    jwk
  )

  //sign the CSR
  const resp = await fetch(audience, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      csr,
      ott: jwt,
      notAfter: '262800h'
    }),

    // @ts-ignore
    agent: agent,
  })

  if (!resp.ok) {
    const text = await resp.text()
    return c.text(`Error signing CSR: ${text}`, 500)
  }

  const respData: any = await resp.json()

  //return it as a file download
  const pem = respData.crt

  c.res.headers.set('Content-Type', 'application/x-x509-ca-cert')
  c.res.headers.set('Content-Disposition', `attachment; filename="leaf.crt"`)
  c.res.headers.set('Content-Length', pem.length)
  c.res.headers.set('Cache-Control', 'no-store')

  return c.body(pem, 200)
})

app.post('/ds_params', async (c) => {
  const device_id = c.req.header('x-device-id')

  if (!device_id) {
    return c.text('Missing device_id!', 400)
  }

  const json = await c.req.json()

  if (!device_id) {
    return c.text('Missing device_id!', 400)
  }

  const dsParams = dsParamsSchema.safeParse(json)
  if (!dsParams.success) {
    return c.text('Invalid ds_params!', 400)
  }

  //check if the device_id exists in the database
  const data = await c.env.db.prepare('SELECT * FROM ds_data WHERE device_id = ?').bind(device_id).first()
  if (data) {
    return c.json({
      status: 'ok',
    });
  }

  //insert the device_id into the database
  await c.env.db.prepare('INSERT INTO ds_data (device_id, ds_json) VALUES (?, ?)').bind(device_id, JSON.stringify(dsParams.data)).run()
  return c.json({
    status: 'ok',
  });
});

app.get('/ds_params', async (c) => {
  const device_id = c.req.header('x-device-id')

  if (!device_id) {
    return c.text('Missing device_id!', 400)
  }

  //check if the device_id exists in the database
  const data = await c.env.db.prepare('SELECT * FROM ds_data WHERE device_id = ?').bind(device_id).first()
  if (!data) {
    return c.text('Device not found!', 404)
  }

  //@ts-expect-error - we're not typing cause we're lazy
  return c.json(data.ds_json);
});

app.get('/', async (c) => {
  return c.redirect("https://github.com/koiosdigital/device-provisioning-api")
})

export default app
