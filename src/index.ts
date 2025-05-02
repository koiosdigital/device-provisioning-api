import { Hono } from 'hono'
import { z } from 'zod'
import { generate_jwt, extract_csr } from './helpers'
import { Agent } from 'https'
import { type D1Database } from '@cloudflare/workers-types'
import { verifyFromJwks } from 'hono/utils/jwt/jwt'
import { cors } from 'hono/cors'

const agent = new Agent({
  rejectUnauthorized: false
})

type Bindings = {
  PROVISIONING_JWK: string
  STEP_CA_HOST: string
  OIDC_ISSUER: string
  db: D1Database
}

const dsParamsSchema = z.object({
  ds_key_id: z.number().min(1).max(7),
  rsa_len: z.number().min(31).max(128),
  cipher_c: z.string().base64(),
  iv: z.string().base64()
});

const app = new Hono<{ Bindings: Bindings }>()

//cors
app.use("*", cors());

//define middleware to check if the request is authenticated
app.use('/v1/factory/*', async (c, next) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader) {
    return c.text('Missing Authorization header', 401)
  }
  const token = authHeader.split(' ')[1]
  if (!token) {
    return c.text('Missing token', 401)
  }
  const issuer = c.env.OIDC_ISSUER
  const issuerResponse = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!issuerResponse.ok) {
    return c.text('Error fetching issuer JWKS!', 500)
  }
  const issuerData = await issuerResponse.json() as any
  const keys = issuerData.jwks_uri;

  try {
    const payload = await verifyFromJwks(token, {
      jwks_uri: keys,
    });
    if (!payload) {
      return c.text('Invalid token', 401)
    }
    const roles = payload['roles'] as string[]
    console.log(payload);
    if (!roles || !roles.includes('koios-factory')) {
      return c.text('User unauthorized', 403)
    }
  } catch (e) {
    console.error(e)
    return c.text('Invalid token', 401)
  }
  return next()
})

app.post('/v1/factory/provision', async (c) => {
  const body = await c.req.parseBody()

  if (!body || !body['csr']) {
    return c.text('Missing CSR!', 400)
  }

  const csr = await (body['csr'] as File).text()

  let cn = "";
  try {
    const data = await extract_csr(csr)

    if (!data) {
      return c.text('Invalid CSR!', 400)
    }

    cn = data.commonName
  } catch (e) {
    return c.text('Invalid CSR!', 400)
  }

  const jwk = c.env.PROVISIONING_JWK
  const jwt = await generate_jwt(
    cn,
    [],
    `${c.env.STEP_CA_HOST}/1.0/sign`,
    "provisioner",
    jwk
  )

  //sign the CSR
  const resp = await fetch(`${c.env.STEP_CA_HOST}/1.0/sign`, {
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

app.post('/v1/ds_params', async (c) => {
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

app.get('/v1/ds_params', async (c) => {
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
  return c.json(JSON.parse(data.ds_json));
});

app.get('/', async (c) => {
  return c.redirect("https://github.com/koiosdigital/device-provisioning-api")
})

export default app
