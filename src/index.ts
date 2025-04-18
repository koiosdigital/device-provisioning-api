import { Hono } from 'hono'
import { z } from 'zod'
import { generate_jwt, extract_csr } from './helpers'
import { Agent } from 'https'

const agent = new Agent({
  rejectUnauthorized: false
})

type Bindings = {
  PROVISIONING_JWK: string
  STEP_CA_HOST: string
  TOKEN_SECRET: string
}

const app = new Hono<{ Bindings: Bindings }>()

const signSchema = z.object({
  csr: z.string(),
  token: z.string().optional(),
})

app.post('/sign', async (c) => {
  const body = await c.req.json()

  const parsed = signSchema.safeParse(body)
  if (!parsed.success) {
    return c.text('Invalid request!', 400)
  }

  const { csr, token } = parsed.data
  const data = await extract_csr(csr)

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
    return c.json({
      issued: false,
      cert: "",
      error: text,
    })
  }

  const respData: any = await resp.json()

  return c.json({
    cert: respData.crt,
    issued: true
  })
})

app.get('/', async (c) => {
  return c.json({
    message: 'Hello World!',
  })
})

export default app
