import { z } from 'zod'
import { type D1Database } from '@cloudflare/workers-types'

export type CloudflareBindings = {
    PROVISIONING_JWK: string
    STEP_CA_HOST: string
    OIDC_ISSUER: string
    STRIPE_SECRET_KEY: string
    ALLOWED_RETURN_DOMAINS: string // Comma-separated list of allowed domains for return_url
    db: D1Database
}

const BASE64_REGEX = /^[A-Za-z0-9+/=]+$/
const COMMON_NAME_REGEX = /^[A-Za-z0-9.+@_-]{3,128}$/

export const deviceIdSchema = z
    .string()
    .trim()
    .min(3, 'device id too short')
    .max(128, 'device id too long')
    .regex(/^[A-Za-z0-9:_-]+$/, 'device id contains invalid characters')

export const csrBodySchema = z.object({
    csr: z.string().trim().min(1).max(12000)
}).superRefine((value, ctx) => {
    const candidate = value.csr || ''
    if (!candidate.includes('-----BEGIN CERTIFICATE REQUEST-----') || !candidate.includes('-----END CERTIFICATE REQUEST-----')) {
        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'csr must be a valid PEM encoded certificate request'
        })
    }
})

export const dsParamsSchema = z.object({
    ds_key_id: z.number().int().min(1).max(9),
    rsa_len: z.number().int().min(31).max(128),
    cipher_c: z.string().min(1).max(4096).regex(BASE64_REGEX, 'cipher_c must be base64 encoded'),
    iv: z.string().min(1).max(64).regex(BASE64_REGEX, 'iv must be base64 encoded')
})

export const csrMetadataSchema = z.object({
    commonName: z.string().trim().regex(COMMON_NAME_REGEX, 'invalid common name')
})

export const checkoutBodySchema = z.object({
    key_type: z.string().trim().min(1).max(64),
    return_url: z.string().trim().url()
})

export const redeemBodySchema = z.object({
    license_key: z.string().trim().min(1),
    csr: z.string().trim().min(1).max(12000)
}).superRefine((value, ctx) => {
    const candidate = value.csr || ''
    if (!candidate.includes('-----BEGIN CERTIFICATE REQUEST-----') || !candidate.includes('-----END CERTIFICATE REQUEST-----')) {
        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'csr must be a valid PEM encoded certificate request'
        })
    }
})

export type DeviceId = z.infer<typeof deviceIdSchema>
export type DsParams = z.infer<typeof dsParamsSchema>
export type CsrMetadata = z.infer<typeof csrMetadataSchema>
export type CheckoutBody = z.infer<typeof checkoutBodySchema>
export type RedeemBody = z.infer<typeof redeemBodySchema>

export const swaggerDocument = {
    openapi: '3.1.0',
    info: {
        title: 'Koios Device Provisioning API',
        version: '1.2.0',
        description: 'Provisioning endpoints for the Koios device factory, downstream devices, and license management.'
    },
    servers: [
        {
            url: 'https://{host}',
            description: 'Deployed worker',
            variables: {
                host: {
                    default: 'api.koios.sh'
                }
            }
        }
    ],
    paths: {
        '/v1/factory/provision': {
            post: {
                summary: 'Sign a CSR for a factory device',
                security: [{ bearerAuth: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'multipart/form-data': {
                            schema: {
                                type: 'object',
                                properties: {
                                    csr: {
                                        type: 'string',
                                        description: 'PEM encoded certificate signing request'
                                    }
                                },
                                required: ['csr']
                            }
                        }
                    }
                },
                responses: {
                    '200': {
                        description: 'Signed certificate',
                        content: {
                            'application/x-x509-ca-cert': {
                                schema: {
                                    type: 'string',
                                    description: 'Leaf certificate in PEM format'
                                }
                            }
                        }
                    },
                    '400': { description: 'Invalid input' },
                    '401': { description: 'Authentication failed' },
                    '403': { description: 'Unauthorized role' },
                    '500': { description: 'Upstream signing error' }
                }
            }
        },
        '/v1/ds_params': {
            get: {
                summary: 'Fetch deterministic secure parameters for a device',
                parameters: [
                    {
                        name: 'x-device-id',
                        in: 'header',
                        required: true,
                        schema: { type: 'string' }
                    }
                ],
                responses: {
                    '200': {
                        description: 'Device found',
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/DsParams' }
                            }
                        }
                    },
                    '400': { description: 'Missing device header' },
                    '404': { description: 'Device not found' }
                }
            },
            post: {
                summary: 'Persist deterministic secure parameters for a device',
                parameters: [
                    {
                        name: 'x-device-id',
                        in: 'header',
                        required: true,
                        schema: { type: 'string' }
                    }
                ],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: { $ref: '#/components/schemas/DsParams' }
                        }
                    }
                },
                responses: {
                    '200': { description: 'Parameters stored' },
                    '400': { description: 'Validation error' }
                }
            }
        },
        '/v1/license/checkout': {
            post: {
                summary: 'Initiate Stripe checkout session for license purchase',
                security: [{ bearerAuth: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: { $ref: '#/components/schemas/CheckoutRequest' }
                        }
                    }
                },
                responses: {
                    '200': {
                        description: 'Checkout session created',
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/CheckoutResponse' }
                            }
                        }
                    },
                    '400': { description: 'Invalid key_type or return_url' },
                    '401': { description: 'Authentication failed' },
                    '500': { description: 'Failed to create checkout session' }
                }
            }
        },
        '/v1/license/checkout/callback': {
            get: {
                summary: 'Stripe checkout callback (internal use)',
                description: 'Handles Stripe redirect after payment. Validates payment and generates license key.',
                parameters: [
                    {
                        name: 'session_id',
                        in: 'query',
                        required: true,
                        schema: { type: 'string' },
                        description: 'Stripe checkout session ID'
                    }
                ],
                responses: {
                    '302': { description: 'Redirect to return_url with license_key parameter' },
                    '400': { description: 'Missing session_id or payment not completed' },
                    '500': { description: 'Failed to process callback' }
                }
            }
        },
        '/v1/license/redeem': {
            post: {
                summary: 'Redeem license key to sign a CSR',
                description: 'Validates license key, signs the provided CSR, and marks key as used. License keys can only be redeemed once.',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: { $ref: '#/components/schemas/RedeemRequest' }
                        }
                    }
                },
                responses: {
                    '200': {
                        description: 'Signed certificate',
                        content: {
                            'application/x-x509-ca-cert': {
                                schema: {
                                    type: 'string',
                                    description: 'Signed certificate in PEM format'
                                }
                            }
                        }
                    },
                    '400': { description: 'Invalid CSR or license key already used' },
                    '404': { description: 'Invalid license key' },
                    '500': { description: 'Unable to generate provisioning token' },
                    '502': { description: 'Error signing CSR' }
                }
            }
        }
    },
    components: {
        securitySchemes: {
            bearerAuth: {
                type: 'http',
                scheme: 'bearer',
                bearerFormat: 'JWT'
            }
        },
        schemas: {
            DsParams: {
                type: 'object',
                properties: {
                    ds_key_id: { type: 'integer', minimum: 1, maximum: 7 },
                    rsa_len: { type: 'integer', minimum: 31, maximum: 128 },
                    cipher_c: { type: 'string', description: 'Base64 encoded cipher text' },
                    iv: { type: 'string', description: 'Base64 encoded initialization vector' }
                },
                required: ['ds_key_id', 'rsa_len', 'cipher_c', 'iv']
            },
            CheckoutRequest: {
                type: 'object',
                properties: {
                    key_type: {
                        type: 'string',
                        description: 'Type of license key to purchase',
                        enum: ['matrx', 'lantern'],
                        example: 'matrx'
                    },
                    return_url: {
                        type: 'string',
                        format: 'uri',
                        description: 'URL to redirect after successful payment (must be whitelisted)',
                        example: 'https://app.koiosdigital.net/success'
                    }
                },
                required: ['key_type', 'return_url']
            },
            CheckoutResponse: {
                type: 'object',
                properties: {
                    url: {
                        type: 'string',
                        format: 'uri',
                        description: 'Stripe checkout session URL',
                        example: 'https://checkout.stripe.com/c/pay/cs_xxxxxxxxxxxxx'
                    }
                }
            },
            RedeemRequest: {
                type: 'object',
                properties: {
                    license_key: {
                        type: 'string',
                        description: 'License key obtained from checkout',
                        example: 'A1B2-C3D4-E5F6-G7H8-I9J0-K1L2-M3N4-O5P6'
                    },
                    csr: {
                        type: 'string',
                        description: 'PEM encoded certificate signing request',
                        example: '-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----'
                    }
                },
                required: ['license_key', 'csr']
            }
        }
    }
} as const

export type SwaggerDocument = typeof swaggerDocument
