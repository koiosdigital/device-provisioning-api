import { z } from 'zod'
import { type D1Database } from '@cloudflare/workers-types'

export type CloudflareBindings = {
    PROVISIONING_JWK: string
    STEP_CA_HOST: string
    OIDC_ISSUER: string
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
    ds_key_id: z.number().int().min(1).max(7),
    rsa_len: z.number().int().min(31).max(128),
    cipher_c: z.string().min(1).max(512).regex(BASE64_REGEX, 'cipher_c must be base64 encoded'),
    iv: z.string().min(1).max(64).regex(BASE64_REGEX, 'iv must be base64 encoded')
})

export const csrMetadataSchema = z.object({
    commonName: z.string().trim().regex(COMMON_NAME_REGEX, 'invalid common name')
})

export type DeviceId = z.infer<typeof deviceIdSchema>
export type DsParams = z.infer<typeof dsParamsSchema>
export type CsrMetadata = z.infer<typeof csrMetadataSchema>

export const swaggerDocument = {
    openapi: '3.1.0',
    info: {
        title: 'Koios Device Provisioning API',
        version: '1.1.0',
        description: 'Provisioning endpoints for the Koios device factory and downstream devices.'
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
            }
        }
    }
} as const

export type SwaggerDocument = typeof swaggerDocument
