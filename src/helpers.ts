import { importJWK, SignJWT, type JWK } from 'jose'
import * as forge from 'node-forge'
import { csrMetadataSchema } from './types'

export async function extractCsr(pem: string) {
    const sanitizedPem = pem.trim()
    if (!sanitizedPem) {
        throw new Error('CSR payload is empty')
    }

    const csr = forge.pki.certificationRequestFromPem(sanitizedPem)
    const field = csr.subject.getField('CN')
    if (!field || !field.value) {
        throw new Error('CSR missing common name')
    }

    return csrMetadataSchema.parse({ commonName: String(field.value).trim() })
}

type GenerateJwtInput = {
    commonName: string
    subjectAlternativeNames?: string[]
    audience: string
    issuer: string
    jwk: string
}

export async function generateJwt(input: GenerateJwtInput) {
    let jwkJson: JWK & { kid?: string; alg?: string }
    try {
        jwkJson = JSON.parse(input.jwk)
    } catch (error) {
        throw new Error('Provisioning key is not valid JSON')
    }

    const algorithm = typeof jwkJson.alg === 'string' ? jwkJson.alg : 'ES256'
    const key = await importJWK(jwkJson, algorithm)
    const sans = (input.subjectAlternativeNames ?? []).map((name) => name.trim()).filter(Boolean)

    const jwt = await new SignJWT({
        sans,
        sub: input.commonName
    })
        .setProtectedHeader({ alg: algorithm, kid: jwkJson.kid })
        .setIssuedAt()
        .setIssuer(input.issuer)
        .setAudience(input.audience)
        .setNotBefore('0s')
        .setExpirationTime('5m')
        .sign(key)

    return jwt
}