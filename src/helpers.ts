import { importJWK, SignJWT } from "jose"
import * as forge from "node-forge"

export async function extract_csr(pem: string) {
    const csr = forge.pki.certificationRequestFromPem(pem);

    const commonName = csr.subject.getField('CN').value

    return { commonName }
}

export async function generate_jwt(cn: string, dnsSANs: string[], audience: string, issuer: string, jwk: string) {
    // make the jwk
    const jwkJSON = await JSON.parse(jwk)
    const privateKey = await importJWK(jwkJSON)
    const kid = jwkJSON.kid

    const jwt = await new SignJWT({
        sans: dnsSANs,
        sub: cn,
    })
        .setProtectedHeader({ alg: 'ES256', kid: kid })
        .setIssuedAt()
        .setIssuer("provisioner")
        .setAudience(audience)
        .setNotBefore('0s')
        .setExpirationTime('5m')
        .sign(privateKey)
    return jwt
}