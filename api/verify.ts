```ts
import type { VercelRequest, VercelResponse } from "@vercel/node";

interface VerifyRequest {
  attestation_token: string;
  challenge_nonce: string;
}

interface MetaResponse {
  data?: Array<{
    message?: string;
    claims?: string;
  }>;
}

interface AttestationClaims {
  request_details?: {
    timestamp?: number;
    exp?: number;
    nonce?: string;
  };

  app_integrity_state?: string;
  package_name?: string;
  package_cert_sha256_digest?: string;
  device_integrity?: string;
}

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Only allow POST
  if (req.method !== "POST") {
    return res.status(405).json({
      valid: false,
      message: "Method not allowed",
    });
  }

  try {
    const body = req.body as VerifyRequest;

    const attestationToken = body?.attestation_token;
    const challengeNonce = body?.challenge_nonce;

    if (!attestationToken || !challengeNonce) {
      return res.status(400).json({
        valid: false,
        message: "Missing attestation_token or challenge_nonce",
      });
    }

    // ---------------------------------------------------------
    // Get Meta access token from Vercel environment variables
    // ---------------------------------------------------------

    const metaAccessToken = process.env.META_ACCESS_TOKEN;

    if (!metaAccessToken) {
      console.error("META_ACCESS_TOKEN is not configured.");

      return res.status(500).json({
        valid: false,
        message: "Server configuration error",
      });
    }

    // ---------------------------------------------------------
    // Send the attestation token to Meta
    // ---------------------------------------------------------

    const metaUrl =
      "https://graph.oculus.com/platform_integrity/verify";

    const params = new URLSearchParams();

    params.set("token", attestationToken);
    params.set("access_token", metaAccessToken);

    const metaResponse = await fetch(
      `${metaUrl}?${params.toString()}`,
      {
        method: "GET",
      }
    );

    const metaData =
      (await metaResponse.json()) as MetaResponse;

    // ---------------------------------------------------------
    // Check Meta's response
    // ---------------------------------------------------------

    const result = metaData?.data?.[0];

    if (!result) {
      return res.status(403).json({
        valid: false,
        message: "Invalid response from Meta",
```

