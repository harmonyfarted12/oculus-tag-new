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
      });
    }

    if (result.message !== "success" || !result.claims) {
      return res.status(403).json({
        valid: false,
        message: result.message || "Attestation rejected",
      });
    }

    // ---------------------------------------------------------
    // Decode the verified claims returned by Meta
    // ---------------------------------------------------------

    let claims: AttestationClaims;

    try {
      claims = JSON.parse(
        decodeBase64Url(result.claims)
      );
    } catch {
      return res.status(403).json({
        valid: false,
        message: "Could not decode attestation claims",
      });
    }

    const requestDetails =
      claims.request_details;

    if (!requestDetails) {
      return res.status(403).json({
        valid: false,
        message: "Missing request details",
      });
    }

    // ---------------------------------------------------------
    // Verify nonce
    // ---------------------------------------------------------

    if (requestDetails.nonce !== challengeNonce) {
      return res.status(403).json({
        valid: false,
        message: "Nonce mismatch",
      });
    }

    // ---------------------------------------------------------
    // Verify expiration
    // ---------------------------------------------------------

    const currentTime =
      Math.floor(Date.now() / 1000);

    if (
      !requestDetails.exp ||
      requestDetails.exp <= currentTime
    ) {
      return res.status(403).json({
        valid: false,
        message: "Attestation token expired",
      });
    }

    // ---------------------------------------------------------
    // Optional integrity checks
    //
    // You should replace these with the values belonging
    // to YOUR application.
    // ---------------------------------------------------------

    if (
      claims.device_integrity &&
      claims.device_integrity !== "Basic" &&
      claims.device_integrity !== "Advanced"
    ) {
      return res.status(403).json({
        valid: false,
        message: "Device integrity check failed",
      });
    }

    // ---------------------------------------------------------
    // Everything passed
    // ---------------------------------------------------------

    return res.status(200).json({
      valid: true,
      message: "Attestation successful",

      // Useful information for your backend.
      // Do not return secrets.
      device_integrity:
        claims.device_integrity || null,

      app_integrity_state:
        claims.app_integrity_state || null,

      package_name:
        claims.package_name || null,
    });

  } catch (error) {
    console.error(
      "Attestation verification error:",
      error
    );

    return res.status(500).json({
      valid: false,
      message: "Internal server error",
    });
  }
}

// -------------------------------------------------------------
// Base64URL decoder
// -------------------------------------------------------------

function decodeBase64Url(value: string): string {
  let base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (base64.length % 4 !== 0) {
    base64 += "=";
  }

  return Buffer.from(base64, "base64").toString("utf8");
}
```
