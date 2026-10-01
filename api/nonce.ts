```ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";

export default function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Only allow GET requests
  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed",
    });
  }

  // Generate 32 cryptographically secure random bytes
  const randomBytes = crypto.randomBytes(32);

  // Convert to Base64URL
  const nonce = randomBytes
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  // Meta requires a nonce between 22 and 172 characters
  return res.status(200).json({
    challenge_nonce: nonce,
  });
}
```

