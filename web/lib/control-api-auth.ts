import { SignJWT } from "jose";
import { randomUUID } from "crypto";

export async function createControlApiToken(userId: string): Promise<string> {
  const secret = process.env.INACTU_API_AUTH_SECRET;
  if (!secret) {
    throw new Error("INACTU_API_AUTH_SECRET is required.");
  }
  if (!userId) {
    throw new Error("user id is required to create control API token.");
  }

  return await new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(userId)
    .setIssuer("inactu-web")
    .setAudience("inactu-control")
    .setJti(randomUUID())
    .setIssuedAt()
    .setNotBefore("0s")
    .setExpirationTime("5m")
    .sign(new TextEncoder().encode(secret));
}
