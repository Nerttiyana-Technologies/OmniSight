import { randomBytes, scryptSync, timingSafeEqual, createHmac } from "node:crypto";
import type { Role } from "@omnisight/shared";

// Password hashing — scrypt from node:crypto (no external dependency).
export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const expected = Buffer.from(hash, "hex");
  const actual = scryptSync(password, salt, 64);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// Minimal HS256 JWT (no external dependency).
function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj: unknown): string {
  return b64url(JSON.stringify(obj));
}

export interface TokenPayload {
  sub: string;       // user id
  username: string;
  role: Role;
  exp: number;       // unix seconds
}

export function signJwt(payload: Omit<TokenPayload, "exp">, secret: string, ttlHours: number): string {
  const exp = Math.floor(Date.now() / 1000) + ttlHours * 3600;
  const header = b64urlJson({ alg: "HS256", typ: "JWT" });
  const body = b64urlJson({ ...payload, exp });
  const sig = b64url(createHmac("sha256", secret).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

export function verifyJwt(token: string, secret: string): TokenPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, sig] = parts;
  const expected = b64url(createHmac("sha256", secret).update(`${header}.${body}`).digest());
  const a = Buffer.from(sig!);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body!, "base64").toString("utf8")) as TokenPayload;
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}
