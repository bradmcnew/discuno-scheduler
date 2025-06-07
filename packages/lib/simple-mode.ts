import type { Session } from "next-auth";
import { getToken } from "next-auth/jwt";
import type { NextRequest } from "next/server";

enum Role {
  ADMIN = "ADMIN",
  USER = "USER",
}

/**
 * Server-side function to check if simple mode should be applied
 * Returns false if user is admin (bypassing simple mode) or if simple mode is disabled
 */
export const shouldApplySimpleMode = async (req?: NextRequest): Promise<boolean> => {
  const isSimpleMode = process.env.NEXT_PUBLIC_SIMPLE_MODE === "true";

  if (!isSimpleMode) {
    return false;
  }

  // If no request object provided, assume simple mode should apply
  if (!req) {
    return true;
  }

  try {
    const token = await getToken({
      req,
      secret: process.env.NEXTAUTH_SECRET,
    });

    // If user is admin, bypass simple mode
    return !(token && token.role === Role.ADMIN);
  } catch {
    // If token verification fails, apply simple mode
    return true;
  }
};

/**
 * Client-side hook to check if simple mode should be applied
 * Returns false if user is admin (bypassing simple mode) or if simple mode is disabled
 */
export const useSimpleMode = (session: Session | null): boolean => {
  const isSimpleMode = process.env.NEXT_PUBLIC_SIMPLE_MODE === "true";

  if (!isSimpleMode) {
    return false;
  }

  // If user is admin, bypass simple mode
  return !(session?.user?.role === Role.ADMIN);
};

/**
 * Static check for simple mode (without admin bypass)
 * Use this only when you can't access user session/token
 */
export const isSimpleModeEnabled = process.env.NEXT_PUBLIC_SIMPLE_MODE === "true";
