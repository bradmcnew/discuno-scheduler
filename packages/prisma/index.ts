import type { Prisma } from "@prisma/client";
import { PrismaClient as PrismaClientWithoutExtension } from "@prisma/client";
import { withAccelerate } from "@prisma/extension-accelerate";
import { existsSync, readdirSync, accessSync, constants } from "fs";
import { join, resolve } from "path";

import { bookingIdempotencyKeyExtension } from "./extensions/booking-idempotency-key";
import { disallowUndefinedDeleteUpdateManyExtension } from "./extensions/disallow-undefined-delete-update-many";
import { excludeLockedUsersExtension } from "./extensions/exclude-locked-users";
import { excludePendingPaymentsExtension } from "./extensions/exclude-pending-payment-teams";
import { usageTrackingExtention } from "./extensions/usage-tracking";
import { bookingReferenceMiddleware } from "./middleware";

// Force cert bundle to be included in the build
const cwd = process.cwd();

const certDir = join(cwd, "certs");
console.log("🔍 [Prisma] certDir path:", certDir);
console.log("🔍 [Prisma] certDir exists:", existsSync(certDir));
if (existsSync(certDir)) {
  console.log("🔍 [Prisma] certDir contents:", readdirSync(certDir));
}

// resolve the exact cert file path
const certRel = join("certs", "prod-ca-2021.crt");
const certPath = resolve(cwd, certRel);
console.log("🔍 [Prisma] looking for cert at:", certPath);

try {
  accessSync(certPath, constants.R_OK);
  console.log("✅ [Prisma] certificate found at:", certPath);
} catch (err) {
  console.error("❌ [Prisma] certificate missing:", certPath, "-", (err as Error).message);
}
// ───────────────────────────────────────────────────────────────────────

const prismaOptions: Prisma.PrismaClientOptions = {};

const globalForPrisma = global as unknown as {
  prismaWithoutClientExtensions: PrismaClientWithoutExtension;
  prismaWithClientExtensions: PrismaClientWithExtensions;
};

const loggerLevel = parseInt(process.env.NEXT_PUBLIC_LOGGER_LEVEL ?? "", 10);

if (!isNaN(loggerLevel)) {
  switch (loggerLevel) {
    case 5:
    case 6:
      prismaOptions.log = ["error"];
      break;
    case 4:
      prismaOptions.log = ["warn", "error"];
      break;
    case 3:
      prismaOptions.log = ["info", "error", "warn"];
      break;
    default:
      // For values 0, 1, 2 (or anything else below 3)
      prismaOptions.log = ["query", "info", "error", "warn"];
      break;
  }
}

// Prevents flooding with idle connections
const prismaWithoutClientExtensions =
  globalForPrisma.prismaWithoutClientExtensions || new PrismaClientWithoutExtension(prismaOptions);

export const customPrisma = (options?: Prisma.PrismaClientOptions) =>
  new PrismaClientWithoutExtension({ ...prismaOptions, ...options })
    .$extends(usageTrackingExtention(prismaWithoutClientExtensions))
    .$extends(excludeLockedUsersExtension())
    .$extends(excludePendingPaymentsExtension())
    .$extends(bookingIdempotencyKeyExtension())
    .$extends(disallowUndefinedDeleteUpdateManyExtension())
    .$extends(withAccelerate());

// If any changed on middleware server restart is required
// TODO: Migrate it to $extends
bookingReferenceMiddleware(prismaWithoutClientExtensions);

// FIXME: Due to some reason, there are types failing in certain places due to the $extends. Fix it and then enable it
// Specifically we get errors like `Type 'string | Date | null | undefined' is not assignable to type 'Exact<string | Date | null | undefined, string | Date | null | undefined>'`
const prismaWithClientExtensions = prismaWithoutClientExtensions
  .$extends(usageTrackingExtention(prismaWithoutClientExtensions))
  .$extends(excludeLockedUsersExtension())
  .$extends(excludePendingPaymentsExtension())
  .$extends(bookingIdempotencyKeyExtension())
  .$extends(disallowUndefinedDeleteUpdateManyExtension())
  .$extends(withAccelerate());

export const prisma = globalForPrisma.prismaWithClientExtensions || prismaWithClientExtensions;

// This prisma instance is meant to be used only for READ operations.
// If self hosting, feel free to leave INSIGHTS_DATABASE_URL as empty and `readonlyPrisma` will default to `prisma`.
export const readonlyPrisma = process.env.INSIGHTS_DATABASE_URL
  ? customPrisma({
      datasources: { db: { url: process.env.INSIGHTS_DATABASE_URL } },
    })
  : prisma;

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prismaWithoutClientExtensions = prismaWithoutClientExtensions;
  globalForPrisma.prismaWithClientExtensions = prisma;
}

type PrismaClientWithExtensions = typeof prismaWithClientExtensions;
export type PrismaClient = PrismaClientWithExtensions;

type OmitPrismaClient = Omit<
  PrismaClient,
  "$connect" | "$disconnect" | "$on" | "$transaction" | "$use" | "$extends"
>;

// we cant pass tx to functions as types miss match since we have a custom prisma client https://github.com/prisma/prisma/discussions/20924#discussioncomment-10077649
export type PrismaTransaction = OmitPrismaClient;

export default prisma;

export * from "./selects";
