import { get } from "@vercel/edge-config";
import { collectEvents } from "next-collect/server";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import { extendEventData, nextCollectBasicSettings } from "@calcom/lib/telemetry";

import { csp } from "./lib/csp";

const safeGet = async <T = any>(key: string): Promise<T | undefined> => {
  try {
    return get<T>(key);
  } catch (error) {
    // Don't crash if EDGE_CONFIG env var is missing
  }
};

// [DISCUNO CUSTOMIZATION] Blocking paths
// https://mentor.discuno.com/*
const BLOCKED_PATHS = [
  // Pages
  "/teams",
  "/routing",
  "/workflows",
  "/enterprise",
  "/org/",
  "/team/",
  "/more",
  "/connect-and-join",
  "/upgrade",
  "/refer",
  "/payment",
  "/settings/security/impersonation",
  "/settings/security/sso",
  "/settings/my-account/out-of-office",
  "/settings/billing",
  "/settings/developer/webhooks",
  "/settings/developer/api-keys",
  "/settings/teams/new",
  // API paths
  "/api/video/recording",
  "/api/version",
  "/api/user/referrals-token",
  "/api/teams",
  "/api/me",
  "/api/intercom-hash",
  "/api/email",
  "/auth/oidc",
  "/auth/saml",
  "/bookings/unconfirmed",
  "/bookings/recurring",
  // tRPC paths (corrected)
  "/api/trpc/teams",
  "/api/trpc/organizations",
  "/api/trpc/workflows",
  "/api/trpc/webhook",
  "/api/trpc/apiKeys",
  "/api/trpc/insights",
  "/api/trpc/saml",
  "/api/trpc/dsync",
  "/api/trpc/oAuth",
  "/api/trpc/googleWorkspace",
  "/api/trpc/delegationCredential",
  "/api/trpc/routingForms",
  "/api/trpc/appRoutingForms",
  "/api/trpc/appBasecamp3",
  "/api/trpc/attributes",
  "/api/trpc/ooo",
  "/api/trpc/calVideo",
  "/api/trpc/availability/team",
  "/api/trpc/eventTypes/create",
  "/api/trpc/eventTypes/delete",
  "/api/trpc/eventTypes/duplicate",
];

// https://mentor.discuno.com/event-types/##?tabName=*
const BLOCKED_EVENT_TABS = ["workflows", "webhooks", "recurring", "limits", "advanced"];

const BLOCKED_DIALOG = ["new", "embed", "duplicate"];

const checkSimplemode = (req: NextRequest): NextResponse | null => {
  const isSimpleMode = process.env.SIMPLE_MODE === "true";

  if (!isSimpleMode) {
    return null;
  }

  const pathname = req.nextUrl.pathname;
  const searchParams = req.nextUrl.searchParams;

  // Check if the path is blocked
  const isBlockedPath = BLOCKED_PATHS.some((blockedPath) => {
    const isBlocked = pathname.startsWith(blockedPath);
    return isBlocked;
  });

  if (isBlockedPath) {
    return new NextResponse(null, { status: 404, statusText: "Not Found" });
  }

  // Check if event type tab is blocked
  if (pathname.startsWith("/event-types/")) {
    const tabName = searchParams.get("tabName");
    if (tabName && BLOCKED_EVENT_TABS.includes(tabName)) {
      return new NextResponse(null, { status: 404, statusText: "Not Found" });
    }
  }

  // Check if event type dialog is blocked
  if (pathname === "/event-types") {
    const dialog = searchParams.get("dialog");
    if (dialog && BLOCKED_DIALOG.includes(dialog)) {
      return new NextResponse(null, { status: 404, statusText: "Not Found" });
    }
  }

  if (pathname.startsWith("/availability")) {
    const type = searchParams.get("type");
    if (type && type === "team") {
      return new NextResponse(null, { status: 404, statusText: "Not Found" });
    }
  }

  return null;
};
// [DISCUNO CUSTOMIZATION] End

export const POST_METHODS_ALLOWED_API_ROUTES = ["/api/auth/signup", "/api/trpc/"];
export function checkPostMethod(req: NextRequest) {
  const pathname = req.nextUrl.pathname;
  if (!POST_METHODS_ALLOWED_API_ROUTES.some((route) => pathname.startsWith(route)) && req.method === "POST") {
    return new NextResponse(null, {
      status: 405,
      statusText: "Method Not Allowed",
      headers: {
        Allow: "GET",
      },
    });
  }
  return null;
}

export function checkStaticFiles(pathname: string) {
  const hasFileExtension = /\.(svg|png|jpg|jpeg|gif|webp|ico)$/.test(pathname);
  // Skip Next.js internal paths (_next) and static assets
  if (pathname.startsWith("/_next") || hasFileExtension) {
    return NextResponse.next();
  }
}

const middleware = async (req: NextRequest): Promise<NextResponse<unknown>> => {
  // [DISCUNO CUSTOMIZATION] Route blocking middleware
  const simpleModeBlocked = checkSimplemode(req);
  if (simpleModeBlocked) return simpleModeBlocked;
  // [DISCUNO CUSTOMIZATION] End

  const postCheckResult = checkPostMethod(req);
  if (postCheckResult) return postCheckResult;

  const isStaticFile = checkStaticFiles(req.nextUrl.pathname);
  if (isStaticFile) return isStaticFile;

  const url = req.nextUrl;
  const requestHeaders = new Headers(req.headers);

  if (!url.pathname.startsWith("/api")) {
    //
    // NOTE: When tRPC hits an error a 500 is returned, when this is received
    //       by the application the user is automatically redirected to /auth/login.
    //
    //     - For this reason our matchers are sufficient for an app-wide maintenance page.
    //
    // Check whether the maintenance page should be shown
    const isInMaintenanceMode = await safeGet<boolean>("isInMaintenanceMode");
    // If is in maintenance mode, point the url pathname to the maintenance page
    if (isInMaintenanceMode) {
      req.nextUrl.pathname = `/maintenance`;
      return NextResponse.rewrite(req.nextUrl);
    }
  }

  const routingFormRewriteResponse = routingForms.handleRewrite(url);
  if (routingFormRewriteResponse) {
    return responseWithHeaders({ url, res: routingFormRewriteResponse, req });
  }

  if (url.pathname.startsWith("/api/trpc/")) {
    requestHeaders.set("x-cal-timezone", req.headers.get("x-vercel-ip-timezone") ?? "");
  }

  if (url.pathname.startsWith("/api/auth/signup")) {
    const isSignupDisabled = await safeGet<boolean>("isSignupDisabled");
    // If is in maintenance mode, point the url pathname to the maintenance page
    if (isSignupDisabled) {
      // TODO: Consider using responseWithHeaders here
      return NextResponse.json({ error: "Signup is disabled" }, { status: 503 });
    }
  }

  if (url.pathname.startsWith("/auth/login") || url.pathname.startsWith("/login")) {
    // Use this header to actually enforce CSP, otherwise it is running in Report Only mode on all pages.
    requestHeaders.set("x-csp-enforce", "true");
  }

  if (url.pathname.startsWith("/apps/installed")) {
    const returnTo = req.cookies.get("return-to");

    if (returnTo?.value) {
      const response = NextResponse.redirect(new URL(returnTo.value, req.url), { headers: requestHeaders });
      response.cookies.delete("return-to");
      return response;
    }
  }

  const res = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  if (url.pathname.startsWith("/auth/logout")) {
    res.cookies.delete("next-auth.session-token");
  }

  return responseWithHeaders({ url, res, req });
};

const routingForms = {
  handleRewrite: (url: URL) => {
    // Don't 404 old routing_forms links
    if (url.pathname.startsWith("/apps/routing_forms")) {
      url.pathname = url.pathname.replace(/^\/apps\/routing_forms($|\/)/, "/apps/routing-forms/");
      return NextResponse.rewrite(url);
    }
  },
};

const embeds = {
  addResponseHeaders: ({ url, res }: { url: URL; res: NextResponse }) => {
    if (!url.pathname.endsWith("/embed")) {
      return res;
    }
    const isCOEPEnabled = url.searchParams.get("flag.coep") === "true";
    if (isCOEPEnabled) {
      res.headers.set("Cross-Origin-Embedder-Policy", "require-corp");
    }

    const embedColorScheme = url.searchParams.get("ui.color-scheme");
    if (embedColorScheme) {
      res.headers.set("x-embedColorScheme", embedColorScheme);
    }

    res.headers.set("x-isEmbed", "true");
    return res;
  },
};

const contentSecurityPolicy = {
  addResponseHeaders: ({ res, req }: { res: NextResponse; req: NextRequest }) => {
    const { nonce } = csp(req, res ?? null);

    if (!process.env.CSP_POLICY) {
      res.headers.set("x-csp", "not-opted-in");
    } else if (!res.headers.get("x-csp")) {
      // If x-csp not set by gSSP, then it's initialPropsOnly
      res.headers.set("x-csp", "initialPropsOnly");
    } else {
      res.headers.set("x-csp", nonce ?? "");
    }
    return res;
  },
};

function responseWithHeaders({ url, res, req }: { url: URL; res: NextResponse; req: NextRequest }) {
  const resWithCSP = contentSecurityPolicy.addResponseHeaders({ res, req });
  const resWithEmbeds = embeds.addResponseHeaders({ url, res: resWithCSP });
  return resWithEmbeds;
}

export const config = {
  // Next.js Doesn't support spread operator in config matcher, so, we must list all paths explicitly here.
  // https://github.com/vercel/next.js/discussions/42458
  // WARNING: DO NOT ADD AN ENDING SLASH "/" TO THE PATHS BELOW
  // THIS WILL MAKE THEM NOT MATCH AND HENCE NOT HIT MIDDLEWARE
  matcher: [
    // Simple mode blocked paths - UI routes
    "/teams/:path*",
    "/routing/:path*",
    "/workflows/:path*",
    "/enterprise/:path*",
    "/org/:path*",
    "/team/:path*",
    "/more/:path*",
    "/connect-and-join/:path*",
    "/upgrade/:path*",
    "/refer/:path*",
    "/payment/:path*",
    "/settings/security/:path*",
    "/settings/billing/:path*",
    "/settings/developer/:path*",
    "/settings/teams/:path*",
    "/settings/my-account/out-of-office/:path*",

    // Simple mode blocked paths - API routes
    "/api/video/recording/:path*",
    "/api/version/:path*",
    "/api/user/referrals-token/:path*",
    "/api/teams/:path*",
    "/api/me/:path*",
    "/api/intercom-hash/:path*",
    "/api/email/:path*",

    // Simple mode blocked paths - Auth routes
    "/auth/oidc/:path*",
    "/auth/saml/:path*",

    // Simple mode blocked paths - tRPC routes
    "/api/trpc/teams/:path*",
    "/api/trpc/organizations/:path*",
    "/api/trpc/workflows/:path*",
    "/api/trpc/webhook/:path*",
    "/api/trpc/apiKeys/:path*",
    "/api/trpc/insights/:path*",
    "/api/trpc/saml/:path*",
    "/api/trpc/dsync/:path*",
    "/api/trpc/oAuth/:path*",
    "/api/trpc/googleWorkspace/:path*",
    "/api/trpc/delegationCredential/:path*",
    "/api/trpc/routingForms/:path*",
    "/api/trpc/appRoutingForms/:path*",
    "/api/trpc/appBasecamp3/:path*",
    "/api/trpc/attributes/:path*",
    "/api/trpc/ooo/:path*",
    "/api/trpc/calVideo/:path*",
    "/api/trpc/availability/team/:path*",
    "/api/trpc/eventTypes/:path*",

    // Event types with query parameters
    "/event-types/:path*",

    // Availability with query parameters
    "/availability/:path*",

    // --------------------------------------
    // Routes to enforce CSP
    "/auth/login",
    "/login",
    // Routes to set cookies
    "/apps/installed",
    "/auth/logout",
    // Embed Routes,
    "/:path*/embed",
    // API routes
    "/api/auth/signup",
    "/api/trpc/:path*",
  ],
};

export default collectEvents({
  middleware,
  ...nextCollectBasicSettings,
  cookieName: "__clnds",
  extend: extendEventData,
});
