import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  RouteGenericInterface,
  RouteOptions,
} from 'fastify';
import type { SessionService } from './session.js';
import type { SessionValidationResult, SessionWithCsrfValidationResult } from './types.js';
import { assertCanonicalOrigin, hasDuplicateRawHeader, validateOrigin } from './csrf.js';

export type RoutePrincipalType = 'anonymous' | 'browser' | 'virtual_key';
export type BrowserRole = 'admin' | 'member';

export type AnonymousRoutePolicy = {
  readonly principal: 'anonymous';
  readonly minRole?: never;
};

export type BrowserRoutePolicy = {
  readonly principal: 'browser';
  readonly minRole: BrowserRole;
};

export type VirtualKeyRoutePolicy = {
  readonly principal: 'virtual_key';
  readonly minRole?: never;
};

export type RouteAuthorizationPolicy =
  AnonymousRoutePolicy | BrowserRoutePolicy | VirtualKeyRoutePolicy;

export type AnonymousPrincipal = {
  readonly type: 'anonymous';
};

export type BrowserPrincipal = {
  readonly type: 'browser';
  readonly userId: string;
  readonly orgId: string;
  readonly role: BrowserRole;
};

export type VirtualKeyPrincipal = {
  readonly type: 'virtual_key';
  readonly keyId: string;
  readonly orgId: string;
  readonly keyPolicy?: unknown;
};

export type AuthorizedPrincipal = AnonymousPrincipal | BrowserPrincipal | VirtualKeyPrincipal;

export type AuthorizationErrorCode =
  | 'AUTHZ_ROUTE_POLICY_INVALID'
  | 'AUTHENTICATION_REQUIRED'
  | 'PRINCIPAL_TYPE_MISMATCH'
  | 'INSUFFICIENT_ROLE'
  | 'AUTHENTICATION_DEPENDENCY_UNAVAILABLE';

export class AuthorizationError extends Error {
  public readonly code: AuthorizationErrorCode;
  public readonly statusCode: number;

  constructor(
    code: AuthorizationErrorCode,
    message: string,
    statusCode = 403,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'AuthorizationError';
    this.code = code;
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface VirtualKeyVerificationResult {
  readonly valid: boolean;
  readonly principal?: VirtualKeyPrincipal;
  readonly reason?: string;
}

export interface VirtualKeyAuthenticator {
  authenticateKey(rawKey: string): Promise<VirtualKeyVerificationResult>;
}

export interface AuthorizationBoundaryOptions {
  sessionService: SessionService;
  trustedOrigin: string;
  virtualKeyAuthenticator?: VirtualKeyAuthenticator;
}

declare module 'fastify' {
  interface FastifyContextConfig {
    authz?: RouteAuthorizationPolicy;
  }
  interface FastifyRequest {
    principal?: AuthorizedPrincipal;
  }
}

/**
 * Validates route authorization metadata contract at runtime (SW-1.5.4).
 * Fails closed on missing, malformed, or ambiguous route metadata.
 */
export function validateRouteAuthorizationPolicy(
  policy: unknown,
  routeInfo?: { method?: string | string[]; url?: string },
): RouteAuthorizationPolicy {
  const methodStr = Array.isArray(routeInfo?.method)
    ? routeInfo.method.join('/')
    : (routeInfo?.method ?? '');
  const prefix = routeInfo?.url
    ? `Route "${methodStr ? `${methodStr} ` : ''}${routeInfo.url}": `
    : '';

  if (policy === undefined || policy === null) {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Missing route authorization policy. Every route must explicitly declare config.authz`,
      500,
    );
  }

  if (typeof policy !== 'object' || Array.isArray(policy)) {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Route authorization policy must be a non-null object`,
      500,
    );
  }

  const policyRecord = policy as Record<string, unknown>;
  const keys = Object.keys(policyRecord);
  if (keys.length === 0) {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Route authorization policy cannot be an empty object`,
      500,
    );
  }

  const rawPrincipal = policyRecord.principal;
  if (typeof rawPrincipal !== 'string') {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Route authorization policy must declare a string principal`,
      500,
    );
  }

  if (
    rawPrincipal !== 'anonymous' &&
    rawPrincipal !== 'browser' &&
    rawPrincipal !== 'virtual_key'
  ) {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Unknown route principal "${rawPrincipal}"; expected "anonymous", "browser", or "virtual_key"`,
      500,
    );
  }

  if (rawPrincipal === 'anonymous') {
    if ('minRole' in policyRecord) {
      throw new AuthorizationError(
        'AUTHZ_ROUTE_POLICY_INVALID',
        `${prefix}Anonymous routes must not declare minRole`,
        500,
      );
    }
    if (keys.length !== 1 || keys[0] !== 'principal') {
      throw new AuthorizationError(
        'AUTHZ_ROUTE_POLICY_INVALID',
        `${prefix}Anonymous route policy must not declare additional properties beyond principal`,
        500,
      );
    }
    return policy as AnonymousRoutePolicy;
  }

  if (rawPrincipal === 'virtual_key') {
    if ('minRole' in policyRecord) {
      throw new AuthorizationError(
        'AUTHZ_ROUTE_POLICY_INVALID',
        `${prefix}Virtual-key routes must not declare minRole`,
        500,
      );
    }
    if (keys.length !== 1 || keys[0] !== 'principal') {
      throw new AuthorizationError(
        'AUTHZ_ROUTE_POLICY_INVALID',
        `${prefix}Virtual-key route policy must not declare additional properties beyond principal`,
        500,
      );
    }
    return policy as VirtualKeyRoutePolicy;
  }

  // rawPrincipal === 'browser'
  if (!('minRole' in policyRecord) || policyRecord.minRole === undefined) {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Browser routes must declare minRole ("member" or "admin")`,
      500,
    );
  }

  const rawRole = policyRecord.minRole;
  if (rawRole !== 'member' && rawRole !== 'admin') {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Unknown browser role "${String(rawRole)}"; expected "member" or "admin"`,
      500,
    );
  }

  if (keys.length !== 2 || keys.some((k) => k !== 'principal' && k !== 'minRole')) {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `${prefix}Browser route policy must not declare additional properties beyond principal and minRole`,
      500,
    );
  }

  return policy as BrowserRoutePolicy;
}

export type AuthorizedRouteOptions<
  RouteGeneric extends RouteGenericInterface = RouteGenericInterface,
  ContextConfig = Record<string, unknown>,
> = Omit<
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  RouteOptions<any, any, any, RouteGeneric, ContextConfig>,
  'config'
> & {
  authz?: RouteAuthorizationPolicy;
  config?: ContextConfig & { authz?: RouteAuthorizationPolicy };
};

/**
 * Standard typed route-registration entry point (SW-1.5.4).
 * Enforces explicit authorization policy before registering the route with Fastify.
 */
export function registerAuthorizedRoute<
  RouteGeneric extends RouteGenericInterface = RouteGenericInterface,
  ContextConfig = Record<string, unknown>,
>(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app: FastifyInstance<any, any, any, any, any>,
  options: AuthorizedRouteOptions<RouteGeneric, ContextConfig>,
): void {
  const policy = options.authz ?? options.config?.authz;
  const validatedPolicy = validateRouteAuthorizationPolicy(policy, {
    method: options.method,
    url: options.url,
  });

  const routeOptionsCopy = { ...options };
  delete routeOptionsCopy.authz;
  const config = {
    ...(options.config ?? {}),
    authz: { ...validatedPolicy },
  } as ContextConfig & { authz: RouteAuthorizationPolicy };

  app.route({
    ...routeOptionsCopy,
    config,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any);
}

async function handleBrowserAuthorization(
  req: FastifyRequest,
  reply: FastifyReply,
  policy: BrowserRoutePolicy,
  options: AuthorizationBoundaryOptions,
  trustedOrigin: string,
): Promise<void> {
  const { sessionService } = options;

  // 1. Principal separation: Reject Authorization header on browser route
  // Conflicting simultaneous credentials (cookie + auth) or bearer on browser route fail with 401
  const authHeader = req.headers['authorization'];
  if (authHeader !== undefined && authHeader !== '') {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  const method = req.method.toUpperCase();
  const isSafeRead = method === 'GET' || method === 'HEAD';

  if (isSafeRead) {
    // 2. Extract Session Cookie
    const cookieHeader = req.headers['cookie'];
    const sessionSecret = sessionService.extractSessionSecretFromCookieHeader(cookieHeader);
    if (!sessionSecret) {
      reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
      return;
    }

    // 3. Resolve and validate session with DB
    let validation: SessionValidationResult;
    try {
      validation = await sessionService.resolveAndValidateSession(sessionSecret);
    } catch {
      reply.status(503).send({
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Authentication service unavailable',
      });
      return;
    }

    if (!validation.valid || !validation.user || !validation.session) {
      reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
      return;
    }

    // 4. Verify user and session relationship
    if (
      validation.user.id !== validation.session.userId ||
      validation.user.orgId !== validation.session.orgId
    ) {
      reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
      return;
    }

    // 5. RBAC role check
    const userRole = validation.user.role;
    if (policy.minRole === 'admin' && userRole !== 'admin') {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Forbidden',
      });
      return;
    }

    if (userRole !== 'admin' && userRole !== 'member') {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Forbidden',
      });
      return;
    }

    // 6. Attach trusted immutable browser principal
    req.principal = Object.freeze({
      type: 'browser',
      userId: validation.user.id,
      orgId: validation.user.orgId,
      role: userRole,
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).user = validation.user;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).session = validation.session;
    return;
  }

  // State-changing browser mutation (POST, PUT, PATCH, DELETE)
  // Check duplicate raw headers (SW-1.5.3, CSRF-04)
  if (hasDuplicateRawHeader(req.raw.rawHeaders, 'origin')) {
    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Invalid or missing Origin',
    });
    return;
  }

  if (hasDuplicateRawHeader(req.raw.rawHeaders, 'x-csrf-token')) {
    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Invalid or missing CSRF token',
    });
    return;
  }

  // Strict Origin verification
  const rawOrigin = req.headers['origin'];
  const originResult = validateOrigin(rawOrigin, trustedOrigin);
  if (!originResult.valid) {
    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Invalid or missing Origin',
    });
    return;
  }

  // Extract Session Cookie
  const cookieHeader = req.headers['cookie'];
  const sessionSecret = sessionService.extractSessionSecretFromCookieHeader(cookieHeader);
  if (!sessionSecret) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  // Extract CSRF Token Header
  const rawCsrfHeader = req.headers['x-csrf-token'];
  if (!rawCsrfHeader || Array.isArray(rawCsrfHeader) || rawCsrfHeader.includes(',')) {
    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Invalid or missing CSRF token',
    });
    return;
  }

  // Session-bound validation with CSRF
  let validation: SessionWithCsrfValidationResult;
  try {
    validation = await sessionService.resolveAndValidateSessionWithCsrf(
      sessionSecret,
      rawCsrfHeader,
    );
  } catch {
    reply.status(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Authentication service unavailable',
    });
    return;
  }

  if (!validation.valid || !validation.user || !validation.session) {
    if (
      validation.reason === 'CSRF_TOKEN_MISMATCH' ||
      validation.reason === 'MALFORMED_TOKEN' ||
      validation.reason === 'MISSING_TOKEN'
    ) {
      reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Invalid or missing CSRF token',
      });
      return;
    }

    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  // Verify user and session relationship
  if (
    validation.user.id !== validation.session.userId ||
    validation.user.orgId !== validation.session.orgId
  ) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  // RBAC role check
  const userRole = validation.user.role;
  if (policy.minRole === 'admin' && userRole !== 'admin') {
    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Forbidden',
    });
    return;
  }

  if (userRole !== 'admin' && userRole !== 'member') {
    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Forbidden',
    });
    return;
  }

  // Attach trusted immutable browser principal
  req.principal = Object.freeze({
    type: 'browser',
    userId: validation.user.id,
    orgId: validation.user.orgId,
    role: userRole,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (req as any).user = validation.user;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (req as any).session = validation.session;
}

async function handleVirtualKeyAuthorization(
  req: FastifyRequest,
  reply: FastifyReply,
  _policy: VirtualKeyRoutePolicy,
  options: AuthorizationBoundaryOptions,
): Promise<void> {
  const { sessionService, virtualKeyAuthenticator } = options;

  // 1. Browser cookie must not be present (conflicting / principal mismatch)
  const cookieHeader = req.headers['cookie'];
  if (cookieHeader) {
    const sessionSecret = sessionService.extractSessionSecretFromCookieHeader(cookieHeader);
    if (sessionSecret) {
      reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required',
      });
      return;
    }
  }

  // 2. Authorization header must be present and Bearer format
  const authHeader = req.headers['authorization'];
  if (!authHeader || typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  const rawKey = authHeader.slice(7).trim();
  if (!rawKey) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  // 3. Authenticator must be present
  if (!virtualKeyAuthenticator) {
    reply.status(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Authentication service unavailable',
    });
    return;
  }

  // 4. Authenticate key
  let result: VirtualKeyVerificationResult;
  try {
    result = await virtualKeyAuthenticator.authenticateKey(rawKey);
  } catch {
    reply.status(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Authentication service unavailable',
    });
    return;
  }

  if (!result.valid || !result.principal) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  // 5. Attach trusted virtual-key principal
  req.principal = Object.freeze(result.principal);
}

/**
 * Installs root-level registration-time and request-time authorization enforcement boundaries (SW-1.5.4).
 * Every registered route must declare explicit, valid config.authz metadata.
 */
export function installAuthorizationBoundary(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app: FastifyInstance<any, any, any, any, any>,
  options: AuthorizationBoundaryOptions,
): void {
  const trustedOrigin = assertCanonicalOrigin(options.trustedOrigin);

  // 1. Registration-time assertion: enforces default-deny on every route registered
  app.addHook('onRoute', (routeOptions) => {
    const policy = routeOptions.config?.authz;
    const validatedPolicy = validateRouteAuthorizationPolicy(policy, {
      method: routeOptions.method,
      url: routeOptions.url,
    });

    if (validatedPolicy.principal === 'virtual_key') {
      if (!options.virtualKeyAuthenticator) {
        const methodStr = Array.isArray(routeOptions.method)
          ? routeOptions.method.join('/')
          : (routeOptions.method ?? 'UNKNOWN');
        throw new AuthorizationError(
          'AUTHZ_ROUTE_POLICY_INVALID',
          `Route "${methodStr} ${routeOptions.url}": Virtual-key routes require an approved verified-key authentication dependency, but none is installed`,
          500,
        );
      }
    }
  });

  // 2. Request-time assertion: enforces authentication, principal separation, CSRF, and RBAC
  app.addHook('preHandler', async (req: FastifyRequest, reply: FastifyReply) => {
    // If request did not match any registered route, allow Fastify's 404 handler to execute
    if (!req.routeOptions?.url) {
      return;
    }

    const policy = req.routeOptions.config?.authz;
    if (!policy) {
      reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'Internal server error',
      });
      return;
    }

    if (policy.principal === 'anonymous') {
      req.principal = Object.freeze({ type: 'anonymous' });
      return;
    }

    if (policy.principal === 'browser') {
      await handleBrowserAuthorization(req, reply, policy, options, trustedOrigin);
      return;
    }

    if (policy.principal === 'virtual_key') {
      await handleVirtualKeyAuthorization(req, reply, policy, options);
      return;
    }

    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Forbidden',
    });
  });
}
