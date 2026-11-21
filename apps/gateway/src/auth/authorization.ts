import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  RouteGenericInterface,
  RouteOptions,
} from 'fastify';
import type { SessionService } from './session.js';
import type { AuthenticatedUser, SessionValidationResult, WebSession } from './types.js';
import {
  assertCanonicalOrigin,
  createCsrfProtectionPreHandler,
  PROTECTED_HTTP_METHODS,
} from './csrf.js';

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

export interface VirtualKeyPolicy {
  readonly allowedModels: readonly string[];
  readonly rpmLimit: number;
  readonly tpmLimit: number;
  readonly concurrentStreamLimit: number;
  readonly exactCacheEnabled: boolean;
  readonly semanticCacheEnabled: boolean;
  readonly piiRedactionEnabled: boolean;
  readonly storePayloads: boolean;
}

export type VirtualKeyPrincipal = {
  readonly type: 'virtual_key';
  readonly keyId: string;
  readonly orgId: string;
  readonly keyPolicy?: VirtualKeyPolicy | Record<string, unknown>;
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
  authenticateKey(rawKey: string, clientIp?: string): Promise<VirtualKeyVerificationResult>;
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
    user?: AuthenticatedUser;
    session?: WebSession;
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
  config: ContextConfig & { authz: RouteAuthorizationPolicy };
};

/**
 * Standard typed route-registration entry point (SW-1.5.4, AUTHZ-03).
 * Enforces mandatory config.authz policy before registering the route with Fastify.
 * Rejects unexpected top-level authz properties and ensures options are not mutated.
 */
export function registerAuthorizedRoute<
  RouteGeneric extends RouteGenericInterface = RouteGenericInterface,
  ContextConfig = Record<string, unknown>,
>(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  app: FastifyInstance<any, any, any, any, any>,
  options: AuthorizedRouteOptions<RouteGeneric, ContextConfig>,
): void {
  if (!options || typeof options !== 'object') {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      'Route options must be a non-null object',
      500,
    );
  }

  // Reject unexpected or conflicting top-level authz declaration at runtime
  if ('authz' in (options as Record<string, unknown>)) {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `Route "${options.url ?? 'UNKNOWN'}": Top-level "authz" property is not permitted; declare policy under "config.authz"`,
      500,
    );
  }

  if (!options.config || typeof options.config !== 'object') {
    throw new AuthorizationError(
      'AUTHZ_ROUTE_POLICY_INVALID',
      `Route "${options.url ?? 'UNKNOWN'}": Missing "config" object with "authz" policy`,
      500,
    );
  }

  const rawPolicy = (options.config as Record<string, unknown>).authz;
  const validatedPolicy = validateRouteAuthorizationPolicy(rawPolicy, {
    method: options.method,
    url: options.url,
  });

  const routeOptionsCopy = {
    ...options,
    config: {
      ...options.config,
      authz: { ...validatedPolicy },
    },
  };

  app.route(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    routeOptionsCopy as RouteOptions<any, any, any, RouteGeneric, ContextConfig>,
  );
}

/**
 * Validates the runtime shape of a verified virtual-key principal (AUTHZ-01).
 * Requires valid: true, virtual_key type, nonempty keyId and orgId, and rejects browser-role identity.
 */
function isValidVirtualKeyPrincipal(principal: unknown): principal is VirtualKeyPrincipal {
  if (!principal || typeof principal !== 'object' || Array.isArray(principal)) {
    return false;
  }
  const p = principal as Record<string, unknown>;
  if (p.type !== 'virtual_key') {
    return false;
  }
  if (typeof p.keyId !== 'string' || p.keyId.trim() === '') {
    return false;
  }
  if (typeof p.orgId !== 'string' || p.orgId.trim() === '') {
    return false;
  }
  // Reject browser-role identity fields (role, userId)
  if ('role' in p || 'userId' in p) {
    return false;
  }
  return true;
}

/**
 * Extracts validated user and session objects established on the request (AUTHZ-02).
 */
function extractBrowserIdentity(req: FastifyRequest): {
  user: AuthenticatedUser;
  session: WebSession;
} | null {
  const reqObj = req as unknown as { user?: unknown; session?: unknown };
  const user = reqObj.user as AuthenticatedUser | undefined;
  const session = reqObj.session as WebSession | undefined;
  if (!user || !session) {
    return null;
  }
  return { user, session };
}

async function handleBrowserAuthorization(
  req: FastifyRequest,
  reply: FastifyReply,
  policy: BrowserRoutePolicy,
  options: AuthorizationBoundaryOptions,
  csrfPreHandler: (req: FastifyRequest, reply: FastifyReply) => Promise<void>,
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
  const isProtectedMutation = PROTECTED_HTTP_METHODS.has(method);

  if (!isSafeRead && !isProtectedMutation) {
    reply.status(405).send({
      statusCode: 405,
      error: 'Method Not Allowed',
      message: 'Method Not Allowed',
    });
    return;
  }

  // Clear any preexisting identity on req to prevent trusting unverified attributes
  const rawReq = req as unknown as { user?: unknown; session?: unknown };
  delete rawReq.user;
  delete rawReq.session;

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

    // 6. Attach trusted immutable browser principal and request identity
    req.principal = Object.freeze({
      type: 'browser',
      userId: validation.user.id,
      orgId: validation.user.orgId,
      role: userRole,
    });
    req.user = validation.user;
    req.session = validation.session;
    return;
  }

  // State-changing browser mutation (POST, PUT, PATCH, DELETE)
  // Invoke accepted CSRF preHandler (AUTHZ-02)
  await csrfPreHandler(req, reply);

  // If CSRF preHandler sent an error response, terminate authorization immediately
  if (reply.sent) {
    return;
  }

  // Only after successful CSRF validation, read verified user/session identity established by middleware
  const identity = extractBrowserIdentity(req);
  if (!identity) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  const { user, session } = identity;

  // Validate user/session ID and organization agreement
  if (user.id !== session.userId || user.orgId !== session.orgId) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  // Apply declared minimum browser role
  const userRole = user.role;
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

  // Construct the immutable browser principal
  req.principal = Object.freeze({
    type: 'browser',
    userId: user.id,
    orgId: user.orgId,
    role: userRole,
  });
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

  const rawKey = authHeader.slice(7);
  if (!rawKey || rawKey.trim() === '') {
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
    result = await virtualKeyAuthenticator.authenticateKey(rawKey, req.ip);
  } catch (err) {
    if (
      (err &&
        typeof err === 'object' &&
        'reason' in err &&
        (err as { reason?: unknown }).reason === 'RATE_LIMITED') ||
      (err &&
        typeof err === 'object' &&
        'code' in err &&
        (err as { code?: unknown }).code === 'RATE_LIMITED')
    ) {
      reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: 'Too many authentication attempts from this IP address. Please try again later.',
      });
      return;
    }
    reply.status(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Authentication service unavailable',
    });
    return;
  }

  // Handle RATE_LIMITED returned as non-exception result
  if (result && result.valid !== true && result.reason === 'RATE_LIMITED') {
    reply.status(429).send({
      statusCode: 429,
      error: 'Too Many Requests',
      message: 'Too many authentication attempts from this IP address. Please try again later.',
    });
    return;
  }

  // Authenticator returns valid: false -> 401 Unauthorized
  if (!result || result.valid !== true) {
    reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authentication required',
    });
    return;
  }

  // Authenticator returns a malformed purported-success result -> controlled 503 (AUTHZ-01)
  if (!isValidVirtualKeyPrincipal(result.principal)) {
    reply.status(503).send({
      statusCode: 503,
      error: 'Service Unavailable',
      message: 'Authentication service unavailable',
    });
    return;
  }

  // 5. Attach trusted virtual-key principal
  req.principal = Object.freeze({
    type: 'virtual_key',
    keyId: result.principal.keyId,
    orgId: result.principal.orgId,
    ...(result.principal.keyPolicy !== undefined ? { keyPolicy: result.principal.keyPolicy } : {}),
  });
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
  const csrfPreHandler = createCsrfProtectionPreHandler({
    sessionService: options.sessionService,
    allowedOrigin: trustedOrigin,
  });

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
      await handleBrowserAuthorization(req, reply, policy, options, csrfPreHandler);
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
