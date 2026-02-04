/**
 * Identity Provider type
 */
export type IdentityProviderType = 'oidc' | 'oauth2' | 'saml';

/**
 * Pre-configured identity provider templates
 */
export type IdentityProviderTemplate =
  | 'google'
  | 'github'
  | 'microsoft'
  | 'apple'
  | 'facebook'
  | 'twitter'
  | 'linkedin'
  | 'generic_oidc'
  | 'generic_oauth2';

/**
 * Attribute mapping for IdP to local user
 */
export interface AttributeMapping {
  id?: string;
  email?: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  picture?: string;
  emailVerified?: string;
  locale?: string;
}

/**
 * Identity Provider configuration
 */
export interface IdentityProvider {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  type: IdentityProviderType;
  template?: IdentityProviderTemplate;
  clientId: string;
  clientSecretEncrypted: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  scopes: string[];
  attributeMapping?: AttributeMapping;
  enabled: boolean;
  displayOrder?: number;
  iconUrl?: string;
  buttonText?: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Identity Provider creation input
 */
export interface CreateIdentityProviderInput {
  tenantId: string;
  name: string;
  slug: string;
  type?: IdentityProviderType;
  template?: IdentityProviderTemplate;
  clientId: string;
  clientSecret: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  scopes?: string[];
  attributeMapping?: AttributeMapping;
  enabled?: boolean;
  displayOrder?: number;
  iconUrl?: string;
  buttonText?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Identity Provider update input
 */
export interface UpdateIdentityProviderInput {
  name?: string;
  clientId?: string;
  clientSecret?: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  scopes?: string[];
  attributeMapping?: AttributeMapping;
  enabled?: boolean;
  displayOrder?: number;
  iconUrl?: string;
  buttonText?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Storage interface for identity provider management
 */
export interface IIdentityProviderStorage {
  /**
   * Create a new identity provider
   */
  create(input: CreateIdentityProviderInput): Promise<IdentityProvider>;

  /**
   * Find an identity provider by ID
   */
  findById(id: string): Promise<IdentityProvider | null>;

  /**
   * Find an identity provider by slug within a tenant
   */
  findBySlug(tenantId: string, slug: string): Promise<IdentityProvider | null>;

  /**
   * Update an identity provider
   */
  update(id: string, input: UpdateIdentityProviderInput): Promise<IdentityProvider>;

  /**
   * Delete an identity provider
   */
  delete(id: string): Promise<void>;

  /**
   * List all identity providers for a tenant
   */
  listByTenant(tenantId: string): Promise<IdentityProvider[]>;

  /**
   * List enabled identity providers for a tenant (for login page)
   */
  listEnabledByTenant(tenantId: string): Promise<IdentityProvider[]>;
}
