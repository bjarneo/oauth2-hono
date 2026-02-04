import type {
  Tenant,
  CreateTenantInput,
  UpdateTenantInput,
  SigningKey,
  OAuthClient,
  CreateClientInput,
  UpdateClientInput,
  RefreshToken,
  IdentityProvider,
  CreateIdentityProviderInput,
  UpdateIdentityProviderInput,
  PaginatedResponse,
  PaginationParams,
  DashboardStats,
  TenantStats,
  TokenFilterParams,
  BulkRevocationResult,
  ClientWithSecret,
  KeyRotationResult,
} from '@oauth2-hono/shared';

const API_BASE = '/_admin';

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new ApiError(response.status, error.message || 'Request failed');
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

function buildQueryString(params: object): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      searchParams.set(key, String(value));
    }
  }
  const queryString = searchParams.toString();
  return queryString ? `?${queryString}` : '';
}

// Dashboard
export async function getDashboardStats(): Promise<DashboardStats> {
  return request('/stats');
}

// Tenants
export async function listTenants(params?: PaginationParams): Promise<PaginatedResponse<Tenant>> {
  return request(`/tenants${buildQueryString(params || {})}`);
}

export async function getTenant(id: string): Promise<Tenant> {
  return request(`/tenants/${id}`);
}

export async function getTenantStats(id: string): Promise<TenantStats> {
  return request(`/tenants/${id}/stats`);
}

export async function createTenant(data: CreateTenantInput): Promise<Tenant> {
  return request('/tenants', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateTenant(id: string, data: UpdateTenantInput): Promise<Tenant> {
  return request(`/tenants/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteTenant(id: string): Promise<void> {
  return request(`/tenants/${id}`, {
    method: 'DELETE',
  });
}

// Clients
export async function listClients(
  tenantId: string,
  params?: PaginationParams
): Promise<PaginatedResponse<OAuthClient>> {
  return request(`/tenants/${tenantId}/clients${buildQueryString(params || {})}`);
}

export async function getClient(id: string): Promise<OAuthClient> {
  return request(`/clients/${id}`);
}

export async function createClient(data: CreateClientInput): Promise<ClientWithSecret> {
  return request(`/tenants/${data.tenantId}/clients`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateClient(id: string, data: UpdateClientInput): Promise<OAuthClient> {
  return request(`/clients/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteClient(id: string): Promise<void> {
  return request(`/clients/${id}`, {
    method: 'DELETE',
  });
}

export async function regenerateClientSecret(id: string): Promise<{ clientSecret: string }> {
  return request(`/clients/${id}/regenerate-secret`, {
    method: 'POST',
  });
}

// Signing Keys
export async function listSigningKeys(tenantId: string): Promise<SigningKey[]> {
  return request(`/tenants/${tenantId}/signing-keys`);
}

export async function createSigningKey(
  tenantId: string,
  data: { algorithm?: string; isPrimary?: boolean }
): Promise<SigningKey> {
  return request(`/tenants/${tenantId}/signing-keys`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function setSigningKeyPrimary(id: string): Promise<SigningKey> {
  return request(`/signing-keys/${id}/set-primary`, {
    method: 'PUT',
  });
}

export async function deleteSigningKey(id: string): Promise<void> {
  return request(`/signing-keys/${id}`, {
    method: 'DELETE',
  });
}

export async function rotateSigningKeys(tenantId: string): Promise<KeyRotationResult> {
  return request(`/tenants/${tenantId}/signing-keys/rotate`, {
    method: 'POST',
  });
}

// Refresh Tokens
export async function listRefreshTokens(
  tenantId: string,
  params?: TokenFilterParams
): Promise<PaginatedResponse<RefreshToken>> {
  return request(`/tenants/${tenantId}/refresh-tokens${buildQueryString(params || {})}`);
}

export async function revokeRefreshToken(id: string): Promise<void> {
  return request(`/refresh-tokens/${id}/revoke`, {
    method: 'POST',
  });
}

export async function revokeUserTokens(tenantId: string, userId: string): Promise<BulkRevocationResult> {
  return request(`/tenants/${tenantId}/refresh-tokens/revoke-by-user/${userId}`, {
    method: 'POST',
  });
}

// Identity Providers
export async function listIdentityProviders(tenantId: string): Promise<IdentityProvider[]> {
  return request(`/tenants/${tenantId}/identity-providers`);
}

export async function getIdentityProvider(id: string): Promise<IdentityProvider> {
  return request(`/identity-providers/${id}`);
}

export async function createIdentityProvider(data: CreateIdentityProviderInput): Promise<IdentityProvider> {
  return request(`/tenants/${data.tenantId}/identity-providers`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateIdentityProvider(
  id: string,
  data: UpdateIdentityProviderInput
): Promise<IdentityProvider> {
  return request(`/identity-providers/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteIdentityProvider(id: string): Promise<void> {
  return request(`/identity-providers/${id}`, {
    method: 'DELETE',
  });
}

export { ApiError };
