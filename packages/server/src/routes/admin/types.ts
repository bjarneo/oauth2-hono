import type { RefreshToken } from '../../types/token.js';
import type { IRefreshTokenStorage } from '../../storage/interfaces/token-storage.js';

/**
 * Extended refresh token storage with list capabilities for admin
 */
export interface IRefreshTokenStorageWithList extends IRefreshTokenStorage {
  listByTenant?(
    tenantId: string,
    options?: {
      userId?: string;
      clientId?: string;
      activeOnly?: boolean;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ items: RefreshToken[]; total: number }>;
}

/**
 * Pagination response
 */
export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}
