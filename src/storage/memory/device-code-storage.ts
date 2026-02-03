import type { DeviceCode, CreateDeviceCodeInput } from '../../types/token.js';
import type { IDeviceCodeStorage } from '../interfaces/device-code-storage.js';
import { generateId, generateDeviceCode, generateUserCode, hashToken } from '../../crypto/index.js';

/**
 * In-memory device code storage implementation
 */
export class MemoryDeviceCodeStorage implements IDeviceCodeStorage {
  private codes = new Map<string, DeviceCode>();
  private hashIndex = new Map<string, string>(); // `${tenantId}:${hash}` -> id
  private userCodeIndex = new Map<string, string>(); // `${tenantId}:${userCode}` -> id

  async create(input: CreateDeviceCodeInput): Promise<{
    deviceCode: DeviceCode;
    deviceCodeValue: string;
    userCode: string;
  }> {
    const id = generateId();
    const deviceCodeValue = generateDeviceCode();
    const deviceCodeHash = hashToken(deviceCodeValue);
    const userCode = generateUserCode();
    const now = new Date();

    const deviceCode: DeviceCode = {
      id,
      tenantId: input.tenantId,
      clientId: input.clientId,
      deviceCodeHash,
      userCode,
      scope: input.scope,
      expiresAt: input.expiresAt,
      interval: input.interval,
      issuedAt: now,
      status: 'pending',
    };

    this.codes.set(id, deviceCode);
    this.hashIndex.set(`${input.tenantId}:${deviceCodeHash}`, id);
    this.userCodeIndex.set(`${input.tenantId}:${userCode}`, id);

    return { deviceCode, deviceCodeValue, userCode };
  }

  async findByHash(tenantId: string, deviceCodeHash: string): Promise<DeviceCode | null> {
    const id = this.hashIndex.get(`${tenantId}:${deviceCodeHash}`);
    if (!id) return null;
    return this.codes.get(id) ?? null;
  }

  async findByValue(tenantId: string, deviceCodeValue: string): Promise<DeviceCode | null> {
    const deviceCodeHash = hashToken(deviceCodeValue);
    return this.findByHash(tenantId, deviceCodeHash);
  }

  async findByUserCode(tenantId: string, userCode: string): Promise<DeviceCode | null> {
    // Normalize user code (remove dashes, uppercase)
    const normalizedCode = userCode.replace(/-/g, '').toUpperCase();
    // Try with and without dash
    const withDash = normalizedCode.slice(0, 4) + '-' + normalizedCode.slice(4);

    const id = this.userCodeIndex.get(`${tenantId}:${withDash}`);
    if (!id) return null;
    return this.codes.get(id) ?? null;
  }

  async updateLastPolled(id: string): Promise<boolean> {
    const code = this.codes.get(id);
    if (!code) return false;

    const now = new Date();

    // Check if polling too fast
    if (code.lastPolledAt) {
      const timeSinceLastPoll = now.getTime() - code.lastPolledAt.getTime();
      if (timeSinceLastPoll < code.interval * 1000) {
        return false; // Polling too fast
      }
    }

    this.codes.set(id, { ...code, lastPolledAt: now });
    return true;
  }

  async authorize(id: string, userId: string): Promise<DeviceCode> {
    const code = this.codes.get(id);
    if (!code) {
      throw new Error(`Device code not found: ${id}`);
    }

    const updated: DeviceCode = {
      ...code,
      userId,
      status: 'authorized',
    };
    this.codes.set(id, updated);
    return updated;
  }

  async deny(id: string): Promise<DeviceCode> {
    const code = this.codes.get(id);
    if (!code) {
      throw new Error(`Device code not found: ${id}`);
    }

    const updated: DeviceCode = {
      ...code,
      status: 'denied',
    };
    this.codes.set(id, updated);
    return updated;
  }

  async consume(id: string): Promise<void> {
    const code = this.codes.get(id);
    if (code) {
      // Remove from indexes when consumed
      this.hashIndex.delete(`${code.tenantId}:${code.deviceCodeHash}`);
      this.userCodeIndex.delete(`${code.tenantId}:${code.userCode}`);
      this.codes.delete(id);
    }
  }

  async deleteExpired(tenantId: string): Promise<number> {
    const now = new Date();
    let deleted = 0;

    for (const [id, code] of this.codes) {
      if (code.tenantId === tenantId && code.expiresAt < now) {
        this.hashIndex.delete(`${code.tenantId}:${code.deviceCodeHash}`);
        this.userCodeIndex.delete(`${code.tenantId}:${code.userCode}`);
        this.codes.delete(id);
        deleted++;
      }
    }

    return deleted;
  }
}
