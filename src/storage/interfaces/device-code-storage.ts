import type { DeviceCode, CreateDeviceCodeInput } from '../../types/token.js';

/**
 * Storage interface for device code management
 * RFC 8628
 */
export interface IDeviceCodeStorage {
  /**
   * Create a new device code
   * Returns the device code record, the plaintext device code, and user code
   */
  create(input: CreateDeviceCodeInput): Promise<{
    deviceCode: DeviceCode;
    deviceCodeValue: string;
    userCode: string;
  }>;

  /**
   * Find a device code by its hash
   */
  findByHash(tenantId: string, deviceCodeHash: string): Promise<DeviceCode | null>;

  /**
   * Find a device code by plaintext value
   */
  findByValue(tenantId: string, deviceCodeValue: string): Promise<DeviceCode | null>;

  /**
   * Find a device code by user code
   */
  findByUserCode(tenantId: string, userCode: string): Promise<DeviceCode | null>;

  /**
   * Update the last polled timestamp
   * Returns false if polling too fast (slow_down error)
   */
  updateLastPolled(id: string): Promise<boolean>;

  /**
   * Authorize a device code (user approved)
   */
  authorize(id: string, userId: string): Promise<DeviceCode>;

  /**
   * Deny a device code (user rejected)
   */
  deny(id: string): Promise<DeviceCode>;

  /**
   * Mark a device code as consumed
   */
  consume(id: string): Promise<void>;

  /**
   * Delete expired device codes (cleanup)
   */
  deleteExpired(tenantId: string): Promise<number>;
}
