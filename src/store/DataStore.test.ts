import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DataStore } from './DataStore';

const mockClient = {
	get: vi.fn(),
	set: vi.fn(),
	del: vi.fn(),
};

describe('DataStore', () => {
	let store: DataStore<{ x: number }>;

	beforeEach(() => {
		vi.clearAllMocks();
		store = new DataStore(mockClient as any, 'test');
	});

	it('gets values by prefixed key', async () => {
		mockClient.get.mockResolvedValueOnce(JSON.stringify({ x: 1 }));

		const value = await store.get('abc');

		expect(mockClient.get).toHaveBeenCalledWith('test:abc');
		expect(value).toEqual({ x: 1 });
	});

	it('returns undefined when the key is missing', async () => {
		mockClient.get.mockResolvedValueOnce(null);

		await expect(store.get('missing')).resolves.toBeUndefined();
	});

	it('sets serialized values by prefixed key', async () => {
		await store.set('abc', { x: 1 });

		expect(mockClient.set).toHaveBeenCalledWith('test:abc', JSON.stringify({ x: 1 }));
	});

	it('sets values with a millisecond ttl', async () => {
		await store.set('abc', { x: 1 }, 5000);

		expect(mockClient.set).toHaveBeenCalledWith('test:abc', JSON.stringify({ x: 1 }), 'PX', 5000);
	});

	it('deletes values by prefixed key', async () => {
		await store.delete('abc');

		expect(mockClient.del).toHaveBeenCalledWith('test:abc');
	});

	it('does not support scanning all values', async () => {
		await expect(store.getAll()).rejects.toThrow('getAll() is not supported by DataStore.');
	});
});
