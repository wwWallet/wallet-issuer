import Valkey from "iovalkey";
import { GenericStore } from "wallet-common";

export interface SetStore<TValue> {
	addToSet(key: string, value: TValue): Promise<void>;
	getSetMembers(key: string): Promise<TValue[]>;
	removeFromSet(key: string, value: TValue): Promise<void>;
}

export interface ConsumableStore<TKey, TValue> extends GenericStore<TKey, TValue> {
	set(key: TKey, value: TValue, ttlMs?: number): Promise<void>;
	consume(key: TKey): Promise<TValue | undefined>;
}

export class DataStore<TValue> implements ConsumableStore<string, TValue>, SetStore<TValue> {
	constructor(
		private readonly client: Valkey,
		private readonly prefix: string,
		private readonly serializeValue: (value: TValue) => string = JSON.stringify,
		private readonly deserializeValue: (value: string) => TValue = JSON.parse,
	) {
		this.client = client;
	}

	private buildKey(key: string): string {
		return `${this.prefix}:${key}`;
	}

	async get(key: string): Promise<TValue | undefined> {
		const value = await this.client.get(this.buildKey(key));

		return value !== null ? this.deserializeValue(value) : undefined;
	}

	async set(key: string, value: TValue, ttlMs?: number): Promise<void> {
		const builtKey = this.buildKey(key);
		const serializedValue = this.serializeValue(value);

		if(ttlMs !== undefined) {
			await this.client.set(
				builtKey,
				serializedValue,
				"PX",
				ttlMs
			);
		} else {
			await this.client.set(
				builtKey,
				serializedValue
			);
		}
	}

	async delete(key: string): Promise<void> {
		await this.client.del(this.buildKey(key));
	}

	async consume(key: string): Promise<TValue | undefined> {
		const value = await this.client.getdel(this.buildKey(key));
		return value !== null ? this.deserializeValue(value) : undefined;
	}

	async addToSet(key: string, value: TValue): Promise<void> {
		await this.client.sadd(this.buildKey(key), this.serializeValue(value));
	}

	async getSetMembers(key: string): Promise<TValue[]> {
		const members = await this.client.smembers(this.buildKey(key));
		return members.map((member: string) => this.deserializeValue(member));
	}

	async removeFromSet(key: string, value: TValue): Promise<void> {
		await this.client.srem(this.buildKey(key), this.serializeValue(value));
	}

	async getAll(): Promise<TValue[]> {
		throw new Error(
			"getAll() is not supported by DataStore.",
		);
	}
}
