export interface GenericStore<TKey, TValue> {
	get(key: TKey): Promise<TValue | undefined>;
	set(key: TKey, value: TValue): Promise<void>;
	delete(key: TKey): Promise<void>;
}
