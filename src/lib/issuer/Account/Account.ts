export interface Account {
  accountId: string;
  
  /**
   * 
   * @param use 
   * @param scope Scopes requested
   * @param claims Explicit claims requested via claims parameter
   * @param rejected Claims the user has rejected (consent handling)
   * @returns The return value will be the exact payload of the credential
   */
  claims: (
    use: string,
    scope: string,
    claims?: Record<string, unknown>,
    rejected?: string[],
  ) => Promise<{ sub: string | undefined, [key: string]: unknown }>;
}
