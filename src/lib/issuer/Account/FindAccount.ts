import { Account } from "./Account";

export type FindAccount = (
  ctx: { url: string, method: string, openidvci: { client?: { cliendId: string } } },
  sub: string,
  token: string
) => Promise<Account | undefined>;
