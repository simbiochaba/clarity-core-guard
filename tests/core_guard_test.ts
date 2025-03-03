import {
  Clarinet,
  Tx,
  Chain,
  Account,
  types
} from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

[... existing tests unchanged ...]

Clarinet.test({
  name: "Ensures empty data storage is rejected",
  async fn(chain: Chain, accounts: Map<string, Account>) {
    const user1 = accounts.get('wallet_1')!;
    
    let block = chain.mineBlock([
      Tx.contractCall('core_guard', 'store-data', [
        types.utf8("")
      ], user1.address)
    ]);
    block.receipts[0].result.expectErr(types.uint(106)); // err-empty-data
  }
});

[... additional new tests ...]
