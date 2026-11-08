import { sqliteTable, text, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core';
export const accounts = sqliteTable('sg_accounts', {
  id: text('id').primaryKey(),
  owner: text('owner').notNull(),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull(),
  createdAt: integer('created_at').notNull(),
  nameKey: text('name_key'),
  role: text('role').notNull().default('member'),
  vaultKey: text('vault_key'),
}, table => [uniqueIndex('sg_accounts_key_hash').on(table.keyHash), index('sg_accounts_owner').on(table.owner),uniqueIndex('sg_accounts_name_key').on(table.nameKey)]);
export const sessions = sqliteTable('sg_sessions', {
  tokenHash: text('token_hash').primaryKey(),
  accountId: text('account_id').notNull().references(() => accounts.id, { onDelete: 'cascade' }),
  owner: text('owner').notNull(),
  expiresAt: integer('expires_at').notNull(),
}, table => [index('sg_sessions_expiry').on(table.expiresAt)]);
export const attempts = sqliteTable('sg_auth_attempts', {
  id: text('id').primaryKey(),
  count: integer('count').notNull(),
  expiresAt: integer('expires_at').notNull(),
});
export const settings=sqliteTable('sg_settings',{key:text('key').primaryKey(),value:text('value').notNull()});
export const invites=sqliteTable('sg_invites',{
 id:text('id').primaryKey(),batchId:text('batch_id').notNull(),slot:integer('slot').notNull(),keyHash:text('key_hash').notNull(),createdBy:text('created_by').notNull().references(()=>accounts.id),createdAt:integer('created_at').notNull(),claimedBy:text('claimed_by').references(()=>accounts.id),claimedAt:integer('claimed_at'),revokedAt:integer('revoked_at'),
},t=>[uniqueIndex('sg_invites_key_hash').on(t.keyHash),uniqueIndex('sg_invites_batch_slot').on(t.batchId,t.slot)]);
export const identities = sqliteTable('sg_identities', {
  provider: text('provider').notNull(), subject: text('subject').notNull(),
  accountId: text('account_id').notNull().references(() => accounts.id, { onDelete: 'cascade' }), createdAt: integer('created_at').notNull(),
}, t => [uniqueIndex('sg_identities_provider_subject').on(t.provider, t.subject), index('sg_identities_account').on(t.accountId)]);
export const oauthStates = sqliteTable('sg_oauth_states', {
  stateHash: text('state_hash').primaryKey(), provider: text('provider').notNull(), cookieHash: text('cookie_hash').notNull(),
  verifier: text('verifier').notNull(), nonce: text('nonce').notNull(), redirectUri: text('redirect_uri').notNull(), expiresAt: integer('expires_at').notNull(),
}, t => [index('sg_oauth_states_expiry').on(t.expiresAt)]);
export const oauthPending = sqliteTable('sg_oauth_pending', {
  tokenHash: text('token_hash').primaryKey(), provider: text('provider').notNull(), subject: text('subject').notNull(),
  name: text('name').notNull(), expiresAt: integer('expires_at').notNull(),
}, t => [index('sg_oauth_pending_expiry').on(t.expiresAt)]);
