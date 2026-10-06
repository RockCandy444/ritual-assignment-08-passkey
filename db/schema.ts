import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';

export const users = sqliteTable('users', {
  id: text('id').primaryKey(), displayName: text('display_name').notNull(), createdAt: integer('created_at').notNull(),
});
export const passkeys = sqliteTable('passkeys', {
  id: text('id').primaryKey(), userId: text('user_id').notNull().references(() => users.id),
  publicKey: text('public_key').notNull(), counter: integer('counter').notNull(), name: text('name').notNull(),
  storage: text('storage').notNull(), transports: text('transports').notNull(), deviceType: text('device_type').notNull(),
  backedUp: integer('backed_up').notNull(), createdAt: integer('created_at').notNull(), revokedAt: integer('revoked_at'),
}, t => [index('idx_passkeys_owner_active').on(t.userId, t.revokedAt)]);
export const sessions = sqliteTable('sessions', {
  tokenHash: text('token_hash').primaryKey(), userId: text('user_id').notNull().references(() => users.id),
  credentialId: text('credential_id').notNull().references(() => passkeys.id),
  createdAt: integer('created_at').notNull(), expiresAt: integer('expires_at').notNull(),
}, t => [index('idx_sessions_owner').on(t.userId)]);
export const challenges = sqliteTable('challenges', {
  id: text('id').primaryKey(), flowHash: text('flow_hash').notNull(), challenge: text('challenge').notNull(),
  kind: text('kind').notNull(), userId: text('user_id').notNull(), displayName: text('display_name').notNull(),
  keyName: text('key_name').notNull(), storage: text('storage').notNull(), sessionHash: text('session_hash'),
  createdAt: integer('created_at').notNull(), expiresAt: integer('expires_at').notNull(), consumedAt: integer('consumed_at'),
}, t => [index('idx_challenges_lookup').on(t.flowHash, t.challenge, t.kind)]);
export const notes = sqliteTable('notes', {
  id: text('id').primaryKey(), userId: text('user_id').notNull().references(() => users.id),
  category: text('category').notNull(), title: text('title').notNull(), body: text('body').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, t => [index('idx_notes_owner').on(t.userId)]);
export const rateLimits = sqliteTable('rate_limits', {
  bucket: text('bucket').primaryKey(), count: integer('count').notNull(), expiresAt: integer('expires_at').notNull(),
});
