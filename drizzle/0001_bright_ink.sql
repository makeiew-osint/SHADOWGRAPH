CREATE TABLE `sg_invites` (
	`id` text PRIMARY KEY NOT NULL,
	`batch_id` text NOT NULL,
	`slot` integer NOT NULL,
	`key_hash` text NOT NULL,
	`created_by` text NOT NULL,
	`created_at` integer NOT NULL,
	`claimed_by` text,
	`claimed_at` integer,
	`revoked_at` integer,
	FOREIGN KEY (`created_by`) REFERENCES `sg_accounts`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`claimed_by`) REFERENCES `sg_accounts`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sg_invites_key_hash` ON `sg_invites` (`key_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `sg_invites_batch_slot` ON `sg_invites` (`batch_id`,`slot`);--> statement-breakpoint
CREATE TABLE `sg_settings` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL
);
--> statement-breakpoint
ALTER TABLE `sg_accounts` ADD `name_key` text;--> statement-breakpoint
ALTER TABLE `sg_accounts` ADD `role` text DEFAULT 'member' NOT NULL;--> statement-breakpoint
ALTER TABLE `sg_accounts` ADD `vault_key` text;--> statement-breakpoint
CREATE UNIQUE INDEX `sg_accounts_name_key` ON `sg_accounts` (`name_key`);