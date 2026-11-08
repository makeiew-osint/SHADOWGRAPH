CREATE TABLE `sg_accounts` (
	`id` text PRIMARY KEY NOT NULL,
	`owner` text NOT NULL,
	`name` text NOT NULL,
	`key_hash` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sg_accounts_key_hash` ON `sg_accounts` (`key_hash`);--> statement-breakpoint
CREATE INDEX `sg_accounts_owner` ON `sg_accounts` (`owner`);--> statement-breakpoint
CREATE TABLE `sg_auth_attempts` (
	`id` text PRIMARY KEY NOT NULL,
	`count` integer NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `sg_sessions` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`owner` text NOT NULL,
	`expires_at` integer NOT NULL,
	FOREIGN KEY (`account_id`) REFERENCES `sg_accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sg_sessions_expiry` ON `sg_sessions` (`expires_at`);