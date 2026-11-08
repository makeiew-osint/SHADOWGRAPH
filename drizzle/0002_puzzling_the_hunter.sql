CREATE TABLE `sg_identities` (
	`provider` text NOT NULL,
	`subject` text NOT NULL,
	`account_id` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`account_id`) REFERENCES `sg_accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sg_identities_provider_subject` ON `sg_identities` (`provider`,`subject`);--> statement-breakpoint
CREATE INDEX `sg_identities_account` ON `sg_identities` (`account_id`);--> statement-breakpoint
CREATE TABLE `sg_oauth_pending` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`provider` text NOT NULL,
	`subject` text NOT NULL,
	`name` text NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `sg_oauth_pending_expiry` ON `sg_oauth_pending` (`expires_at`);--> statement-breakpoint
CREATE TABLE `sg_oauth_states` (
	`state_hash` text PRIMARY KEY NOT NULL,
	`provider` text NOT NULL,
	`cookie_hash` text NOT NULL,
	`verifier` text NOT NULL,
	`nonce` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `sg_oauth_states_expiry` ON `sg_oauth_states` (`expires_at`);