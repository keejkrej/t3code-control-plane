CREATE TABLE "client_authorizations" (
	"id" text PRIMARY KEY NOT NULL,
	"user_code" text NOT NULL,
	"device_code_hash" text NOT NULL,
	"client_name" text NOT NULL,
	"client_kind" text NOT NULL,
	"client_version" text NOT NULL,
	"scopes" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"user_id" text,
	"expires_at" timestamp with time zone NOT NULL,
	"last_polled_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "client_authorizations_user_code_unique" UNIQUE("user_code"),
	CONSTRAINT "client_authorizations_device_code_hash_unique" UNIQUE("device_code_hash")
);
--> statement-breakpoint
CREATE TABLE "client_tokens" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"token_hash" text NOT NULL,
	"name" text NOT NULL,
	"client_kind" text NOT NULL,
	"client_version" text NOT NULL,
	"scopes" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "client_tokens_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "connect_token_issuances" (
	"jti" text PRIMARY KEY NOT NULL,
	"device_id" text NOT NULL,
	"user_id" text NOT NULL,
	"client_token_id" text,
	"scope" text NOT NULL,
	"revocation_epoch" integer NOT NULL,
	"issued_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "device_pairings" (
	"id" text PRIMARY KEY NOT NULL,
	"code" text NOT NULL,
	"public_key" text NOT NULL,
	"name" text NOT NULL,
	"hostname" text NOT NULL,
	"platform" text NOT NULL,
	"arch" text NOT NULL,
	"client_kind" text NOT NULL,
	"client_version" text NOT NULL,
	"tailscale_ip" text,
	"magic_dns_name" text,
	"port" integer NOT NULL,
	"capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"approved_by_user_id" text,
	"device_id" text,
	"expires_at" timestamp with time zone NOT NULL,
	"last_polled_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "device_pairings_code_unique" UNIQUE("code")
);
--> statement-breakpoint
CREATE TABLE "devices" (
	"id" text PRIMARY KEY NOT NULL,
	"owner_user_id" text NOT NULL,
	"name" text NOT NULL,
	"hostname" text NOT NULL,
	"platform" text NOT NULL,
	"arch" text NOT NULL,
	"client_kind" text NOT NULL,
	"client_version" text NOT NULL,
	"tailscale_ip" text,
	"magic_dns_name" text,
	"port" integer NOT NULL,
	"capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"public_key" text NOT NULL,
	"public_key_fingerprint" text NOT NULL,
	"credential_hash" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"revocation_epoch" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	CONSTRAINT "devices_credential_hash_unique" UNIQUE("credential_hash")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY NOT NULL,
	"vercel_user_id" text NOT NULL,
	"email" text,
	"name" text,
	"username" text,
	"avatar_url" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_vercel_user_id_unique" UNIQUE("vercel_user_id")
);
--> statement-breakpoint
ALTER TABLE "client_authorizations" ADD CONSTRAINT "client_authorizations_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_tokens" ADD CONSTRAINT "client_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connect_token_issuances" ADD CONSTRAINT "connect_token_issuances_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "connect_token_issuances" ADD CONSTRAINT "connect_token_issuances_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "device_pairings" ADD CONSTRAINT "device_pairings_approved_by_user_id_users_id_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "devices" ADD CONSTRAINT "devices_owner_user_id_users_id_fk" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "client_authorizations_expires_at_idx" ON "client_authorizations" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "client_tokens_user_idx" ON "client_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "connect_token_issuances_device_idx" ON "connect_token_issuances" USING btree ("device_id");--> statement-breakpoint
CREATE INDEX "device_pairings_expires_at_idx" ON "device_pairings" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "devices_owner_idx" ON "devices" USING btree ("owner_user_id");