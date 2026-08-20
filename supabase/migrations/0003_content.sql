-- 0003_content.sql
-- Skeleton tables for later phases. Phase 1 creates them and locks them down;
-- it deliberately puts no publishing, scheduling or platform logic in them.

do $$ begin
  create type public.social_platform as enum
    ('facebook', 'instagram', 'x', 'tiktok', 'linkedin', 'youtube');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type public.account_status as enum ('connected', 'disconnected', 'error');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type public.post_status as enum
    ('draft', 'pending_approval', 'approved', 'scheduled', 'published', 'failed');
exception when duplicate_object then null;
end $$;

create table if not exists public.social_accounts (
  id                        uuid primary key default gen_random_uuid(),
  business_id               uuid not null references public.businesses (id) on delete cascade,
  platform                  public.social_platform not null,
  label                     text not null check (length(trim(label)) between 1 and 120),
  provider                  text,
  -- A public, non-secret identifier from the platform (e.g. a page id).
  provider_account_ref      text,
  -- The NAME of a Supabase Vault secret, never the secret itself.
  -- Phase 2 resolves this server-side; the value never reaches the browser.
  encrypted_credential_ref  text,
  status                    public.account_status not null default 'disconnected',
  connected_at              timestamptz,
  created_at                timestamptz not null default now()
);

-- Guard rail: this column must hold a Vault secret NAME, not a credential.
-- Anything long or token-shaped is almost certainly a leaked secret, so reject it.
alter table public.social_accounts
  drop constraint if exists social_accounts_credential_ref_is_a_reference;
alter table public.social_accounts
  add constraint social_accounts_credential_ref_is_a_reference
  check (
    encrypted_credential_ref is null
    or encrypted_credential_ref ~ '^[a-z0-9_\-]{1,80}$'
  );

create table if not exists public.posts (
  id          uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses (id) on delete cascade,
  created_by  uuid references auth.users (id) on delete set null,
  status      public.post_status not null default 'draft',
  body        jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);

create table if not exists public.scheduled_posts (
  id                uuid primary key default gen_random_uuid(),
  post_id           uuid not null references public.posts (id) on delete cascade,
  social_account_id uuid not null references public.social_accounts (id) on delete cascade,
  scheduled_for     timestamptz not null,
  status            public.post_status not null default 'scheduled',
  attempts          int not null default 0 check (attempts >= 0),
  created_at        timestamptz not null default now()
);

create index if not exists social_accounts_business_idx on public.social_accounts (business_id);
create index if not exists posts_business_idx on public.posts (business_id);
create index if not exists scheduled_posts_post_idx on public.scheduled_posts (post_id);
create index if not exists scheduled_posts_due_idx on public.scheduled_posts (scheduled_for);

alter table public.social_accounts  enable row level security;
alter table public.posts            enable row level security;
alter table public.scheduled_posts  enable row level security;
alter table public.social_accounts  force row level security;
alter table public.posts            force row level security;
alter table public.scheduled_posts  force row level security;
