-- 0002_tenancy.sql
-- The tenant root: a business, and the people who belong to it.

create table if not exists public.businesses (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (length(trim(name)) between 1 and 120),
  timezone    text not null default 'UTC',
  created_at  timestamptz not null default now(),
  created_by  uuid references auth.users (id) on delete set null
);

do $$ begin
  create type public.member_role as enum ('owner', 'manager', 'viewer');
exception when duplicate_object then null;
end $$;

create table if not exists public.business_members (
  id           uuid primary key default gen_random_uuid(),
  business_id  uuid not null references public.businesses (id) on delete cascade,
  user_id      uuid not null references auth.users (id) on delete cascade,
  role         public.member_role not null default 'viewer',
  created_at   timestamptz not null default now(),
  unique (business_id, user_id)
);

-- Membership is looked up on every single RLS check, so index both directions.
create index if not exists business_members_user_idx on public.business_members (user_id);
create index if not exists business_members_business_idx on public.business_members (business_id);

alter table public.businesses enable row level security;
alter table public.business_members enable row level security;

-- Belt and braces: FORCE applies RLS even to the table owner, so a migration or a
-- mis-scoped connection cannot quietly read across tenants.
alter table public.businesses force row level security;
alter table public.business_members force row level security;
