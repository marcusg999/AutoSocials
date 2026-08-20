-- Reverses 0009_seed_businesses.sql.
--
-- Deliberately conservative. `businesses` cascades to members, posts, accounts and
-- scheduled posts, so a careless rollback on a live database would delete real
-- customer data. This removes only businesses that still carry their seeded name
-- AND are completely unused: no members, no posts, no connected accounts.
drop function if exists app.grant_admin_all_businesses(text);

delete from public.businesses b
 where b.name in ('BUSINESS_1','BUSINESS_2','BUSINESS_3','BUSINESS_4',
                  'BUSINESS_5','BUSINESS_6','BUSINESS_7')
   and not exists (select 1 from public.business_members m where m.business_id = b.id)
   and not exists (select 1 from public.posts p            where p.business_id = b.id)
   and not exists (select 1 from public.social_accounts a  where a.business_id = b.id);
