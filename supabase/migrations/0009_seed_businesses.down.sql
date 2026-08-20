-- Reverses 0009_seed_businesses.sql. Only removes businesses still carrying their
-- seeded name, so a business you have renamed is never deleted by a rollback.
drop function if exists app.grant_admin_all_businesses(text);
delete from public.businesses
 where name in ('BUSINESS_1','BUSINESS_2','BUSINESS_3','BUSINESS_4',
                'BUSINESS_5','BUSINESS_6','BUSINESS_7');
