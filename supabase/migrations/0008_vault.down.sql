-- Reverses 0008_vault.sql. The vault extension itself is left in place:
-- dropping it would destroy stored secrets.
drop function if exists app.read_account_credential(text);
drop function if exists app.store_account_credential(uuid, text);
