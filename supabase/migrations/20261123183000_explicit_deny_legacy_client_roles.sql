-- Make the legacy RLS posture explicit and remove dangerous client table privileges.
-- These tables already had RLS enabled with no policies (effective default deny).
-- Explicit deny policies preserve that behaviour while REVOKE also removes
-- TRUNCATE, MAINTAIN, TRIGGER, REFERENCES and other table-level grants.
-- service_role and database owners are deliberately untouched.

DO $$
DECLARE
  target record;
  deny_policy constant text := 'vgs_explicit_deny_client_access';
BEGIN
  FOR target IN
    SELECT n.nspname, c.relname
      FROM pg_class AS c
      JOIN pg_namespace AS n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND c.relrowsecurity
       AND NOT EXISTS (
         SELECT 1 FROM pg_policy AS p WHERE p.polrelid = c.oid
       )
     ORDER BY c.relname
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM anon, authenticated',
      target.nspname, target.relname
    );
    EXECUTE format(
      'CREATE POLICY %I ON %I.%I FOR ALL TO anon, authenticated USING (false) WITH CHECK (false)',
      deny_policy, target.nspname, target.relname
    );
  END LOOP;
END
$$;
