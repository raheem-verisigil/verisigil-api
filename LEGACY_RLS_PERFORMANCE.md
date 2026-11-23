# Legacy RLS query-plan optimization

The restored project had 13 service-role-only policies whose auth.role() call could be evaluated for every row. The optimization wraps that stable identity check in a scalar subquery so PostgreSQL can evaluate it as an init plan once per statement. The policy result is unchanged: only service-role sessions pass. No row data or grants are changed.