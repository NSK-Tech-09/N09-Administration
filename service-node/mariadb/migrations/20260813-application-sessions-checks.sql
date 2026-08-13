-- Contrôles non destructifs du lot 46.
-- Le premier résultat doit valoir 1 après migration ; la table doit être vide
-- avant la première nouvelle connexion de recette.

SELECT COUNT(*) AS application_sessions_table_count
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name = 'application_sessions'
  AND engine = 'InnoDB';

SELECT
  (SELECT COUNT(*)
   FROM information_schema.columns
   WHERE table_schema = DATABASE()
     AND table_name = 'application_sessions') AS column_count,
  (SELECT COUNT(DISTINCT index_name)
   FROM information_schema.statistics
   WHERE table_schema = DATABASE()
     AND table_name = 'application_sessions') AS index_count,
  (SELECT COUNT(*)
   FROM information_schema.referential_constraints
   WHERE constraint_schema = DATABASE()
     AND table_name = 'application_sessions') AS foreign_key_count;

SELECT COUNT(*) AS application_session_count
FROM application_sessions;
