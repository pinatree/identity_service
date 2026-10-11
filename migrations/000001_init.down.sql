-- 000001_init.down.sql — откат начальной миграции.
-- Порядок важен: sessions ссылается на users через FK.

DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;