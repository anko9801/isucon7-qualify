CREATE TABLE user (
  id SMALLINT UNSIGNED AUTO_INCREMENT NOT NULL PRIMARY KEY,
  name VARCHAR(191) UNIQUE,
  salt VARCHAR(20),
  password VARCHAR(40),
  display_name TEXT,
  avatar_icon TEXT,
  created_at DATETIME NOT NULL,
  INDEX idx_name (`name`)
) Engine=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE image (
  id SMALLINT UNSIGNED AUTO_INCREMENT NOT NULL PRIMARY KEY,
  name VARCHAR(191),
  data LONGBLOB
) Engine=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE channel (
  id SMALLINT AUTO_INCREMENT NOT NULL PRIMARY KEY,
  name TEXT NOT NULL,
  description MEDIUMTEXT,
  updated_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL
) Engine=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE message (
  id SMALLINT AUTO_INCREMENT NOT NULL PRIMARY KEY,
  channel_id SMALLINT,
  user_id SMALLINT,
  content TEXT,
  created_at DATETIME NOT NULL,
  INDEX idx_channel_id_id (`channel_id`, `id`)
) Engine=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE haveread (
  user_id SMALLINT NOT NULL,
  channel_id SMALLINT NOT NULL,
  message_id SMALLINT,
  updated_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY(user_id, channel_id)
) Engine=InnoDB DEFAULT CHARSET=utf8mb4;
