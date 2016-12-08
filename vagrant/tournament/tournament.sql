-- Table definitions for the tournament project.
--
-- Put your SQL 'create table' statements in this file; also 'create view'
-- statements if you choose to use it.
--
-- You can write comments in this file by starting them with two dashes, like
-- these lines here.

DROP DATABASE IF EXISTS tournament;
CREATE DATABASE tournament;
\c tournament;
CREATE TABLE players (
  id  SERIAL PRIMARY KEY,
  name  varchar(50)
);
CREATE TABLE matches (
  id SERIAL PRIMARY KEY,
  winner integer REFERENCES players ON DELETE CASCADE ON UPDATE CASCADE,
  loser integer REFERENCES players ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE VIEW wins AS
  SELECT players.id, COUNT(matches.winner)
  FROM players
  JOIN matches ON players.id = matches.winner
  GROUP BY players.id;

CREATE VIEW games AS
  SELECT players.id, COUNT(matches.id)
  FROM players
  JOIN matches ON players.id = matches.winner OR players.id = matches.loser
  GROUP BY players.id;

CREATE VIEW standings AS
  SELECT p.id, p.name, COALESCE(w.count,0) AS wins,
    COALESCE(g.count,0) AS matches
  FROM players p
  LEFT OUTER JOIN wins w ON p.id = w.id
  LEFT OUTER JOIN games g ON p.id = g.id
  ORDER BY wins DESC;
